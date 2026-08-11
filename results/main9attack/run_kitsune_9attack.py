#!/usr/bin/env python3
"""Regenerate the main-paper per-attack (nine-attack) Kitsune/Tenko table.

Reviewer blocker B2. The manuscript's nine-attack table (Active Wiretap, ARP MitM,
Fuzzing, Mirai, OS Scan, SSDP Flood, SSL Renegotiation, SYN DoS, Video Injection)
previously survived only as hard-coded literals in ``resultsNew.py`` on branch
``Daksh-Mateen`` (no driver, no CSV, no AUC/EER). This script rebuilds the per-attack
row **from anomaly scores + ground-truth labels**, under the same benign-only
thresholding strategies used in the paper, and additionally emits the
threshold-independent AUC and EER that the literals never preserved.

Two input modes (per attack):

  (A) --scores-npz <file>   Load a precomputed score stream produced by the Kitsune
                            pipeline (e.g. tenko_eval/run_kitsune_mirai.py). Expected
                            keys: ``scores`` (per-packet RMSE), ``labels`` (0=benign,
                            1=attack) and optionally ``benign_cal`` (attack-free
                            calibration scores). If ``benign_cal`` is absent the
                            benign calibration set is taken as ``scores[labels==0]``.

  (B) --dataset-csv <file> --labels-csv <file>
                            Run the repository KitNET (KitNET/KitNET.py, paper-style
                            numpy dA) over a 115-feature AfterImage matrix and derive
                            the score stream, then evaluate as in (A). ``--benign-count``
                            (or the labels) delimits the attack-free calibration rows.

Thresholding strategies (all derived from benign scores only, no test labels):
  mean, min, max, max+std, mean+3sigma, median+1.5*MAD, p95, p99.
The names map onto the resultsNew.py columns as:
  Medium(mean)->mean, Lowest(min)->min, Max->max, Highest(max+std)->max+std,
  3sigma->mean+3sigma, Med+1.5xMAD->median+1.5*MAD.  ('Logarithmic' from
  resultsNew.py is intentionally omitted: its exact definition is not recorded in
  the committed code, so reproducing it would require guessing.)

Usage:
  python results/main9attack/run_kitsune_9attack.py \
      --attack Mirai \
      --scores-npz /path/to/kitsune_mirai_scores.npz \
      --output results/main9attack/kitsune_9attack_metrics.csv
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


THRESHOLD_METHODS = ["mean", "min", "max", "max+std", "mean+3sigma",
                     "median+1.5MAD", "p95", "p99"]


def benign_thresholds(benign: np.ndarray) -> Dict[str, float]:
    benign = benign[np.isfinite(benign)]
    mu, sd = float(benign.mean()), float(benign.std())
    med = float(np.median(benign))
    mad = float(np.median(np.abs(benign - med)))
    return {
        "mean": mu,
        "min": float(benign.min()),
        "max": float(benign.max()),
        "max+std": float(benign.max()) + sd,
        "mean+3sigma": mu + 3.0 * sd,
        "median+1.5MAD": med + 1.5 * mad,
        "p95": float(np.percentile(benign, 95)),
        "p99": float(np.percentile(benign, 99)),
    }


def confusion_at(scores: np.ndarray, labels: np.ndarray, thr: float):
    pred = scores > thr
    tp = int(np.sum(pred & (labels == 1)))
    fp = int(np.sum(pred & (labels == 0)))
    fn = int(np.sum(~pred & (labels == 1)))
    tn = int(np.sum(~pred & (labels == 0)))
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = 1.0 - tpr
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0.0
    return dict(tn=tn, fp=fp, fn=fn, tp=tp, tpr=tpr, fpr=fpr, fnr=fnr,
                precision=precision, f1=f1)


def auc_eer(scores: np.ndarray, labels: np.ndarray) -> Tuple[float, float]:
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    # average ranks for ties
    vals, inv, counts = np.unique(scores, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=ranks)
    ranks = (sums / counts)[inv]
    n_pos = int(np.sum(labels == 1))
    n_neg = int(np.sum(labels == 0))
    if n_pos == 0 or n_neg == 0:
        return 0.0, 0.0
    sum_pos = float(np.sum(ranks[labels == 1]))
    auc = (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    order2 = np.argsort(scores)[::-1]
    ls = labels[order2]
    tp = fp = 0
    fn, tn = n_pos, n_neg
    best, eer = 1.0, 0.0
    for lab in ls:
        if lab == 1:
            tp += 1; fn -= 1
        else:
            fp += 1; tn -= 1
        fpr = fp / n_neg
        fnr = fn / n_pos
        d = abs(fpr - fnr)
        if d < best:
            best, eer = d, (fpr + fnr) / 2.0
    return float(auc), float(eer)


def load_from_npz(path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    d = np.load(path)
    scores = np.asarray(d["scores"], dtype=np.float64)
    labels = np.asarray(d["labels"], dtype=np.int8)
    finite = np.isfinite(scores)
    if not finite.all():
        scores = scores.copy()
        scores[~finite] = np.nanmax(scores[finite])
    benign_cal = (np.asarray(d["benign_cal"], dtype=np.float64)
                  if "benign_cal" in d.files else scores[labels == 0])
    return scores, labels, benign_cal


def load_from_csv(dataset_csv: Path, labels_csv: Path, benign_count: int,
                  max_ae_size: int, chunksize: int, has_index_col: bool,
                  drop_last_col: bool) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    from KitNET.KitNET import KitNET

    labels = pd.read_csv(labels_csv, header=None).to_numpy().ravel().astype(np.int8)

    def rows():
        for chunk in pd.read_csv(dataset_csv, header=None, chunksize=chunksize):
            arr = chunk.to_numpy(dtype=np.float64, copy=True)
            if has_index_col:
                arr = arr[:, 1:]
            if drop_last_col:
                arr = arr[:, :-1]
            for r in arr:
                yield r

    it = rows()
    first = next(it)
    n_features = len(first)
    fmap = [list(range(i, min(i + max_ae_size, n_features)))
            for i in range(0, n_features, max_ae_size)]
    if benign_count <= 0:
        benign_count = int(np.sum(labels == 0))
    kit = KitNET(n_features, max_ae_size, 0, benign_count, 0.1, 0.75, None)
    kit.v = fmap
    kit.__createAD__()

    scores = np.empty(len(labels), dtype=np.float64)
    # first row already pulled
    def all_rows():
        yield first
        yield from it
    for i, r in enumerate(all_rows()):
        if i < benign_count:
            kit.train(r)
            scores[i] = kit.execute(r)
        else:
            scores[i] = kit.execute(r)
    benign_cal = scores[:benign_count]
    return scores, labels, benign_cal


def build_row(attack: str, scores, labels, benign_cal) -> List[dict]:
    thr = benign_thresholds(benign_cal)
    auc, eer = auc_eer(scores, labels)
    out = []
    for method in THRESHOLD_METHODS:
        c = confusion_at(scores, labels, thr[method])
        out.append({
            "attack": attack,
            "threshold_method": method,
            "threshold": thr[method],
            **{k: c[k] for k in ("tpr", "fpr", "fnr", "precision", "f1",
                                 "tn", "fp", "fn", "tp")},
            "auc": auc,
            "eer": eer,
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Rebuild nine-attack Kitsune/Tenko table")
    ap.add_argument("--attack", required=True, help="Attack name (e.g. Mirai)")
    ap.add_argument("--scores-npz")
    ap.add_argument("--dataset-csv")
    ap.add_argument("--labels-csv")
    ap.add_argument("--benign-count", type=int, default=0)
    ap.add_argument("--max-ae-size", type=int, default=10)
    ap.add_argument("--chunksize", type=int, default=50000)
    ap.add_argument("--has-index-col", action="store_true",
                    help="Dataset CSV has a leading integer index column to drop.")
    ap.add_argument("--drop-last-col", action="store_true",
                    help="Dataset CSV has a trailing (timestamp) column to drop.")
    ap.add_argument("--output", default="results/main9attack/kitsune_9attack_metrics.csv")
    ap.add_argument("--append", action="store_true",
                    help="Append to the output CSV instead of overwriting.")
    args = ap.parse_args()

    if args.scores_npz:
        scores, labels, benign_cal = load_from_npz(Path(args.scores_npz))
    elif args.dataset_csv and args.labels_csv:
        scores, labels, benign_cal = load_from_csv(
            Path(args.dataset_csv), Path(args.labels_csv), args.benign_count,
            args.max_ae_size, args.chunksize, args.has_index_col, args.drop_last_col)
    else:
        ap.error("Provide either --scores-npz OR (--dataset-csv and --labels-csv)")

    rows = build_row(args.attack, scores, labels, benign_cal)
    df = pd.DataFrame(rows)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if args.append and out_path.exists():
        df.to_csv(out_path, mode="a", header=False, index=False)
    else:
        df.to_csv(out_path, index=False)

    print(f"[{args.attack}] benign_cal n={len(benign_cal)} "
          f"(mu={benign_cal.mean():.6g}, sigma={benign_cal.std():.6g}); "
          f"test n={len(labels)} pos={int((labels==1).sum())} neg={int((labels==0).sum())}")
    print(f"AUC={rows[0]['auc']:.4f}  EER={rows[0]['eer']:.4f}")
    for r in rows:
        print(f"  {r['threshold_method']:<14} thr={r['threshold']:.6g}  "
              f"TPR={r['tpr']:.3f} FPR={r['fpr']:.3f} FNR={r['fnr']:.3f} "
              f"Prec={r['precision']:.3f} F1={r['f1']:.3f}")
    print(f"Wrote {len(rows)} rows -> {out_path}")


if __name__ == "__main__":
    main()
