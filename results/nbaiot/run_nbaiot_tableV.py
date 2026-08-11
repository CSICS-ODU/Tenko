#!/usr/bin/env python3
"""Regenerate the N-BaIoT per-device / per-attack table (paper Table V).

This is the committed, self-contained driver for reviewer blocker B3. It rebuilds
the N-BaIoT detection metrics directly from the raw UCI "detection_of_IoT_botnet
_attacks_N_BaIoT" CSVs, using the repository's own KitNET (paper-style numpy dA
backend, KitNET/KitNET.py) so the numbers are reproducible from this repo alone.

Protocol (matches the original external driver `nbaio_tenko_eval.py` that produced
the manuscript numbers):
  * Per device d (1..9):
      - benign file            : ``<d>.benign.csv`` (115 AfterImage features, header row).
      - train / test split     : first ``train_ratio`` (0.9) of benign rows train KitNET;
                                  the remaining benign rows are the benign test set.
      - feature map            : fixed contiguous blocks of ``max_ae_size`` (=10)
                                  features -> 12 autoencoders (no FM grace / no
                                  correlation clustering), identical to the original.
      - threshold              : ``mean + 3*std`` of the KitNET RMSE over the TRAIN
                                  rows (attack-free calibration, no test labels used).
      - per attack             : every ``<d>.<family>.<attack>.csv`` present is scored;
                                  a packet is flagged malicious iff RMSE > threshold.
  * Metrics per (device, attack): tn, fp, fn, tp, TPR, FPR, precision, F1, accuracy,
    AUC (Mann-Whitney rank statistic) and EER, benign scores vs attack scores.

Usage examples:
  python results/nbaiot/run_nbaiot_tableV.py \
      --dataset "~/dataset/N-BaIoT" \
      --output results/nbaiot/nbaiot_tableV_metrics.csv

  # Quick reproducibility check on a single device:
  python results/nbaiot/run_nbaiot_tableV.py --dataset <dir> --devices 1 \
      --output results/nbaiot/nbaiot_device1_check.csv
"""

import argparse
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd

# Make the repository root importable so ``KitNET`` resolves regardless of CWD.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from KitNET.KitNET import KitNET  # noqa: E402  (paper-style numpy dA backend)


ATTACKS: List[Tuple[str, str]] = [
    ("mirai", "scan"),
    ("mirai", "ack"),
    ("mirai", "syn"),
    ("mirai", "udp"),
    ("mirai", "udpplain"),
    ("gafgyt", "combo"),
    ("gafgyt", "junk"),
    ("gafgyt", "scan"),
    ("gafgyt", "tcp"),
    ("gafgyt", "udp"),
]


@dataclass
class Metrics:
    tn: int
    fp: int
    fn: int
    tp: int
    tpr: float
    fpr: float
    precision: float
    f1: float
    accuracy: float
    auc: float
    eer: float


def count_rows(csv_path: Path) -> int:
    with csv_path.open("r", encoding="utf-8", errors="ignore") as f:
        return max(0, sum(1 for _ in f) - 1)


def iter_rows(csv_path: Path, chunksize: int, max_rows: int = 0) -> Iterable[np.ndarray]:
    seen = 0
    for chunk in pd.read_csv(csv_path, chunksize=chunksize):
        data = chunk.to_numpy(dtype=np.float32, copy=True)
        for row in data:
            yield row
            seen += 1
            if max_rows and seen >= max_rows:
                return


def compute_mean_std(scores: Iterable[float]) -> Tuple[float, float]:
    n = 0
    mean = 0.0
    m2 = 0.0
    for value in scores:
        n += 1
        delta = value - mean
        mean += delta / n
        m2 += delta * (value - mean)
    if n < 2:
        return mean, 0.0
    variance = m2 / (n - 1)
    return mean, float(np.sqrt(variance))


def rankdata(values: np.ndarray) -> np.ndarray:
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty_like(order, dtype=np.float64)
    ranks[order] = np.arange(1, len(values) + 1, dtype=np.float64)
    _, inv, counts = np.unique(values, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=ranks)
    avg_ranks = sums / counts
    return avg_ranks[inv]


def compute_auc_eer(benign_scores: np.ndarray, attack_scores: np.ndarray) -> Tuple[float, float]:
    scores = np.concatenate([benign_scores, attack_scores])
    labels = np.concatenate([
        np.zeros(len(benign_scores), dtype=np.int32),
        np.ones(len(attack_scores), dtype=np.int32),
    ])
    n_pos = int(np.sum(labels))
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.0, 0.0
    ranks = rankdata(scores)
    sum_pos = float(np.sum(ranks[labels == 1]))
    roc_auc = (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)

    order = np.argsort(scores)[::-1]
    labels_sorted = labels[order]
    tp = 0
    fp = 0
    fn = n_pos
    tn = n_neg
    best_eer = 1.0
    eer = 0.0
    for label in labels_sorted:
        if label == 1:
            tp += 1
            fn -= 1
        else:
            fp += 1
            tn -= 1
        fpr = fp / n_neg if n_neg else 0.0
        fnr = fn / n_pos if n_pos else 0.0
        diff = abs(fpr - fnr)
        if diff < best_eer:
            best_eer = diff
            eer = (fpr + fnr) / 2.0
    return float(roc_auc), float(eer)


def compute_metrics(tn, fp, fn, tp, benign_scores, attack_scores) -> Metrics:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    f1 = 2 * (precision * tpr) / (precision + tpr) if (precision + tpr) else 0.0
    roc_auc, eer = compute_auc_eer(benign_scores, attack_scores)
    return Metrics(tn, fp, fn, tp, tpr, fpr, precision, f1, accuracy, roc_auc, eer)


def build_feature_map(n_features: int, max_ae_size: int) -> List[List[int]]:
    max_ae_size = max(1, max_ae_size)
    return [list(range(i, min(i + max_ae_size, n_features)))
            for i in range(0, n_features, max_ae_size)]


def build_kitnet(n_features: int, max_ae_size: int, train_count: int,
                 feature_map: List[List[int]]) -> KitNET:
    """Instantiate the repo KitNET with a *fixed* contiguous feature map.

    The repo's ``KitNET.__init__`` calls ``__createAD__`` before ``ensembleLayer``
    is initialised when a feature_map is passed positionally (latent bug that the
    original external ``KitNET_improved`` avoided). We therefore construct with
    ``feature_map=None`` (skips that path, sets ``ensembleLayer=[]``) and then
    install the fixed map and build the anomaly detector ourselves. This yields
    the same fixed 12-autoencoder ensemble with no FM-grace clustering, exactly
    matching the original N-BaIoT protocol.
    """
    kitnet = KitNET(n_features, max_ae_size, 0, train_count, 0.1, 0.75, None)
    kitnet.v = feature_map
    kitnet.__createAD__()
    return kitnet


def evaluate_device(dataset_dir, device_id, device_name, train_ratio, chunksize,
                    max_ae_size, max_rows, print_results) -> Dict[str, Metrics]:
    benign_path = dataset_dir / f"{device_id}.benign.csv"
    if not benign_path.exists():
        raise FileNotFoundError(f"Missing benign file: {benign_path}")

    total_benign = count_rows(benign_path)
    train_count = int(total_benign * train_ratio)

    train_rows: List[np.ndarray] = []
    test_rows: List[np.ndarray] = []
    for row in iter_rows(benign_path, chunksize=chunksize):
        (train_rows if len(train_rows) < train_count else test_rows).append(row)
    if not train_rows:
        raise RuntimeError(f"No training data for device {device_id}")

    n_features = len(train_rows[0])
    feature_map = build_feature_map(n_features, max_ae_size)
    kitnet = build_kitnet(n_features, max_ae_size, len(train_rows), feature_map)

    for row in train_rows:
        kitnet.train(row)

    train_scores = [kitnet.execute(row) for row in train_rows]
    mean_score, std_score = compute_mean_std(train_scores)
    threshold = mean_score + 3.0 * std_score

    benign_scores = np.array([kitnet.execute(row) for row in test_rows], dtype=np.float32)
    benign_preds = benign_scores > threshold
    tn = int(np.sum(~benign_preds))
    fp = int(np.sum(benign_preds))

    results: Dict[str, Metrics] = {}
    for family, attack in ATTACKS:
        attack_path = dataset_dir / f"{device_id}.{family}.{attack}.csv"
        if not attack_path.exists():
            continue
        attack_scores_list = []
        tp = 0
        fn = 0
        for row in iter_rows(attack_path, chunksize=chunksize, max_rows=max_rows):
            score = kitnet.execute(row)
            attack_scores_list.append(score)
            if score > threshold:
                tp += 1
            else:
                fn += 1
        attack_scores = np.array(attack_scores_list, dtype=np.float32)
        metrics = compute_metrics(tn, fp, fn, tp, benign_scores, attack_scores)
        results[f"{family}.{attack}"] = metrics
        if print_results:
            print(f"METRIC,{device_id},{device_name},{family}.{attack},"
                  f"{metrics.tpr:.6f},{metrics.fpr:.6f},{metrics.f1:.6f},"
                  f"{metrics.auc:.6f},{metrics.eer:.6f}", flush=True)

    print(f"Device {device_id} ({device_name}) benign total={total_benign}, "
          f"train={len(train_rows)}, test={len(test_rows)}, threshold={threshold:.6f}",
          flush=True)
    return results


def load_device_names(device_info_path: Path) -> Dict[int, str]:
    if not device_info_path.exists():
        return {}
    df = pd.read_csv(device_info_path)
    return {int(r["DeviceID"]): str(r["DeviceName"]) for _, r in df.iterrows()}


def save_results_csv(output_path: Path, names: Dict[int, str],
                     all_results: Dict[int, Dict[str, Metrics]]) -> None:
    rows = []
    for device_id, metrics_map in all_results.items():
        for attack_name, metrics in metrics_map.items():
            rows.append({
                "device_id": device_id,
                "device_name": names.get(device_id, f"device_{device_id}"),
                "attack": attack_name,
                **asdict(metrics),
            })
    pd.DataFrame(rows).to_csv(output_path, index=False)


def main() -> None:
    ap = argparse.ArgumentParser(description="Rebuild N-BaIoT Table V from raw CSVs")
    ap.add_argument("--dataset", required=True, help="Directory with <d>.benign.csv etc.")
    ap.add_argument("--train-ratio", type=float, default=0.9)
    ap.add_argument("--chunksize", type=int, default=50000)
    ap.add_argument("--max-ae-size", type=int, default=10)
    ap.add_argument("--devices", type=int, nargs="*", default=list(range(1, 10)))
    ap.add_argument("--max-rows", type=int, default=0,
                    help="Cap attack rows per file (0 = all); for quick benchmarks only.")
    ap.add_argument("--output", default="results/nbaiot/nbaiot_tableV_metrics.csv")
    ap.add_argument("--print-results", action="store_true")
    args = ap.parse_args()

    dataset_dir = Path(args.dataset).expanduser().resolve()
    names = load_device_names(dataset_dir / "device_info.csv")

    all_results: Dict[int, Dict[str, Metrics]] = {}
    t0 = time.time()
    for device_id in args.devices:
        all_results[device_id] = evaluate_device(
            dataset_dir, device_id, names.get(device_id, f"device_{device_id}"),
            args.train_ratio, args.chunksize, args.max_ae_size, args.max_rows,
            args.print_results,
        )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_results_csv(out_path, names, all_results)
    print(f"\nSaved {sum(len(v) for v in all_results.values())} rows to {out_path} "
          f"in {time.time() - t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()
