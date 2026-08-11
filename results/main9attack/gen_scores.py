#!/usr/bin/env python3
"""Generate a Kitsune anomaly-score stream (npz) for one attack, mirroring how the
committed Mirai row was produced (``tenko_eval/run_kitsune_mirai.py``) and the
authentic Kitsune pipeline in ``ymirsky/Kitsune-py`` (``example.py``).

This uses the *authentic* KitNET: the feature map is LEARNED online via correlation
clustering (corClust) over an FM-grace of 5,000 packets, and the ensemble's anomaly
detector is then trained over an AD-grace of 50,000 packets (``feature_map=None``,
``kit.process`` during grace). This is what produced the committed Mirai row
(benign_cal ~44,999 = post-grace benign). It differs from the driver's
``--dataset-csv`` mode, which uses a *fixed* contiguous 10-feature grouping and
therefore cannot separate the subtler attacks; feeding this authentic score stream
to the driver via ``--scores-npz`` keeps the committed driver as the sole evaluator
while matching the paper/Mirai methodology.

Also fixes a calibration pitfall: benign thresholds are computed from *post-grace,
execute-mode* benign scores (KitNET is stable), never from the training-warmup
scores (which are astronomically large for untrained autoencoders).

Steps:
  1. Learn FM + train AD on the first G = FM_grace + AD_grace benign packets [0, G)
     (these are excluded from evaluation).
  2. Execute KitNET on packets [G, N) to obtain stable RMSE scores.
  3. Emit an npz whose ``scores``/``labels`` cover only [G, N), and whose
     ``benign_cal`` = execute-mode scores of post-grace, PRE-ATTACK benign packets
     [G, A) where A = index of the first attack packet.

Feed the npz to ``run_kitsune_9attack.py --scores-npz`` for evaluation.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", required=True)
    ap.add_argument("--dataset-csv", required=True, help="115-feature CSV (.gz ok), no header/index")
    ap.add_argument("--labels-csv", required=True, help="plain single-column 0/1 labels")
    ap.add_argument("--fm-grace", type=int, default=5000, help="packets to learn the corClust feature map")
    ap.add_argument("--ad-grace", type=int, default=50000, help="packets to train the anomaly detector")
    ap.add_argument("--max-ae-size", type=int, default=10)
    ap.add_argument("--chunksize", type=int, default=100000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    from KitNET.KitNET import KitNET

    labels = pd.read_csv(args.labels_csv, header=None).to_numpy().ravel().astype(np.int8)
    N = len(labels)
    ones = np.where(labels == 1)[0]
    A = int(ones[0]) if len(ones) else N  # first attack packet index
    G = args.fm_grace + args.ad_grace     # total grace (excluded from eval)
    if G >= A:
        raise SystemExit(f"grace {G} >= attack-start {A}: no pure-benign calibration room")

    def rows():
        for chunk in pd.read_csv(args.dataset_csv, header=None, chunksize=args.chunksize):
            arr = chunk.to_numpy(dtype=np.float64, copy=True)
            for r in arr:
                yield r

    it = rows()
    first = next(it)
    n_features = len(first)
    # Authentic Kitsune: feature_map=None -> learn corClust map over FM grace,
    # then train the ensemble AD over AD grace.
    kit = KitNET(n_features, args.max_ae_size, args.fm_grace, args.ad_grace,
                 0.1, 0.75, None)

    scores = np.empty(N, dtype=np.float64)

    def all_rows():
        yield first
        yield from it

    for i, r in enumerate(all_rows()):
        if i < G:
            kit.process(r)            # learns FM (at fm_grace) then trains AD
        else:
            scores[i] = kit.execute(r)
        if i % 500000 == 0:
            print(f"  {args.attack}: {i}/{N}", flush=True)

    eval_scores = scores[G:]
    eval_labels = labels[G:]
    benign_cal = scores[G:A]  # post-grace, pre-attack benign (attack-free calibration)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out, scores=eval_scores, labels=eval_labels, benign_cal=benign_cal)
    print(f"[{args.attack}] N={N} attack_start={A} grace={G} "
          f"eval_n={len(eval_scores)} benign_cal_n={len(benign_cal)} "
          f"pos={int((eval_labels==1).sum())} neg={int((eval_labels==0).sum())} "
          f"(benign_cal mu={benign_cal.mean():.4g} max={benign_cal.max():.4g}) -> {out}")


if __name__ == "__main__":
    main()
