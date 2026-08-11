#!/usr/bin/env python3
"""Re-run Tenko X2-X4 (single-tanh) at a REDUCED benign split on cached RMSEs.

Why this is equivalent to rebuilding shorter PCAP streams:
  KitNET freezes after grace (n_trained > FMgrace+ADgrace => execute-only,
  KitNET/KitNET.py:61), so a benign packet's raw RMSE depends only on the frozen
  model (trained on the SAME first 55k benign packets) and that packet's features
  -- it is order-independent post-grace. The Tenko node/pattern models are frozen
  at benignLimit. Hence re-running X2 with a smaller benignLimit on the cached
  rmse_raw arrays produces byte-identical scores to physically rebuilding a shorter
  stream, for every corresponding packet; a shorter rebuild is just a truncation.
  We therefore feed cached rmse_raw (single-tanh => results.py applies tanh once)
  and only change benignLimit. This avoids re-running the slow X1 (KitNET).

Reduced split (documented in the memo), stream indices (0-based):
  [0      : 55000 ] KitNET training (FM grace 5000 + AD grace 50000); frozen @55001
  [55001  : 60000 ] Tenko pattern-model training (benignLimit = 60000)
  [60000  : 65000 ] eta calibration slice (5000 benign) -- test-array idx [0:5000]
  [65000  : 124000] benign eval / FPR negatives (59000)  -- test-array idx [5000:64000]
  [124000 : 180000] extra benign (excluded from headline; robustness) idx [64000:120000]
  [180000 : 230000] attack (50000)                        -- test-array idx [120000:170000]
The returned nd arrays cover test region [benignLimit:230000] = 170000 entries.
"""
from __future__ import annotations
import os, sys, time
os.environ.setdefault("MPLBACKEND", "Agg")
import numpy as np
import results as R

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
BIG = "/Users/sbhola/Desktop/cic/pilot"
BENIGN_LIMIT = 60000
TAG = "s60k"


def run_one(attack: str):
    tsv = f"{BIG}/stream_{attack}.pcap.tsv"
    lab = f"{OUT}/labels_{attack}.csv"
    rmse_raw = np.load(f"{OUT}/rmse_raw_{attack}.npy")  # cached raw KitNET RMSE
    labels = R.build_label_list(lab, label_col="x")
    IPs, IPd = R.build_IP_list(tsv)
    assert len(rmse_raw) == len(IPs) == len(labels), (
        f"len mismatch {len(rmse_raw)} {len(IPs)} {len(labels)}")
    t0 = time.time()
    out = R.get_adversarial_IPs_weighted_pattern(
        IPs=IPs, IPd=IPd, LABELS=labels, RMSEs=list(rmse_raw),  # single-tanh: feed RAW
        memorySize=60, blockchainMode="offline",
        pattern_window_size=100, pattern_segments=10,
        global_pool_tol_factor=50, single_agg_tol_factor=20,   # only used as norm base; nd is eta-free
        weight_global=0.5, weight_single=0.5, ensemble_threshold=0.5,
        benignLimit=BENIGN_LIMIT, return_scores=True,
    )
    tgold = np.asarray(out[0])
    cont = np.asarray(out[9]); node = np.asarray(out[10])
    nd_g = np.asarray(out[11]); nd_s = np.asarray(out[12])
    np.save(f"{OUT}/arr_gold_{attack}_{TAG}.npy", tgold)
    np.save(f"{OUT}/arr_ndg_{attack}_{TAG}.npy", nd_g)
    np.save(f"{OUT}/arr_nds_{attack}_{TAG}.npy", nd_s)
    np.save(f"{OUT}/arr_node_{attack}_{TAG}.npy", node)
    np.save(f"{OUT}/arr_cont_{attack}_{TAG}.npy", cont)
    dt = time.time() - t0
    n_benign = int((tgold == 0).sum()); n_atk = int((tgold == 1).sum())
    print(f"[DONE] {attack}: test={len(tgold)} (benign={n_benign} attack={n_atk}) "
          f"nd_g[b_max={nd_g[tgold==0].max():.3f} a_max={nd_g[tgold==1].max():.3f}] "
          f"nd_s[b_max={nd_s[tgold==0].max():.3f} a_max={nd_s[tgold==1].max():.3f}] {dt:.1f}s",
          flush=True)


if __name__ == "__main__":
    run_one(sys.argv[1])
