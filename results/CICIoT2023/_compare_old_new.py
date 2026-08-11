#!/usr/bin/env python3
"""Compare reduced split (s60k) vs OLD 150k-lead (single), + AUC + benign non-stationarity.

OLD single arrays (benignLimit=150000): arr_{gold,ndg,nds}_<attack>_single.npy
  test = [150000:230000] = 30000 benign_test [0:30000] + 50000 attack [30000:80000]
  honest calib = benign_test[0:5000]; eval = benign_test[5000:30000] (25000)
"""
from __future__ import annotations
import numpy as np
from sklearn.metrics import roc_auc_score

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]


def calibrate_shared_q(cndg, cnds, target):
    qs = np.concatenate([np.linspace(0.50, 0.90, 41), np.linspace(0.9001, 0.99999, 1200)])
    best = None
    for q in qs:
        eg = float(np.quantile(cndg, q)); es = float(np.quantile(cnds, q))
        fpr = float(np.mean((cndg > eg) | (cnds > es)))
        over = 0 if fpr <= target + 1e-9 else 1
        key = (over, abs(fpr - target))
        if best is None or key < best[0]:
            best = (key, eg, es, fpr)
    return best[1], best[2], best[3]


def fused_auc(ndg, nds, g):
    fused = 0.5 * ndg + 0.5 * nds
    return roc_auc_score(g, fused)


print("======== OLD 150k-lead (single-tanh) honest benign-calib transfer ========")
print(f"{'attack':<22}{'AUC':>7}{'eg@1':>8}{'es@1':>7}{'calibFPR':>9}{'evalFPR':>9}{'TPR@1':>8}")
old_rows = []
for a in ATTACKS:
    g = np.load(f"{OUT}/arr_gold_{a}.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{a}_single.npy")
    nds = np.load(f"{OUT}/arr_nds_{a}_single.npy")
    n_test = int((g == 0).sum())   # 30000
    ben = np.where(g == 0)[0]; atk = np.where(g == 1)[0]
    calib_idx = ben[:5000]; eval_idx = ben[5000:]
    auc = fused_auc(ndg, nds, g)
    for t in (0.01, 0.05):
        eg, es, cfpr = calibrate_shared_q(ndg[calib_idx], nds[calib_idx], t)
        efpr = float(np.mean((ndg[eval_idx] > eg) | (nds[eval_idx] > es)))
        tpr = float(np.mean((ndg[atk] > eg) | (nds[atk] > es)))
        old_rows.append((a, t, auc, eg, es, cfpr, efpr, tpr, len(eval_idx), len(atk)))
        if t == 0.01:
            print(f"{a:<22}{auc:>7.3f}{eg:>8.3f}{es:>7.3f}{cfpr:>9.4f}{efpr:>9.4f}{tpr:>8.4f}")

print("\n======== REDUCED s60k fused AUC (eta-independent separability) ========")
for a in ATTACKS:
    g = np.load(f"{OUT}/arr_gold_{a}_s60k.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{a}_s60k.npy")
    nds = np.load(f"{OUT}/arr_nds_{a}_s60k.npy")
    # use eval benign + attack for a comparable AUC (exclude extra)
    sel = np.r_[5000:64000, 120000:170000]
    auc = fused_auc(ndg[sel], nds[sel], g[sel])
    auc_full = fused_auc(ndg, nds, g)
    print(f"{a:<22} AUC(eval+atk)={auc:.4f}  AUC(all benign+atk)={auc_full:.4f}")

print("\n======== BENIGN NON-STATIONARITY: fused nd_g by benign window (s60k) ========")
# one attack's benign nd_g is representative (benign shared); use DoS-SYN
ndg = np.load(f"{OUT}/arr_ndg_DoS-SYN_Flood_s60k.npy")
g = np.load(f"{OUT}/arr_gold_DoS-SYN_Flood_s60k.npy")
ben = ndg[g == 0]  # 120000 benign, stream 60000..179999
print("benign stream-window nd_g p50/p90/p99/max (each 20k):")
for k in range(0, 120000, 20000):
    seg = ben[k:k+20000]
    s0 = 60000 + k
    print(f"  stream[{s0:>6}:{s0+20000:>6}] p50={np.median(seg):8.2f} p90={np.percentile(seg,90):8.2f} "
          f"p99={np.percentile(seg,99):8.2f} max={seg.max():8.2f} frac>6.457={np.mean(seg>6.457):.3f}")

print("\n======== OLD benign_test non-stationarity (single, stream 150000..179999) ========")
ndg_o = np.load(f"{OUT}/arr_ndg_DoS-SYN_Flood_single.npy")
g_o = np.load(f"{OUT}/arr_gold_DoS-SYN_Flood.npy")
ben_o = ndg_o[g_o == 0]  # 30000
for k in range(0, 30000, 5000):
    seg = ben_o[k:k+5000]; s0 = 150000 + k
    print(f"  stream[{s0:>6}:{s0+5000:>6}] p50={np.median(seg):7.3f} p90={np.percentile(seg,90):7.3f} "
          f"p99={np.percentile(seg,99):7.3f} max={seg.max():7.3f}")
