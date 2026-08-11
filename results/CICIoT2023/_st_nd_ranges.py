#!/usr/bin/env python3
"""TASK 1: single vs double tanh normalized-distance (nd) ranges + committed-eta firing.

Uses the EXISTING cached per-test-packet arrays from run_ciciot2023.py at the
original split (benignLimit=150000, test region = 30k benign_test + 50k attack):
  arr_gold_<attack>.npy         test labels (0=benign_test, 1=attack)
  arr_ndg_<attack>_<tag>.npy    global normalized pattern distance
  arr_nds_<attack>_<tag>.npy    single-aggregate normalized pattern distance
tag in {single, double}. nd is eta-independent (base = tol/tol_factor = mean benign
spread); the committed binary rule fires iff (nd_g>eta_g) OR (nd_s>eta_s).
"""
from __future__ import annotations
import numpy as np

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
ETA_G, ETA_S = 50.0, 20.0  # committed


def pct(a):
    return np.percentile(a, [50, 90, 99, 100])


print(f"{'attack':<22}{'tag':<7}"
      f"{'benign nd_g[p50/p99/max]':<30}{'attack nd_g[p50/p99/max]':<30}"
      f"{'benign nd_s max':<16}{'attack nd_s max':<16}")
rows = []
for a in ATTACKS:
    g = np.load(f"{OUT}/arr_gold_{a}.npy")
    for tag in ("double", "single"):
        ndg = np.load(f"{OUT}/arr_ndg_{a}_{tag}.npy")
        nds = np.load(f"{OUT}/arr_nds_{a}_{tag}.npy")
        bmask = g == 0
        amask = g == 1
        bg, ag = ndg[bmask], ndg[amask]
        bs, as_ = nds[bmask], nds[amask]
        # committed-eta fused OR firing on full test region
        pred = ((ndg > ETA_G) | (nds > ETA_S)).astype(int)
        tp = int(((pred == 1) & (g == 1)).sum()); fp = int(((pred == 1) & (g == 0)).sum())
        fn = int(((pred == 0) & (g == 1)).sum()); tn = int(((pred == 0) & (g == 0)).sum())
        tpr = tp / (tp + fn) if (tp + fn) else float('nan')
        fpr = fp / (fp + tn) if (fp + tn) else float('nan')
        fired = (tp + fp) > 0
        print(f"{a:<22}{tag:<7}"
              f"{np.median(bg):>6.3f}/{np.percentile(bg,99):>6.3f}/{bg.max():>6.3f}        "
              f"{np.median(ag):>6.3f}/{np.percentile(ag,99):>6.3f}/{ag.max():>6.3f}        "
              f"{bs.max():>8.3f}      {as_.max():>8.3f}")
        rows.append(dict(attack=a, tag=tag,
                         b_ndg_max=bg.max(), a_ndg_max=ag.max(),
                         b_ndg_p99=np.percentile(bg,99), a_ndg_p99=np.percentile(ag,99),
                         b_nds_max=bs.max(), a_nds_max=as_.max(),
                         a_ndg_med=np.median(ag), a_nds_med=np.median(as_),
                         committed_TPR=tpr, committed_FPR=fpr, committed_fired=int(fired),
                         tp=tp, fp=fp))

print("\n=== Committed eta=50/20 firing (fused OR) at original split ===")
print(f"{'attack':<22}{'tag':<7}{'TPR':>9}{'FPR':>9}{'fired':>7}")
for r in rows:
    print(f"{r['attack']:<22}{r['tag']:<7}{r['committed_TPR']:>9.4f}{r['committed_FPR']:>9.4f}{r['committed_fired']:>7d}")

print("\n=== attack nd max summary (does single raise nd?) ===")
for a in ATTACKS:
    d = [r for r in rows if r['attack'] == a]
    dd = [r for r in d if r['tag'] == 'double'][0]
    ss = [r for r in d if r['tag'] == 'single'][0]
    print(f"{a:<22} attack nd_g max: double={dd['a_ndg_max']:.3f} single={ss['a_ndg_max']:.3f} "
          f"(x{ss['a_ndg_max']/max(dd['a_ndg_max'],1e-9):.2f})   "
          f"nd_s max: double={dd['a_nds_max']:.3f} single={ss['a_nds_max']:.3f} "
          f"(x{ss['a_nds_max']/max(dd['a_nds_max'],1e-9):.2f})")
