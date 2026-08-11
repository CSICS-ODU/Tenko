#!/usr/bin/env python3
"""AUC-PR (average precision) for the combined mixed CICIoT2023 stream, to enable
apples-to-apples comparison with Ramkumar et al. 2025 (which reports AUC-PR).

Test arrays (len 360000): benign [0:60000] then 6x50000 attack blocks.
"""
import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve, auc

M = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023/mixed"
gold = np.load(f"{M}/arr_gold_mixed.npy")
cont = np.load(f"{M}/arr_cont_mixed.npy")
kit = np.load(f"{M}/kitsune_testscores_mixed.npy")
assert len(gold) == len(cont) == 360000, (len(gold), len(cont))
assert len(kit) == 360000, len(kit)

ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
BEN = slice(0, 60000)


def aucpr(neg, pos):
    y = np.concatenate([np.zeros(len(neg), int), np.ones(len(pos), int)])
    s = np.concatenate([neg, pos])
    ap = average_precision_score(y, s)          # average precision (AUC-PR)
    p, r, _ = precision_recall_curve(y, s)
    ap_trap = auc(r, p)                          # trapezoidal AUC-PR
    return ap, ap_trap


print("=== Combined stream AUC-PR (benign 60k negatives) ===")
ap_t, apt_t = aucpr(cont[BEN], cont[60000:])
ap_k, apt_k = aucpr(kit[BEN], kit[60000:])
print(f"Tenko   overall  AP={ap_t:.4f}  (trap AUC-PR={apt_t:.4f})")
print(f"Kitsune overall  AP={ap_k:.4f}  (trap AUC-PR={apt_k:.4f})")

print("\n=== Per-attack AUC-PR (each attack block vs shared 60k benign) ===")
print(f"{'attack':24s} {'Tenko_AP':>9s} {'Kit_AP':>9s}")
tsum = ksum = 0.0
for i, a in enumerate(ATTACKS):
    lo = 60000 + i * 50000
    hi = lo + 50000
    at, _ = aucpr(cont[BEN], cont[lo:hi])
    ak, _ = aucpr(kit[BEN], kit[lo:hi])
    tsum += at; ksum += ak
    print(f"{a:24s} {at:9.4f} {ak:9.4f}")
print(f"{'MEAN':24s} {tsum/6:9.4f} {ksum/6:9.4f}")

# Prevalence-matched AUC-PR to Ramkumar's 95% benign / 5% attack split.
# Keep all 60000 benign; sample attack positives so positives = 5% of total.
print("\n=== Prevalence-matched AUC-PR (95% benign / 5% attack, as in Ramkumar) ===")
n_ben = 60000
n_pos = round(n_ben * 5 / 95)   # ~3158
atk_cont = cont[60000:]
atk_kit = kit[60000:]
ts, ks = [], []
for seed in range(20):
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(atk_cont), size=n_pos, replace=False)
    ts.append(aucpr(cont[BEN], atk_cont[idx])[0])
    ks.append(aucpr(kit[BEN], atk_kit[idx])[0])
print(f"positives={n_pos} (5.0% prevalence); mean over 20 seeds")
print(f"Tenko   AUC-PR@5% = {np.mean(ts):.4f} +/- {np.std(ts):.4f}")
print(f"Kitsune AUC-PR@5% = {np.mean(ks):.4f} +/- {np.std(ks):.4f}")
print(f"(random-baseline AUC-PR at 5% prevalence ~ 0.05)")
