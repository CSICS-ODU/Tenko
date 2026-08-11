#!/usr/bin/env python3
"""Prevalence sweep for the combined mixed CICIoT2023 stream.

Everything is computed ANALYTICALLY from cached score arrays -- no pipeline re-run.

Key idea:
  TPR, FPR, and AUC-ROC are WITHIN-class rates -> INVARIANT to attack prevalence.
  Accuracy, Precision, micro-F1, AUC-PR depend on prevalence.

We fix each detector's within-class confusion (from its committed operating point),
then reweight the positive class to hit target attack fractions pi.
"""
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

M = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023/mixed"
gold = np.load(f"{M}/arr_gold_mixed.npy")
ndg = np.load(f"{M}/arr_ndg_mixed.npy")
nds = np.load(f"{M}/arr_nds_mixed.npy")
cont = np.load(f"{M}/arr_cont_mixed.npy")
kit = np.load(f"{M}/kitsune_testscores_mixed.npy")

N = len(gold)
assert N == 360000, N
for a in (ndg, nds, cont, kit):
    assert len(a) == N

ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
BEN = slice(0, 60000)

# --- verify stream layout against arr_gold_mixed ---
assert gold[BEN].sum() == 0, "benign region not all 0"
for i in range(6):
    lo, hi = 60000 + i * 50000, 60000 + (i + 1) * 50000
    assert gold[lo:hi].min() == 1 and gold[lo:hi].max() == 1, f"attack block {i} not all 1"
n_benign = 60000
n_pos_full = N - n_benign
assert n_pos_full == 300000

# ============================================================
# 1. FIXED within-class rates at each detector's operating point
# ============================================================
# Tenko committed eta: flag if (nd_g > 50) OR (nd_s > 20)
tenko_pred = (ndg > 50) | (nds > 20)
# Kitsune: benign-only Median+MAD on benign region [0:60000]
kb = kit[BEN]
med = np.median(kb)
mad = np.median(np.abs(kb - med))
kit_thr = med + 3 * 1.4826 * mad
kit_pred = kit > kit_thr


def within_class(pred):
    ben = pred[BEN]
    atk = pred[60000:]
    FP = int(ben.sum())
    TN = n_benign - FP
    fpr = FP / n_benign
    TP_all = int(atk.sum())
    tpr = TP_all / n_pos_full
    per_attack = {}
    for i, a in enumerate(ATTACKS):
        lo, hi = i * 50000, (i + 1) * 50000
        per_attack[a] = atk[lo:hi].mean()
    return dict(FP=FP, TN=TN, fpr=fpr, tpr=tpr, per_attack=per_attack)


t = within_class(tenko_pred)
k = within_class(kit_pred)

# AUC-ROC (benign vs all-attack pooled) -- also prevalence-invariant
y = np.concatenate([np.zeros(n_benign, int), np.ones(n_pos_full, int)])
auc_t = roc_auc_score(y, np.concatenate([cont[BEN], cont[60000:]]))
auc_k = roc_auc_score(y, np.concatenate([kit[BEN], kit[60000:]]))

print("=" * 64)
print("FIXED within-class rates (prevalence-INVARIANT)")
print("=" * 64)
print(f"Kitsune threshold: median={med:.6f} MAD={mad:.6e} thr={kit_thr:.6f}")
print(f"{'':10s} {'FPR':>10s} {'FP':>7s} {'TPR':>10s} {'AUC_ROC':>10s}")
print(f"{'Tenko':10s} {t['fpr']:10.6f} {t['FP']:7d} {t['tpr']:10.6f} {auc_t:10.6f}")
print(f"{'Kitsune':10s} {k['fpr']:10.6f} {k['FP']:7d} {k['tpr']:10.6f} {auc_k:10.6f}")
print("\nPer-attack TPR (prevalence-invariant):")
print(f"{'attack':24s} {'Tenko':>8s} {'Kitsune':>8s}")
for a in ATTACKS:
    print(f"{a:24s} {t['per_attack'][a]:8.4f} {k['per_attack'][a]:8.4f}")

# sanity check
print("\nSanity check (expected Tenko FPR~0.0069 [417/60000], TPR~0.879):")
print(f"  Tenko FP={t['FP']} (expected 417), FPR={t['fpr']:.4f}, TPR={t['tpr']:.4f}")


# ============================================================
# 2. Prevalence sweep -- analytic reweighting
# ============================================================
def prev_adjusted(tpr, fpr, pi, n_neg=60000):
    P = round(n_neg * pi / (1 - pi))
    TP = tpr * P
    FN = P - TP
    FP = fpr * n_neg
    TN = n_neg - FP
    acc = (TP + TN) / (TP + TN + FP + FN)
    prec = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    f1 = 2 * TP / (2 * TP + FP + FN) if (2 * TP + FP + FN) > 0 else 0.0
    return dict(P=P, acc=acc, prec=prec, f1=f1)


def aucpr_at_prevalence(neg_scores, pos_scores, pi):
    """Analytic AUC-PR (average-precision style) at target prevalence pi.

    Use roc_curve on the FULL pooled scores to get (fpr_t, tpr_t) at every
    threshold. recall = tpr_t; precision at target prevalence:
        prec(pi) = pi*tpr_t / (pi*tpr_t + (1-pi)*fpr_t)
    Then integrate precision over recall in average-precision fashion:
        AP = sum_k (R_k - R_{k-1}) * P_k
    """
    yy = np.concatenate([np.zeros(len(neg_scores), int), np.ones(len(pos_scores), int)])
    ss = np.concatenate([neg_scores, pos_scores])
    fpr, tpr, _ = roc_curve(yy, ss)  # sorted: fpr,tpr increasing from (0,0)
    denom = pi * tpr + (1 - pi) * fpr
    with np.errstate(divide="ignore", invalid="ignore"):
        prec = np.where(denom > 0, pi * tpr / denom, 1.0)
    # recall = tpr. AP = sum (R_k - R_{k-1}) * P_k
    ap = np.sum(np.diff(tpr) * prec[1:])
    return ap


PIS = [0.833, 0.50, 0.30, 0.10, 0.05]

tenko_neg, tenko_pos = cont[BEN], cont[60000:]
kit_neg, kit_pos = kit[BEN], kit[60000:]

rows = []  # detector, pi, TPR, FPR, Precision, microF1, Accuracy, AUC_ROC, AUC_PR
print("\n" + "=" * 64)
print("PREVALENCE SWEEP")
print("=" * 64)
hdr = f"{'det':8s} {'pi':>6s} {'TPR':>8s} {'FPR':>8s} {'Prec':>8s} {'microF1':>8s} {'Acc':>8s} {'AUC_ROC':>8s} {'AUC_PR':>8s}"
print(hdr)
for pi in PIS:
    for name, det, auc, neg, pos in (
        ("Tenko", t, auc_t, tenko_neg, tenko_pos),
        ("Kitsune", k, auc_k, kit_neg, kit_pos),
    ):
        pa = prev_adjusted(det["tpr"], det["fpr"], pi)
        aupr = aucpr_at_prevalence(neg, pos, pi)
        rows.append((name, pi, det["tpr"], det["fpr"], pa["prec"], pa["f1"], pa["acc"], auc, aupr))
        print(f"{name:8s} {pi:6.3f} {det['tpr']:8.4f} {det['fpr']:8.4f} {pa['prec']:8.4f} "
              f"{pa['f1']:8.4f} {pa['acc']:8.4f} {auc:8.4f} {aupr:8.4f}")

# ============================================================
# 3. Crossover: where does Tenko overtake Kitsune on Acc & microF1?
# ============================================================
print("\n" + "=" * 64)
print("CROSSOVER ANALYSIS (fine pi grid)")
print("=" * 64)
grid = np.linspace(0.005, 0.95, 9451)
# Tenko wins at LOW prevalence, Kitsune at HIGH prevalence. Find the largest pi
# at which Tenko is still >= Kitsune (the crossover boundary).
cross_acc = cross_f1 = None
for pi in grid:
    ta = prev_adjusted(t["tpr"], t["fpr"], pi)
    ka = prev_adjusted(k["tpr"], k["fpr"], pi)
    if ta["acc"] >= ka["acc"]:
        cross_acc = pi
    if ta["f1"] >= ka["f1"]:
        cross_f1 = pi
print(f"Tenko Accuracy >= Kitsune for attack prevalence <= {cross_acc:.4f}")
print(f"Tenko micro-F1 >= Kitsune for attack prevalence <= {cross_f1:.4f}")

# ============================================================
# Write CSV
# ============================================================
csv_path = f"{M}/ciciot2023_prevalence_sweep_metrics.csv"
with open(csv_path, "w") as f:
    f.write("detector,attack_prevalence,TPR,FPR,Precision,microF1,Accuracy,AUC_ROC,AUC_PR\n")
    for r in rows:
        f.write(f"{r[0]},{r[1]:.3f},{r[2]:.6f},{r[3]:.6f},{r[4]:.6f},{r[5]:.6f},{r[6]:.6f},{r[7]:.6f},{r[8]:.6f}\n")
print(f"\nWrote {csv_path}")

# Dump structured values for the memo
import json
out = dict(
    kit_thr=kit_thr, kit_med=med, kit_mad=mad,
    tenko=dict(fpr=t["fpr"], FP=t["FP"], tpr=t["tpr"], auc=auc_t, per_attack=t["per_attack"]),
    kitsune=dict(fpr=k["fpr"], FP=k["FP"], tpr=k["tpr"], auc=auc_k, per_attack=k["per_attack"]),
    cross_acc=cross_acc, cross_f1=cross_f1,
    rows=rows,
)
with open(f"{M}/_prevalence_sweep_dump.json", "w") as f:
    json.dump(out, f, indent=2, default=float)
print(f"Wrote {M}/_prevalence_sweep_dump.json")
