#!/usr/bin/env python3
"""PREVIEW: pooled 'one big stream' (mixed) CICIoT2023 evaluation from cached
single-tanh benignLimit=60000 arrays. Shared benign (identical across attacks)
is counted ONCE as negatives; all 6 attacks pooled as positives. This mirrors
Table 9 (tab:mateen_comparative_performance): Accuracy / F1 / Macro-F1 / AUC-ROC.

NOTE: this pools per-attack cached scores (node state does NOT carry across
attacks). A faithful physically-concatenated run is being built separately.

Clean-split windows (test_idx = stream-60000):
  benign test negatives : [40000:120000] (80000, burst included)  -- shared
  each attack positives  : [120000:170000] (50000)
"""
from __future__ import annotations
import numpy as np
from sklearn.metrics import roc_curve, auc as sk_auc

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
BEN = slice(40000, 120000)
ATK = slice(120000, 170000)
EG, ES = 50.0, 20.0


def load(a):
    ndg = np.load(f"{OUT}/arr_ndg_{a}_s60k.npy")
    nds = np.load(f"{OUT}/arr_nds_{a}_s60k.npy")
    cont = np.load(f"{OUT}/arr_cont_{a}_s60k.npy")
    return ndg, nds, cont


def f1_of(tp, fp, fn):
    return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float('nan')


def main():
    # shared benign (identical across attacks): take from first attack, verify identical
    ndg0, nds0, cont0 = load(ATTACKS[0])
    ben_ndg, ben_nds, ben_cont = ndg0[BEN], nds0[BEN], cont0[BEN]
    for a in ATTACKS[1:]:
        g, s, c = load(a)
        assert np.allclose(g[BEN], ben_ndg) and np.allclose(s[BEN], ben_nds), \
            f"benign differs for {a} -> pooling-once invalid"

    # benign false positives at committed eta (shared, counted once)
    ben_flag = (ben_ndg > EG) | (ben_nds > ES)
    fp = int(ben_flag.sum()); tn = int((~ben_flag).sum())
    n_ben = fp + tn

    # pool attacks
    tp_total = fn_total = 0
    per_attack_f1 = []
    atk_cont_all = []
    for a in ATTACKS:
        ndg, nds, cont = load(a)
        af = (ndg[ATK] > EG) | (nds[ATK] > ES)
        tp = int(af.sum()); fn = int((~af).sum())
        tp_total += tp; fn_total += fn
        per_attack_f1.append(f1_of(tp, fp, fn))  # each attack vs shared benign
        atk_cont_all.append(cont[ATK])

    n_atk = tp_total + fn_total
    # micro (pooled) metrics
    tpr = tp_total / (tp_total + fn_total)
    fpr = fp / (fp + tn)
    prec = tp_total / (tp_total + fp) if (tp_total + fp) else float('nan')
    micro_f1 = f1_of(tp_total, fp, fn_total)
    acc = (tp_total + tn) / (tp_total + tn + fp + fn_total)
    macro_f1 = float(np.mean(per_attack_f1))

    # AUC-ROC / EER pooled (benign 0 vs all-attacks 1) on continuous fused score
    scores = np.concatenate([ben_cont] + atk_cont_all)
    labels = np.concatenate([np.zeros(n_ben, int), np.ones(n_atk, int)])
    froc, troc, _ = roc_curve(labels, scores)
    roc_auc = sk_auc(froc, troc)
    fnr = 1 - troc
    i = int(np.nanargmin(np.abs(fnr - froc)))
    eer = (froc[i] + fnr[i]) / 2

    print("\n===== MIXED / ONE-BIG-STREAM (pooled preview) CICIoT2023, committed eta=50/20 =====")
    print(f"  negatives (shared benign) = {n_ben}  |  positives (6 attacks pooled) = {n_atk}")
    print(f"  Accuracy   = {acc:.4f}")
    print(f"  F1 (micro) = {micro_f1:.4f}")
    print(f"  Macro-F1   = {macro_f1:.4f}   (mean of per-attack F1)")
    print(f"  AUC-ROC    = {roc_auc:.4f}")
    print(f"  EER        = {eer:.4f}")
    print(f"  (TPR={tpr:.4f} FPR={fpr:.4f} Precision={prec:.4f})")
    print("\n  per-attack F1 (vs shared benign, committed eta):")
    for a, f in zip(ATTACKS, per_attack_f1):
        print(f"    {a:24s} {f:.4f}")


if __name__ == "__main__":
    main()
