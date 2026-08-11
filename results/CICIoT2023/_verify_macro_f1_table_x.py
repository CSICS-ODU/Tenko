#!/usr/bin/env python3
"""Verify Macro F1 in Table X (cic_mixed_comparison / table_ix_mixed_with_iforest).

Shows that reported MacroF1 = mean of 6 per-attack F1s (each block vs shared
60k benign), NOT sklearn binary f1_macro / reviewer binary macro-F1.

Run:
  .venv/bin/python results/CICIoT2023/_verify_macro_f1_table_x.py
"""
from __future__ import annotations

import csv
import os

import numpy as np
from sklearn.metrics import f1_score, precision_score, roc_auc_score

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CIC = os.path.join(ROOT, "results", "CICIoT2023")
MIX = os.path.join(CIC, "mixed")
CSV = os.path.join(CIC, "baselines", "table_ix_mixed_with_iforest.csv")

ATTACK_BLOCKS = [
    ("DoS-SYN_Flood", 60_000, 110_000),
    ("DDoS-UDP_Flood", 110_000, 160_000),
    ("Recon-OSScan", 160_000, 210_000),
    ("MITM-ArpSpoofing", 210_000, 260_000),
    ("Mirai-greeth_flood", 260_000, 310_000),
    ("DictionaryBruteForce", 310_000, 360_000),
]


def f1_from_counts(tp, fp, fn):
    d = 2 * tp + fp + fn
    return (2 * tp / d) if d else float("nan")


def per_attack_macro(y, pred):
    pred = np.asarray(pred).astype(int)
    fp_shared = int(pred[y == 0].sum())
    per = []
    for _, s, e in ATTACK_BLOCKS:
        blk = pred[s:e]
        tp = int(blk.sum())
        fn = int((blk == 0).sum())
        per.append(f1_from_counts(tp, fp_shared, fn))
    return float(np.mean(per)), per


def binary_macro_from_rates(tpr, fpr, n_ben=60_000, n_atk=300_000):
    tp = tpr * n_atk
    fp = fpr * n_ben
    fn = (1.0 - tpr) * n_atk
    tn = (1.0 - fpr) * n_ben
    f1_atk = f1_from_counts(tp, fp, fn)
    r_ben = 1.0 - fpr
    p_ben = tn / (tn + fn) if (tn + fn) else float("nan")
    f1_ben = (2 * p_ben * r_ben / (p_ben + r_ben)) if (p_ben + r_ben) else float("nan")
    return 0.5 * (f1_atk + f1_ben), f1_atk, f1_ben


def main():
    y = np.load(os.path.join(MIX, "arr_gold_mixed.npy")).astype(int)
    ndg = np.load(os.path.join(MIX, "arr_ndg_mixed.npy"))
    nds = np.load(os.path.join(MIX, "arr_nds_mixed.npy"))
    cont = np.load(os.path.join(MIX, "arr_cont_mixed.npy"))
    kit = np.load(os.path.join(MIX, "kitsune_testscores_mixed.npy"))
    mateen = np.load(os.path.join(CIC, "baselines", "mateen", "mateen_mixed.npz"))
    vae = np.load(os.path.join(CIC, "baselines", "vaeesdd", "vaeesdd_mixed.npz"))
    ifo = np.load(os.path.join(CIC, "baselines", "iforest", "iforest_mixed.npz"))

    b = kit[y == 0]
    kit_thr = float(np.median(b) + 3 * 1.4826 * np.median(np.abs(b - np.median(b))))

    methods = [
        ("Tenko (orrule@2%)", ((ndg > 30.14) | (nds > 3.14)).astype(int), cont),
        ("Kitsune (med+MAD)", (kit > kit_thr).astype(int), kit),
        ("Mateen", mateen["preds"].astype(int), mateen["scores"]),
        ("VAEESDD frozen", vae["preds"].astype(int), vae["scores"]),
        ("iForest z-score", ifo["preds_zscore"].astype(int), ifo["scores"]),
    ]

    print(f"{'method':22s} {'TPR':>7s} {'FPR':>7s} {'F1':>7s} "
          f"{'binMac':>7s} {'atkMac':>7s} {'skMac':>7s} {'CSV':>7s}")
    csv_macro = {}
    with open(CSV) as f:
        for row in csv.DictReader(f):
            key = row["method"].split("(")[0].strip().lower()
            csv_macro[key] = float(row["MacroF1"])

    for name, pred, score in methods:
        tpr = float(pred[y == 1].mean())
        fpr = float(pred[y == 0].mean())
        f1 = float(f1_score(y, pred, pos_label=1, zero_division=0))
        sk = float(f1_score(y, pred, average="macro", zero_division=0))
        bin_m, _, _ = binary_macro_from_rates(tpr, fpr)
        atk_m, _ = per_attack_macro(y, pred)
        key = name.split("(")[0].strip().lower()
        # fuzzy CSV lookup
        csv_v = None
        for k, v in csv_macro.items():
            if key.split()[0] in k or k.split()[0] in key:
                csv_v = v
                break
        if "iforest" in key or "paper1" in str(csv_macro):
            for k, v in csv_macro.items():
                if "iforest" in k or "paper1" in k:
                    if "ifo" in key or "iforest" in key:
                        csv_v = v
        print(f"{name:22s} {tpr:7.4f} {fpr:7.4f} {f1:7.4f} "
              f"{bin_m:7.4f} {atk_m:7.4f} {sk:7.4f} "
              f"{(csv_v if csv_v is not None else float('nan')):7.4f}")

    print("\nNotes:")
    print("  binMac = mean(attack F1, benign F1) from TPR/FPR [= sklearn f1_macro]")
    print("  atkMac = mean of 6 per-attack F1s vs shared benign [= CSV MacroF1]")
    print("  Tenko OP: (nd_g>30.14) OR (nd_s>3.14)  [orrule@2%]")


if __name__ == "__main__":
    main()
