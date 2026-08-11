#!/usr/bin/env python3
"""Rebuild the mixed-stream comparison table (paper Table X).

Output: results/CICIoT2023/baselines/table_ix_mixed_with_iforest.csv

  python results/CICIoT2023/build_table_ix_mixed.py
  python results/CICIoT2023/build_table_ix_mixed.py --check
"""
from __future__ import annotations

import argparse
import csv
import os

import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
MIX = os.path.join(HERE, "mixed")
BASE = os.path.join(HERE, "baselines")
OUT = os.path.join(BASE, "table_ix_mixed_with_iforest.csv")

N_BEN = 60_000  # eval-region benign leading the test arrays


def f1_from_counts(tp, fp, fn):
    d = 2 * tp + fp + fn
    return (2 * tp / d) if d else float("nan")


def scalar_metrics(y, pred, score):
    pred = np.asarray(pred).astype(int)
    y = np.asarray(y).astype(int)
    tp = int(pred[y == 1].sum())
    fp = int(pred[y == 0].sum())
    fn = int((y == 1).sum() - tp)
    tn = int((y == 0).sum() - fp)
    tpr = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    f1 = f1_from_counts(tp, fp, fn)
    acc = (tp + tn) / len(y)
    auc = float(roc_auc_score(y, score))
    return dict(TPR=tpr, FPR=fpr, Precision=prec, F1=f1, Accuracy=acc, AUC_ROC=auc)


def calibrate_orrule(ndg_ben, nds_ben, target_fpr=0.02, tol=1e-4, iters=60):
    """Pick shared tail prob p so benign OR-flag rate ~= target_fpr."""
    lo, hi = 0.0, target_fpr
    best = None
    for _ in range(iters):
        p = 0.5 * (lo + hi)
        eg = float(np.quantile(ndg_ben, 1.0 - p))
        es = float(np.quantile(nds_ben, 1.0 - p))
        rate = float(((ndg_ben > eg) | (nds_ben > es)).mean())
        best = (eg, es, rate, p)
        if abs(rate - target_fpr) < tol:
            break
        if rate > target_fpr:
            hi = p
        else:
            lo = p
    return best


def load():
    y = np.load(os.path.join(MIX, "arr_gold_mixed.npy")).astype(int)
    ndg = np.load(os.path.join(MIX, "arr_ndg_mixed.npy"))
    nds = np.load(os.path.join(MIX, "arr_nds_mixed.npy"))
    cont = np.load(os.path.join(MIX, "arr_cont_mixed.npy"))
    kit = np.load(os.path.join(MIX, "kitsune_testscores_mixed.npy"))
    mateen = np.load(os.path.join(BASE, "mateen", "mateen_mixed.npz"))
    vae = np.load(os.path.join(BASE, "vaeesdd", "vaeesdd_mixed.npz"))
    ifo = np.load(os.path.join(BASE, "iforest", "iforest_mixed.npz"))
    return y, ndg, nds, cont, kit, mateen, vae, ifo


def build_rows():
    y, ndg, nds, cont, kit, mateen, vae, ifo = load()
    ben = slice(0, N_BEN)

    # η on eval-region benign (paper Table X operating point).
    eg, es, _ach, _p = calibrate_orrule(ndg[ben], nds[ben], 0.02)
    tenko_pred = ((ndg > eg) | (nds > es)).astype(int)

    b = kit[ben]
    kit_thr = float(np.median(b) + 3 * 1.4826 * np.median(np.abs(b - np.median(b))))
    kit_pred = (kit > kit_thr).astype(int)

    rows = []
    rows.append(("Tenko (OR-rule)", scalar_metrics(y, tenko_pred, cont)))
    rows.append(("Kitsune (med+MAD)", scalar_metrics(y, kit_pred, kit)))
    rows.append(("Mateen (native adaptive preds)",
                 scalar_metrics(y, mateen["preds"], mateen["scores"])))
    rows.append(("VAEESDD frozen (train p95)",
                 scalar_metrics(y, vae["preds"], vae["scores"])))
    rows.append(("Paper1 iForest (z-score on decision_function)",
                 scalar_metrics(y, ifo["preds_zscore"], ifo["scores"])))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="compare against committed CSV instead of overwriting")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    rows = build_rows()
    cols = ["method", "TPR", "FPR", "Precision", "F1", "Accuracy", "AUC_ROC"]

    if args.check:
        with open(OUT) as f:
            committed = {r["method"].split("(")[0].strip(): r
                         for r in csv.DictReader(f)}
        ok = True
        for name, m in rows:
            key = name.split("(")[0].strip()
            ref = committed.get(key)
            if ref is None:
                print(f"[MISS] {key} not in committed CSV")
                ok = False
                continue
            for c in cols[1:]:
                a, b = m[c], float(ref[c])
                if abs(a - b) > 1e-3:
                    print(f"[DIFF] {key}.{c}: rebuilt={a:.6f} committed={b:.6f}")
                    ok = False
        print("CHECK:", "PASS (rebuilt == committed within 1e-3)" if ok else "FAIL")
        return

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for name, m in rows:
            w.writerow([name] + [m[c] for c in cols[1:]])
    print(f"wrote {args.out}")
    for name, m in rows:
        print(f"  {name:48s} TPR={m['TPR']:.4f} FPR={m['FPR']:.4f} "
              f"F1={m['F1']:.4f} Acc={m['Accuracy']:.4f} AUC={m['AUC_ROC']:.4f}")


if __name__ == "__main__":
    main()
