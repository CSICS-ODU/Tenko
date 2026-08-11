#!/usr/bin/env python3
"""Offline analysis for the two CICIoT2023 follow-up tasks (no X1/X2 rerun needed).

Reads the per-test-packet arrays saved by run_ciciot2023.py:
  arr_gold_<attack>.npy            test-region labels (0=benign_test, 1=attack)
  arr_ndg_<attack>_<tag>.npy       global normalized pattern distance (distance / benign spread)
  arr_nds_<attack>_<tag>.npy       single-aggregate normalized pattern distance
  arr_cont_<attack>_<tag>.npy      fused normalized distance (0.5*ndg + 0.5*nds)
  arr_node_<attack>_<tag>.npy      X2 node anomaly score
  arr_kitsune_<attack>.npy         Kitsune test score = tanh(raw RMSE)   (variant-independent)
tag in {double, single}.

TASK 1: recalibrate eta on benign_test ONLY (no attack labels) so the FUSED
committed rule ((nd_g>eta_g) OR (nd_s>eta_s), from weights 0.5/0.5 & T=0.5)
achieves a target benign_test FPR. eta_g,eta_s are derived from a single shared
benign quantile q found by 1-D search on benign_test; this yields distinct,
benign-only eta values while pinning the fused benign FPR to the target.
Uses the DOUBLE-tanh variant = the committed Tenko pipeline.

TASK 2: single vs double tanh -- pattern-distance AUC/EER per attack, and
whether the committed eta=50/20 operating point is degenerate under each.
"""
from __future__ import annotations
import csv
import os
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_curve, auc

OUT = os.environ.get("CIC_RESULTS_ROOT", "./results/CICIoT2023")
ATTACKS = ["DDoS-UDP_Flood", "DoS-SYN_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
COMMITTED_ETA_G = 50.0
COMMITTED_ETA_S = 20.0
FPR_TARGETS = [0.01, 0.05]


def load(attack, tag):
    g = np.load(f"{OUT}/arr_gold_{attack}.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{attack}_{tag}.npy")
    nds = np.load(f"{OUT}/arr_nds_{attack}_{tag}.npy")
    cont = np.load(f"{OUT}/arr_cont_{attack}_{tag}.npy")
    return g, ndg, nds, cont


def point_metrics(gold, pred):
    cm = confusion_matrix(gold, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    tpr = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")
    return dict(tpr=tpr, fpr=fpr, precision=prec, f1=f1,
               tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))


def f1_from_pr(p, r):
    return (2 * p * r / (p + r)) if (p + r) > 0 else float("nan")


def auc_eer(gold, scores):
    gold = np.asarray(gold)
    if gold.sum() == 0 or gold.sum() == len(gold):
        return float("nan"), float("nan")
    fpr, tpr, _ = roc_curve(gold, scores)
    a = auc(fpr, tpr)
    fnr = 1 - tpr
    i = int(np.nanargmin(np.abs(fpr - fnr)))
    return float(a), float((fpr[i] + fnr[i]) / 2)


def calibrate_shared_quantile(benign_ndg, benign_nds, target_fpr):
    """Find shared benign quantile q s.t. fused OR benign FPR ~= target (from below)."""
    qs = np.concatenate([np.linspace(0.50, 0.90, 41), np.linspace(0.9001, 0.99999, 900)])
    best = None
    for q in qs:
        eg = float(np.quantile(benign_ndg, q))
        es = float(np.quantile(benign_nds, q))
        fpr = float(np.mean((benign_ndg > eg) | (benign_nds > es)))
        # prefer the highest FPR that does not exceed target; fallback nearest
        cand = (fpr, q, eg, es)
        if best is None:
            best = cand
        else:
            # closeness to target, tie-break preferring fpr<=target
            def score(c):
                f = c[0]
                over = 0 if f <= target_fpr + 1e-9 else 1
                return (over, abs(f - target_fpr))
            if score(cand) < score(best):
                best = cand
    return best  # (achieved_fpr, q, eta_g, eta_s)


def main():
    counts = pd.read_csv(f"{OUT}/stream_counts.csv").set_index("attack")

    recal_rows = []          # for ciciot2023_metrics_recalibrated.csv
    combined_rows = []       # for canonical ciciot2023_per_class_metrics.csv
    impact_rows = []         # for ciciot2023_tanh_impact.csv

    for a in ATTACKS:
        n_test = int(counts.loc[a, "n_test"]); n_atk = int(counts.loc[a, "n_attack"])
        benignLimit = int(counts.loc[a, "benignLimit"])
        kscores = np.load(f"{OUT}/arr_kitsune_{a}.npy")

        # ----- Kitsune (variant-independent) -----
        # rebuild point metrics from the committed Median+MAD threshold used in run driver:
        # we recompute AUC/EER from continuous kscores; point metrics come from run log CSV.
        # (Kitsune point metrics already in ciciot2023_committedEta_double.csv row "Kitsune")

        # ================= TASK 2: single vs double =================
        rec = {"attack": a}
        for tag in ("double", "single"):
            g, ndg, nds, cont = load(a, tag)
            assert len(g) == n_test + n_atk, f"{a}/{tag} len {len(g)} != {n_test+n_atk}"
            a_auc, a_eer = auc_eer(g, cont)
            # committed eta operating point
            pred_committed = ((ndg > COMMITTED_ETA_G) | (nds > COMMITTED_ETA_S)).astype(int)
            pm = point_metrics(g, pred_committed)
            degen = (pm["tp"] + pm["fp"]) == 0
            rec[f"{tag}_pattern_AUC"] = a_auc
            rec[f"{tag}_pattern_EER"] = a_eer
            rec[f"{tag}_committedEta_TPR"] = pm["tpr"]
            rec[f"{tag}_committedEta_FPR"] = pm["fpr"]
            rec[f"{tag}_committedEta_degenerate"] = int(degen)
        ka, ke = auc_eer(np.load(f"{OUT}/arr_gold_{a}.npy"), kscores)
        rec["kitsune_AUC"] = ka; rec["kitsune_EER"] = ke
        impact_rows.append(rec)

        # ================= TASK 1: benign-only eta recalibration (DOUBLE = committed pipeline) =================
        g, ndg, nds, cont = load(a, "double")
        benign_ndg, benign_nds = ndg[:n_test], nds[:n_test]
        t_auc, t_eer = auc_eer(g, cont)  # threshold-independent (unchanged by operating point)

        for target in FPR_TARGETS:
            achieved, q, eg, es = calibrate_shared_quantile(benign_ndg, benign_nds, target)
            pred = ((ndg > eg) | (nds > es)).astype(int)
            pm = point_metrics(g, pred)
            # F1 reconciliation from precision & recall
            f1_check = f1_from_pr(pm["precision"], pm["tpr"])
            f1_ok = (np.isnan(pm["f1"]) and np.isnan(f1_check)) or abs(pm["f1"] - f1_check) < 1e-6
            recal_rows.append({
                "attack": a, "target_benign_fpr": target,
                "shared_q": round(q, 6), "eta_global": eg, "eta_node": es,
                "achieved_benign_fpr_calib": achieved,
                "TPR": pm["tpr"], "FPR": pm["fpr"], "Precision": pm["precision"],
                "F1": pm["f1"], "F1_recomputed": f1_check, "F1_ok": int(bool(f1_ok)),
                "AUC": t_auc, "EER": t_eer, "n_benign_test": n_test, "n_attack": n_atk,
                "benignLimit": benignLimit,
            })

    # ---------- write TASK1 recalibrated CSV ----------
    with open(f"{OUT}/ciciot2023_metrics_recalibrated.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(recal_rows[0].keys()))
        w.writeheader()
        for r in recal_rows:
            w.writerow(r)

    # ---------- write TASK2 impact CSV ----------
    with open(f"{OUT}/ciciot2023_tanh_impact.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(impact_rows[0].keys()))
        w.writeheader()
        for r in impact_rows:
            w.writerow(r)

    # ---------- rebuild canonical combined CSV with 4 row-groups ----------
    # pull Kitsune + committed-eta(double) point metrics from the driver's double CSV
    dbl = pd.read_csv(f"{OUT}/ciciot2023_committedEta_double.csv")
    def drow(attack, model):
        r = dbl[(dbl.attack == attack) & (dbl.model == model)].iloc[0]
        return r
    recal_df = pd.DataFrame(recal_rows)
    with open(f"{OUT}/ciciot2023_per_class_metrics.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "model", "TPR", "FPR", "Precision", "F1", "AUC", "EER",
                    "n_benign_test", "n_attack", "benignLimit_used"])
        for a in ATTACKS:
            k = drow(a, "Kitsune"); t = drow(a, "Tenko")
            n_test = int(counts.loc[a, "n_test"]); n_atk = int(counts.loc[a, "n_attack"])
            bl = int(counts.loc[a, "benignLimit"])
            w.writerow([a, "Kitsune", f"{k.TPR:.6f}", f"{k.FPR:.6f}", f"{k.Precision:.6f}",
                        f"{k.F1:.6f}", f"{k.AUC:.6f}", f"{k.EER:.6f}", n_test, n_atk, bl])
            w.writerow([a, "Tenko (committed eta=50/20, degenerate)", f"{t.TPR:.6f}", f"{t.FPR:.6f}",
                        f"{t.Precision}", f"{t.F1:.6f}", f"{t.AUC:.6f}", f"{t.EER:.6f}", n_test, n_atk, bl])
            for target in FPR_TARGETS:
                rr = recal_df[(recal_df.attack == a) & (recal_df.target_benign_fpr == target)].iloc[0]
                w.writerow([a, f"Tenko (eta recal benign, FPR@{int(target*100)}%)",
                            f"{rr.TPR:.6f}", f"{rr.FPR:.6f}", f"{rr.Precision:.6f}", f"{rr.F1:.6f}",
                            f"{rr.AUC:.6f}", f"{rr.EER:.6f}", n_test, n_atk, bl])

    # ---------- console report ----------
    print("=== TASK 1: recalibrated eta (double-tanh, committed pipeline) ===")
    print(recal_df[["attack", "target_benign_fpr", "eta_global", "eta_node",
                    "achieved_benign_fpr_calib", "TPR", "FPR", "Precision", "F1",
                    "F1_ok", "AUC", "EER"]].to_string(index=False))
    print("\n=== TASK 2: single vs double tanh impact ===")
    imp = pd.DataFrame(impact_rows)
    print(imp.to_string(index=False))
    print("\nAll F1 reconciled:", int(recal_df["F1_ok"].all()))


if __name__ == "__main__":
    main()
