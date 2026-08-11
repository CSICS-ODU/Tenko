#!/usr/bin/env python3
"""TASK 3 -- fully OUT-OF-SAMPLE eta recalibration for CICIoT2023.

Fixes the in-sample FPR caveat of recalibrate_ciciot2023.py, where eta was fit on
benign_test and FPR was then measured on that SAME benign_test (definitional).

Protocol (no attack labels used anywhere in eta selection):
  benign_test region = arr indices [0 : n_test]      (0=benign, contiguous same-trace)
  attack region      = arr indices [n_test : n_test+n_attack]
  CALIB  = first half of benign_test  [0 : n_test//2]      <- eta selected here ONLY
  EVAL   = second half of benign_test [n_test//2 : n_test]  <- held-out benign, disjoint

Steps per (attack, tanh variant, FPR target):
  1. On CALIB, find a shared benign quantile q such that the committed FUSED rule
     ((nd_g>eta_g) OR (nd_s>eta_s)) hits the target benign FPR. eta_g=Q(calib_ndg,q),
     eta_s=Q(calib_nds,q). (identical calibrator to the in-sample script, different data)
  2. HONEST test set = held-out EVAL benign (negatives) + attack (positives).
     Report held-out benign FPR (the honest number) and TPR/Precision/F1 there.
  3. AUC/EER threshold-independent, computed on the SAME honest EVAL+attack set.

Writes results/CICIoT2023/ciciot2023_metrics_recalibrated_oos.csv and prints tables,
including the shift vs the in-sample version (recalibrate_ciciot2023.py output).
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
FPR_TARGETS = [0.01, 0.05]
VARIANTS = ["double", "single"]


def load(attack, tag):
    g = np.load(f"{OUT}/arr_gold_{attack}.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{attack}_{tag}.npy")
    nds = np.load(f"{OUT}/arr_nds_{attack}_{tag}.npy")
    return g, ndg, nds


def point_metrics(gold, pred):
    cm = confusion_matrix(gold, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    tpr = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")
    return dict(tpr=tpr, fpr=fpr, precision=prec, f1=f1,
                tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))


def auc_eer(gold, scores):
    gold = np.asarray(gold)
    if gold.sum() == 0 or gold.sum() == len(gold):
        return float("nan"), float("nan")
    fpr, tpr, _ = roc_curve(gold, scores)
    a = auc(fpr, tpr)
    fnr = 1 - tpr
    i = int(np.nanargmin(np.abs(fpr - fnr)))
    return float(a), float((fpr[i] + fnr[i]) / 2)


def calibrate_shared_quantile(cal_ndg, cal_nds, target_fpr):
    """Shared benign quantile q on CALIB s.t. fused OR benign FPR ~= target (from below)."""
    qs = np.concatenate([np.linspace(0.50, 0.90, 41), np.linspace(0.9001, 0.99999, 900)])
    best = None
    for q in qs:
        eg = float(np.quantile(cal_ndg, q))
        es = float(np.quantile(cal_nds, q))
        fpr = float(np.mean((cal_ndg > eg) | (cal_nds > es)))
        cand = (fpr, q, eg, es)

        def score(c):
            f = c[0]
            over = 0 if f <= target_fpr + 1e-9 else 1
            return (over, abs(f - target_fpr))
        if best is None or score(cand) < score(best):
            best = cand
    return best  # (achieved_calib_fpr, q, eta_g, eta_s)


def main():
    counts = pd.read_csv(f"{OUT}/stream_counts.csv").set_index("attack")
    # in-sample reference (double-tanh) to report the shift
    insample = pd.read_csv(f"{OUT}/ciciot2023_metrics_recalibrated.csv")

    rows = []
    for a in ATTACKS:
        n_test = int(counts.loc[a, "n_test"])
        n_atk = int(counts.loc[a, "n_attack"])
        benignLimit = int(counts.loc[a, "benignLimit"])
        half = n_test // 2  # CALIB = [0:half], EVAL = [half:n_test]

        for tag in VARIANTS:
            g, ndg, nds = load(a, tag)
            assert len(g) == n_test + n_atk, f"{a}/{tag} len mismatch"

            atk_ndg, atk_nds = ndg[n_test:], nds[n_test:]
            # benign_test is non-stationary (warm-up transient in the first packets),
            # so the honest held-out FPR is split-direction sensitive. Report BOTH:
            #   fwd: calibrate on first half, evaluate held-out on second half
            #   rev: calibrate on second half, evaluate held-out on first half
            splits = {
                "fwd": ((slice(0, half)), (slice(half, n_test))),
                "rev": ((slice(half, n_test)), (slice(0, half))),
            }
            for split_name, (cal_sl, ev_sl) in splits.items():
                cal_ndg, cal_nds = ndg[cal_sl], nds[cal_sl]
                eval_ndg, eval_nds = ndg[ev_sl], nds[ev_sl]
                n_eval = len(eval_ndg)
                gold_oos = np.concatenate([np.zeros(n_eval, int), np.ones(n_atk, int)])
                hg = np.concatenate([eval_ndg, atk_ndg])
                hs = np.concatenate([eval_nds, atk_nds])
                cont_oos = 0.5 * hg + 0.5 * hs
                a_auc, a_eer = auc_eer(gold_oos, cont_oos)

                for target in FPR_TARGETS:
                    cal_fpr, q, eg, es = calibrate_shared_quantile(cal_ndg, cal_nds, target)
                    heldout_fpr = float(np.mean((eval_ndg > eg) | (eval_nds > es)))
                    pred_oos = ((hg > eg) | (hs > es)).astype(int)
                    pm = point_metrics(gold_oos, pred_oos)

                    # shift vs in-sample (double variant reference)
                    ins = insample[(insample.attack == a) &
                                   (np.isclose(insample.target_benign_fpr, target))]
                    d_tpr = d_f1 = ins_tpr = ins_f1 = float("nan")
                    if len(ins):
                        ins_tpr = float(ins.iloc[0]["TPR"]); ins_f1 = float(ins.iloc[0]["F1"])
                        d_tpr = pm["tpr"] - ins_tpr
                        d_f1 = pm["f1"] - ins_f1

                    rows.append({
                        "attack": a, "variant": tag, "split": split_name,
                        "target_benign_fpr": target,
                        "shared_q": round(q, 6), "eta_global": eg, "eta_node": es,
                        "calib_benign_fpr": round(cal_fpr, 6),
                        "heldout_benign_fpr": round(heldout_fpr, 6),
                        "heldout_fpr_minus_target": round(heldout_fpr - target, 6),
                        "TPR": pm["tpr"], "FPR": pm["fpr"], "Precision": pm["precision"],
                        "F1": pm["f1"], "AUC": a_auc, "EER": a_eer,
                        "n_calib_benign": len(cal_ndg), "n_eval_benign": n_eval,
                        "n_attack": n_atk, "benignLimit": benignLimit,
                        "insample_TPR": ins_tpr, "insample_F1": ins_f1,
                        "dTPR_vs_insample": d_tpr, "dF1_vs_insample": d_f1,
                    })

    df = pd.DataFrame(rows)
    df.to_csv(f"{OUT}/ciciot2023_metrics_recalibrated_oos.csv", index=False)

    pd.set_option("display.width", 240)
    pd.set_option("display.max_columns", 40)
    for tag in VARIANTS:
        for split_name in ("fwd", "rev"):
            print(f"\n===== OOS recalibration :: {tag}-tanh :: split={split_name} "
                  f"(calib={'first' if split_name=='fwd' else 'second'} half) =====")
            sub = df[(df.variant == tag) & (df.split == split_name)]
            print(sub[["attack", "target_benign_fpr", "eta_global", "eta_node",
                       "calib_benign_fpr", "heldout_benign_fpr", "heldout_fpr_minus_target",
                       "TPR", "FPR", "Precision", "F1", "AUC", "EER"]].to_string(index=False))
    print("\n===== shift vs in-sample (double-tanh, fwd split) =====")
    print(df[(df.variant == "double") & (df.split == "fwd")][["attack", "target_benign_fpr",
          "insample_TPR", "TPR", "dTPR_vs_insample",
          "insample_F1", "F1", "dF1_vs_insample"]].to_string(index=False))
    print("\nwrote:", f"{OUT}/ciciot2023_metrics_recalibrated_oos.csv")


if __name__ == "__main__":
    main()
