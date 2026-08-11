#!/usr/bin/env python3
"""Clean-split metrics for CICIoT2023 (single-tanh, benignLimit=60000 cached arrays).

Design (no in-window / held-out cherry-pick): training + eta calibration all finish
by stream index 100000; EVERY benign packet after 100000 is one test set (burst
included) and gives a SINGLE FPR per attack.

Cached test arrays cover stream [60000:230000] (len 170000); test_idx = stream-60000.
  calib benign : stream [60000:100000] -> test_idx [0     : 40000 ]  (40000)  eta selection ONLY
  test  benign : stream [100000:180000]-> test_idx [40000 : 120000]  (80000)  FPR negatives (burst inside)
  attack       : stream [180000:230000]-> test_idx [120000:170000]  (50000)  TPR positives
  (burst window stream [140000:160000] -> test_idx [80000:100000])
Fused OR rule (wg=ws=.5,T=.5): pred = (nd_g > eta_g) | (nd_s > eta_s).
Continuous score for AUC/EER = arr_cont = 0.5*nd_g + 0.5*nd_s (results.py:956, eta-free).
"""
from __future__ import annotations
import csv, numpy as np
from sklearn.metrics import roc_curve, auc as sk_auc

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]

CALIB = slice(0, 40000)        # stream 60k..100k
TEST_BEN = slice(40000, 120000)  # stream 100k..180k  (negatives; burst inside)
ATK = slice(120000, 170000)    # stream 180k..230k
# burst / calm sub-windows inside TEST_BEN (for diagnostic breakdown)
BURST = slice(80000, 100000)   # stream 140k..160k
CALM_A = slice(40000, 80000)   # stream 100k..140k
CALM_B = slice(100000, 120000) # stream 160k..180k
N_TEST_BEN, N_ATK = 80000, 50000
FPR_TARGETS = [0.01, 0.05]


def load(a):
    g = np.load(f"{OUT}/arr_gold_{a}_s60k.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{a}_s60k.npy")
    nds = np.load(f"{OUT}/arr_nds_{a}_s60k.npy")
    cont = np.load(f"{OUT}/arr_cont_{a}_s60k.npy")
    assert len(g) == 170000, f"{a}: len {len(g)}"
    # sanity: calib+test benign are benign, attack region is attack
    assert g[CALIB].sum() == 0 and g[TEST_BEN].sum() == 0, f"{a}: benign region has attacks"
    assert g[ATK].sum() == N_ATK, f"{a}: attack count {g[ATK].sum()}"
    return g, ndg, nds, cont


def metrics(atk_flag, ben_flag):
    tp = int(atk_flag.sum()); fn = int((~atk_flag).sum())
    fp = int(ben_flag.sum()); tn = int((~ben_flag).sum())
    tpr = tp / (tp + fn) if (tp + fn) else float('nan')
    fpr = fp / (fp + tn) if (fp + tn) else float('nan')
    prec = tp / (tp + fp) if (tp + fp) else float('nan')
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float('nan')
    acc = (tp + tn) / (tp + tn + fp + fn)
    return dict(TPR=tpr, FPR=fpr, Precision=prec, F1=f1, Accuracy=acc,
                tp=tp, fp=fp, fn=fn, tn=tn)


def eval_eta(ndg, nds, eg, es):
    atk_flag = (ndg[ATK] > eg) | (nds[ATK] > es)
    ben_flag = (ndg[TEST_BEN] > eg) | (nds[TEST_BEN] > es)
    return metrics(atk_flag, ben_flag)


def calib_q(cndg, cnds, target):
    qs = np.concatenate([np.linspace(0.50, 0.90, 41), np.linspace(0.9001, 0.99999, 1500)])
    best = None
    for q in qs:
        eg = float(np.quantile(cndg, q)); es = float(np.quantile(cnds, q))
        fpr = float(np.mean((cndg > eg) | (cnds > es)))
        key = (0 if fpr <= target + 1e-9 else 1, abs(fpr - target))
        if best is None or key < best[0]:
            best = (key, eg, es, fpr)
    return best[1], best[2], best[3]  # eta_g, eta_s, calib_fpr


def auc_eer(cont, g):
    sc = np.concatenate([cont[TEST_BEN], cont[ATK]])
    lab = np.concatenate([np.zeros(N_TEST_BEN, int), np.ones(N_ATK, int)])
    fpr, tpr, _ = roc_curve(lab, sc)
    a = sk_auc(fpr, tpr)
    fnr = 1 - tpr
    i = np.nanargmin(np.abs(fnr - fpr))
    eer = (fpr[i] + fnr[i]) / 2
    return a, eer


def main():
    rows, diag = [], []
    for a in ATTACKS:
        g, ndg, nds, cont = load(a)
        A, E = auc_eer(cont, g)

        # committed fixed eta=50/20 (benign-only, no labels)
        m = eval_eta(ndg, nds, 50.0, 20.0)
        rows.append(dict(attack=a, method="committed_50_20", uses_labels=0,
                         eta_g=50.0, eta_s=20.0, AUC=A, EER=E, **m))

        # benign-only quantile calibration on [60k:100k]
        for t in FPR_TARGETS:
            eg, es, cf = calib_q(ndg[CALIB], nds[CALIB], t)
            m = eval_eta(ndg, nds, eg, es)
            rows.append(dict(attack=a, method=f"benign_calib@{int(t*100)}%",
                             uses_labels=0, eta_g=eg, eta_s=es, AUC=A, EER=E, **m))

        # diagnostic FPR breakdown at committed 50/20 across the test benign sub-windows
        def wf(sl):
            return float(np.mean((ndg[sl] > 50.0) | (nds[sl] > 20.0)))
        diag.append(dict(attack=a,
                         fpr_test_all=wf(TEST_BEN), fpr_calm_100_140=wf(CALM_A),
                         fpr_burst_140_160=wf(BURST), fpr_calm_160_180=wf(CALM_B)))

    fields = ["attack", "method", "uses_labels", "eta_g", "eta_s",
              "TPR", "FPR", "Precision", "F1", "Accuracy", "AUC", "EER",
              "tp", "fp", "fn", "tn"]
    with open(f"{OUT}/ciciot2023_cleansplit_metrics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields + ["n_benign_test", "n_attack"])
        w.writeheader()
        for r in rows:
            r["n_benign_test"] = N_TEST_BEN; r["n_attack"] = N_ATK
            w.writerow({k: (f"{r[k]:.6f}" if isinstance(r.get(k), float) else r.get(k, ""))
                        for k in fields + ["n_benign_test", "n_attack"]})

    def line(vals, widths):
        return " ".join(str(v).ljust(w) if i < 2 else str(v).rjust(w)
                        for i, (v, w) in enumerate(zip(vals, widths)))
    hdr = ["attack", "method", "eta_g", "eta_s", "TPR", "FPR", "Prec", "F1", "Acc", "AUC", "EER"]
    W = [22, 17, 8, 7, 7, 7, 7, 7, 7, 7, 7]
    print("\n===== CLEAN SPLIT: calib benign [60k:100k]; TEST benign [100k:180k] (80k, burst incl.); attack 50k =====")
    print(line(hdr, W))
    for r in rows:
        print(line([r["attack"], r["method"], f"{r['eta_g']:.2f}", f"{r['eta_s']:.2f}",
                    f"{r['TPR']:.4f}", f"{r['FPR']:.4f}", f"{r['Precision']:.4f}",
                    f"{r['F1']:.4f}", f"{r['Accuracy']:.4f}", f"{r['AUC']:.4f}", f"{r['EER']:.4f}"], W))

    print("\n===== MEAN over 6 attacks by method =====")
    methods = ["committed_50_20", "benign_calib@1%", "benign_calib@5%"]
    print(line(["method", "", "", "", "TPR", "FPR", "Prec", "F1", "Acc", "AUC", "EER"], W))
    for mth in methods:
        sub = [r for r in rows if r["method"] == mth]
        avg = lambda k: sum(r[k] for r in sub) / len(sub)
        print(line([mth, "", "", "", f"{avg('TPR'):.4f}", f"{avg('FPR'):.4f}", f"{avg('Precision'):.4f}",
                    f"{avg('F1'):.4f}", f"{avg('Accuracy'):.4f}", f"{avg('AUC'):.4f}", f"{avg('EER'):.4f}"], W))

    print("\n===== DIAGNOSTIC: committed 50/20 FPR across test-benign sub-windows =====")
    dh = ["attack", "all[100-180k]", "calm[100-140k]", "burst[140-160k]", "calm[160-180k]"]
    DW = [22, 14, 15, 16, 15]
    print(line(dh, DW))
    for d in diag:
        print(line([d["attack"], f"{d['fpr_test_all']:.4f}", f"{d['fpr_calm_100_140']:.4f}",
                    f"{d['fpr_burst_140_160']:.4f}", f"{d['fpr_calm_160_180']:.4f}"], DW))
    print(f"\nWrote {OUT}/ciciot2023_cleansplit_metrics.csv")


if __name__ == "__main__":
    main()
