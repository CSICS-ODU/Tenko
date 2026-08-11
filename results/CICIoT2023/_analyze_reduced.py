#!/usr/bin/env python3
"""Offline analysis for the single-tanh + reduced-split experiment (no re-run).

Consumes arr_{gold,ndg,nds}_<attack>_s60k.npy produced by _rerun_reduced.py.
nd_g/nd_s are eta-independent; fused binary rule (wg=ws=.5, T=.5) = OR:
  pred = (nd_g > eta_g) | (nd_s > eta_s)

Reduced split test-array indices (stream idx = 60000 + test_idx):
  calib benign  : [0     : 5000 ]   (stream 60000..64999)  -> eta selection
  eval  benign  : [5000  : 64000]   (stream 65000..123999) -> FPR negatives (59000)
  extra benign  : [64000 : 120000]  (stream 124000..179999) robustness only
  attack        : [120000: 170000]  (stream 180000..229999) TPR positives (50000)
"""
from __future__ import annotations
import csv, numpy as np

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
N_CALIB, N_EVAL, N_EXTRA, N_ATK = 5000, 59000, 56000, 50000
CALIB = slice(0, 5000)
EVAL = slice(5000, 64000)
EXTRA = slice(64000, 120000)
ATK = slice(120000, 170000)
FPR_TARGETS = [0.01, 0.05]


def load(a):
    g = np.load(f"{OUT}/arr_gold_{a}_s60k.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{a}_s60k.npy")
    nds = np.load(f"{OUT}/arr_nds_{a}_s60k.npy")
    assert len(g) == 170000, f"{a}: len {len(g)}"
    assert g[CALIB].sum() == 0 and g[EVAL].sum() == 0 and g[EXTRA].sum() == 0
    assert g[ATK].sum() == N_ATK
    return g, ndg, nds


def counts_metrics(atk_flag, ben_flag):
    """atk_flag: bool preds on attack region; ben_flag: bool preds on benign eval."""
    tp = int(atk_flag.sum()); fn = int((~atk_flag).sum())
    fp = int(ben_flag.sum()); tn = int((~ben_flag).sum())
    tpr = tp / (tp + fn) if (tp + fn) else float('nan')
    fpr = fp / (fp + tn) if (fp + tn) else float('nan')
    prec = tp / (tp + fp) if (tp + fp) else float('nan')
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float('nan')
    acc = (tp + tn) / (tp + tn + fp + fn)
    return dict(TPR=tpr, FPR=fpr, Precision=prec, F1=f1, Accuracy=acc,
                tp=tp, fp=fp, fn=fn, tn=tn)


def eval_eta(ndg, nds, eta_g, eta_s):
    atk_flag = (ndg[ATK] > eta_g) | (nds[ATK] > eta_s)
    ben_flag = (ndg[EVAL] > eta_g) | (nds[EVAL] > eta_s)
    m = counts_metrics(atk_flag, ben_flag)
    m["eta_g"] = eta_g; m["eta_s"] = eta_s
    return m


def calibrate_shared_q(cndg, cnds, target):
    """Shared benign quantile q on CALIB s.t. fused OR calib-FPR ~= target (<=)."""
    qs = np.concatenate([np.linspace(0.50, 0.90, 41), np.linspace(0.9001, 0.99999, 1200)])
    best = None
    for q in qs:
        eg = float(np.quantile(cndg, q)); es = float(np.quantile(cnds, q))
        fpr = float(np.mean((cndg > eg) | (cnds > es)))
        over = 0 if fpr <= target + 1e-9 else 1
        key = (over, abs(fpr - target))
        if best is None or key < best[0]:
            best = (key, q, eg, es, fpr)
    return best[1], best[2], best[3], best[4]  # q, eta_g, eta_s, calib_fpr


def grid_oracle(ndg, nds, criterion="f1"):
    """ORACLE: sweep eta over pooled test quantiles, pick best by criterion on
    EVAL benign + ATTACK (USES ATTACK LABELS -> supervised upper bound)."""
    pool_g = np.concatenate([ndg[EVAL], ndg[ATK]])
    pool_s = np.concatenate([nds[EVAL], nds[ATK]])
    cand_g = np.unique(np.quantile(pool_g, np.linspace(0.0, 1.0, 121)))
    cand_s = np.unique(np.quantile(pool_s, np.linspace(0.0, 1.0, 121)))
    best = None
    for eg in cand_g:
        atk_g = ndg[ATK] > eg; ben_g = ndg[EVAL] > eg
        for es in cand_s:
            atk_flag = atk_g | (nds[ATK] > es)
            ben_flag = ben_g | (nds[EVAL] > es)
            m = counts_metrics(atk_flag, ben_flag)
            if criterion == "f1":
                score = m["F1"]
            else:  # youden J = TPR - FPR
                score = m["TPR"] - m["FPR"]
            if best is None or (not np.isnan(score) and score > best[0]):
                best = (score, eg, es, m)
    return best[1], best[2], best[3]  # eta_g, eta_s, metrics


def main():
    rows = []                # final CSV rows
    calib_eta = {}           # per attack calibrated etas
    nd_summary = []
    transfer = []
    for a in ATTACKS:
        g, ndg, nds = load(a)
        b_all = ndg[g == 0]; a_all = ndg[g == 1]
        bs_all = nds[g == 0]; as_all = nds[g == 1]
        nd_summary.append(dict(attack=a,
            ndg_benign_p50=np.median(b_all), ndg_benign_p99=np.percentile(b_all,99),
            ndg_benign_max=b_all.max(), ndg_attack_p50=np.median(a_all),
            ndg_attack_p99=np.percentile(a_all,99), ndg_attack_max=a_all.max(),
            nds_benign_max=bs_all.max(), nds_attack_max=as_all.max()))

        # ---- (a0) fixed committed eta=50/20 (no attack labels; coincidentally rescaled) ----
        m = eval_eta(ndg, nds, 50.0, 20.0)
        rows.append(dict(attack=a, method="committed_eta_50_20", uses_attack_labels=0,
            eta_g=50.0, eta_s=20.0, calib_fpr=float(np.mean((ndg[CALIB]>50.0)|(nds[CALIB]>20.0))),
            **{k: m[k] for k in ("TPR","FPR","Precision","F1","Accuracy","tp","fp","fn","tn")}))

        # ---- (a) benign-only calibration (HONEST; calib slice only) ----
        for t in FPR_TARGETS:
            q, eg, es, cfpr = calibrate_shared_q(ndg[CALIB], nds[CALIB], t)
            m = eval_eta(ndg, nds, eg, es)
            calib_eta[(a, t)] = (eg, es)
            rows.append(dict(attack=a, method=f"benign_calib@{int(t*100)}%",
                uses_attack_labels=0, eta_g=eg, eta_s=es, calib_fpr=cfpr,
                **{k: m[k] for k in ("TPR","FPR","Precision","F1","Accuracy","tp","fp","fn","tn")}))

        # ---- (b) grid-search ORACLE (uses attack labels) ----
        for crit, name in (("f1", "gridsearch_ORACLE_maxF1"), ("j", "gridsearch_ORACLE_youdenJ")):
            eg, es, m = grid_oracle(ndg, nds, crit)
            rows.append(dict(attack=a, method=name, uses_attack_labels=1,
                eta_g=eg, eta_s=es, calib_fpr=float('nan'),
                **{k: m[k] for k in ("TPR","FPR","Precision","F1","Accuracy","tp","fp","fn","tn")}))

        # ---- transfer: eta from calib@1% applied to disjoint benign windows ----
        eg1, es1 = calib_eta[(a, 0.01)]
        eg5, es5 = calib_eta[(a, 0.05)]
        def wfpr(sl, eg, es):
            return float(np.mean((ndg[sl] > eg) | (nds[sl] > es)))
        transfer.append(dict(attack=a,
            fpr_calib_1=wfpr(CALIB, eg1, es1), fpr_eval_1=wfpr(EVAL, eg1, es1),
            fpr_extra_1=wfpr(EXTRA, eg1, es1),
            fpr_calib_5=wfpr(CALIB, eg5, es5), fpr_eval_5=wfpr(EVAL, eg5, es5),
            fpr_extra_5=wfpr(EXTRA, eg5, es5)))

    # ---------- write final metrics CSV ----------
    fields = ["attack","method","uses_attack_labels","eta_g","eta_s","calib_fpr",
              "TPR","FPR","Precision","F1","Accuracy","tp","fp","fn","tn",
              "n_benign_eval","n_attack"]
    with open(f"{OUT}/ciciot2023_singletanh_gridsearch_metrics.csv","w",newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows:
            r["n_benign_eval"] = N_EVAL; r["n_attack"] = N_ATK
            w.writerow({k: r.get(k,"") for k in fields})

    # ---------- console report ----------
    import pandas as pd
    df = pd.DataFrame(rows)
    pd.set_option("display.width", 200); pd.set_option("display.max_columns", 30)
    print("\n================ ND RANGES (reduced split, single-tanh, benignLimit=60000) ================")
    print(pd.DataFrame(nd_summary).to_string(index=False, float_format=lambda x: f"{x:.3f}"))
    print("\n================ FINAL METRICS (eval benign=59000, attack=50000) ================")
    show = ["attack","method","uses_attack_labels","eta_g","eta_s","TPR","FPR","Precision","F1","Accuracy"]
    print(df[show].to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    print("\n================ FPR TRANSFER (eta from calib slice -> disjoint benign windows) ================")
    print(pd.DataFrame(transfer).to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    # means per method
    print("\n================ MEAN over 6 attacks by method ================")
    mean = df.groupby("method").agg(
        uses_labels=("uses_attack_labels","first"),
        TPR=("TPR","mean"), FPR=("FPR","mean"), Precision=("Precision","mean"),
        F1=("F1","mean"), Accuracy=("Accuracy","mean")).reset_index()
    print(mean.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    df.to_pickle(f"{OUT}/_reduced_rows.pkl")
    pd.DataFrame(transfer).to_pickle(f"{OUT}/_reduced_transfer.pkl")
    pd.DataFrame(nd_summary).to_pickle(f"{OUT}/_reduced_ndsummary.pkl")


if __name__ == "__main__":
    main()
