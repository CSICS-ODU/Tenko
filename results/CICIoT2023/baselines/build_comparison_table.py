"""
Build ONE comparison table: Tenko vs Kitsune vs Mateen vs VAEESDD, on the
CICIoT2023 mixed stream and the 6 independent attack streams.

All methods are scored on the SAME test region (Tenko's benignLimit=60000 split)
and the SAME gold labels, using per-packet anomaly scores:
    Tenko    -> arr_cont_*            (fused pattern-distance score)
    Kitsune  -> arr_kitsune_* / kitsune_testscores_mixed
    Mateen   -> baselines/mateen/mateen_<name>.npz['scores']   (AE RMSE)
    VAEESDD  -> baselines/vaeesdd/vaeesdd_<name>.npz['scores']  (VAE loss)

Threshold-free metrics (ROC-AUC, PR-AUC) come straight from the scores.
Operating-point metrics (F1/Precision/Recall) are reported at a common
criterion: the threshold on benign test scores giving 1% FPR, so every method
is compared at the same false-positive rate. Best-achievable F1 (over all
thresholds) is also reported.

Run with the base env:
    .venv/bin/python results/CICIoT2023/baselines/build_comparison_table.py
"""
import os
import numpy as np
import pandas as pd
from sklearn.metrics import (roc_auc_score, average_precision_score,
                             precision_recall_curve, f1_score,
                             precision_score, recall_score)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CIC = os.path.join(ROOT, "results", "CICIoT2023")
MATEEN_DIR = os.path.join(CIC, "baselines", "mateen")
VAE_DIR = os.path.join(CIC, "baselines", "vaeesdd")
OUT_CSV = os.path.join(CIC, "baselines", "comparison_metrics.csv")

ATTACKS = ["DDoS-UDP_Flood", "DoS-SYN_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
# display name -> (stream key used for Mateen/VAE npz)
STREAMS = [("mixed", "mixed")] + [(a, f"indep_{a}") for a in ATTACKS]


def _load(path):
    return np.load(path) if os.path.exists(path) else None


def tenko_scores(display):
    if display == "mixed":
        g = _load(os.path.join(CIC, "mixed", "arr_gold_mixed.npy"))
        s = _load(os.path.join(CIC, "mixed", "arr_cont_mixed.npy"))
    else:
        g = _load(os.path.join(CIC, "indep", f"arr_gold_{display}_indep.npy"))
        s = _load(os.path.join(CIC, "indep", f"arr_cont_{display}_indep.npy"))
    return g, s


def kitsune_scores(display):
    if display == "mixed":
        g = _load(os.path.join(CIC, "mixed", "arr_gold_mixed.npy"))
        s = _load(os.path.join(CIC, "mixed", "kitsune_testscores_mixed.npy"))
    else:
        g = _load(os.path.join(CIC, "indep", f"arr_gold_{display}_indep.npy"))
        s = _load(os.path.join(CIC, "indep", f"arr_kitsune_{display}_indep.npy"))
    return g, s


def npz_scores(path):
    if not os.path.exists(path):
        return None, None
    d = np.load(path)
    return d["y_test"].astype(int), d["scores"].astype(float)


def metrics(y, s):
    y = np.asarray(y).astype(int)
    s = np.nan_to_num(np.asarray(s, dtype=float))
    n = min(len(y), len(s))
    y, s = y[:n], s[:n]
    out = {"n_test": n, "n_attack": int(y.sum())}
    if len(np.unique(y)) < 2:
        return {**out, "roc_auc": np.nan, "pr_auc": np.nan,
                "f1_best": np.nan, "f1_at_1fpr": np.nan,
                "tpr_at_1fpr": np.nan, "prec_at_1fpr": np.nan}
    out["roc_auc"] = roc_auc_score(y, s)
    out["pr_auc"] = average_precision_score(y, s)
    # best-F1 over PR curve
    prec, rec, thr = precision_recall_curve(y, s)
    f1s = 2 * prec * rec / (prec + rec + 1e-12)
    out["f1_best"] = float(np.nanmax(f1s))
    # common operating point: 1% FPR on benign test scores
    benign, attack = s[y == 0], s[y == 1]
    t = np.quantile(benign, 0.99)
    pred = (s > t).astype(int)
    out["tpr_at_1fpr"] = float((attack > t).mean())
    out["prec_at_1fpr"] = precision_score(y, pred, zero_division=0)
    out["f1_at_1fpr"] = f1_score(y, pred, zero_division=0)
    return out


def main():
    rows = []
    for display, key in STREAMS:
        sources = {
            "Tenko": tenko_scores(display),
            "Kitsune": kitsune_scores(display),
            "Mateen": npz_scores(os.path.join(MATEEN_DIR, f"mateen_{key}.npz")),
            "VAEESDD": npz_scores(os.path.join(VAE_DIR, f"vaeesdd_{key}.npz")),
        }
        for method, (g, s) in sources.items():
            if g is None or s is None:
                print(f"[skip] {display}/{method}: missing arrays")
                continue
            m = metrics(g, s)
            rows.append({"stream": display, "method": method, **m})

    df = pd.DataFrame(rows)
    if df.empty:
        print("No results yet.")
        return
    df.to_csv(OUT_CSV, index=False)
    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 20)
    print(f"\nWrote {OUT_CSV}\n")

    for metric in ["roc_auc", "pr_auc", "f1_best", "tpr_at_1fpr"]:
        piv = df.pivot(index="stream", columns="method", values=metric)
        cols = [c for c in ["Tenko", "Kitsune", "Mateen", "VAEESDD"] if c in piv.columns]
        piv = piv[cols]
        print(f"\n===== {metric} =====")
        print(piv.round(4).to_string())


if __name__ == "__main__":
    main()
