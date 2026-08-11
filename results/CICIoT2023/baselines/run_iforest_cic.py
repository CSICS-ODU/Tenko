"""
Run sklearn Isolation Forest on CICIoT2023 streams using the detection recipe
from Ramkumar et al. "Diagnosing Unknown Attacks in Smart Homes Using Abductive
Reasoning" (IEEE TSE 2025 / more-than-zero):

  - IsolationForest(random_state=42)  # sklearn defaults otherwise
  - train on benign-only data
  - anomaly score = decision_function (higher => more normal)
  - paper binary rule: Z-score of scores, flag if z < 0

Adapted to Tenko's fair-comparison protocol:
  - input = shared 100-dim AfterImage/Kitsune features
  - train = X[:60000] (all benign); evaluate on X[60000:]
  - comparison scores = -decision_function (higher => more anomalous),
    matching Mateen/VAEESDD/Tenko score polarity

NOTE: This is the paper's *detection* algorithm (named sklearn IsolationForest),
not a reimplementation of their ASP abductive diagnosis pipeline. Diagnosis
requires Clingo + smart-home contextual ASP encodings (see
external/more-than-zero/diagnosis/) and is not applied here.

Usage:
    .venv/bin/python results/CICIoT2023/baselines/run_iforest_cic.py --stream mixed
    .venv/bin/python results/CICIoT2023/baselines/run_iforest_cic.py --all
"""
import os
import argparse
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (roc_auc_score, average_precision_score, f1_score,
                             precision_score, recall_score)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
FEAT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "features")
OUT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "iforest")

BENIGN_LIMIT = 60000

STREAMS = ["mixed", "indep_DDoS-UDP_Flood", "indep_DoS-SYN_Flood",
           "indep_Recon-OSScan", "indep_MITM-ArpSpoofing",
           "indep_Mirai-greeth_flood", "indep_DictionaryBruteForce"]


def fpr_at(y, score, target_fpr=0.01):
    benign = score[y == 0]
    attack = score[y == 1]
    if len(benign) == 0 or len(attack) == 0:
        return float("nan"), float("nan")
    thr = np.quantile(benign, 1.0 - target_fpr)
    tpr = float((attack > thr).mean())
    fpr = float((benign > thr).mean())
    return tpr, fpr


def paper_zscore_preds(decision_scores):
    """Ramkumar et al. detect_anomaly_z_score: z = (s-mean)/std; anomaly if z < 0."""
    mu = np.mean(decision_scores)
    sigma = np.std(decision_scores)
    if sigma == 0:
        return np.zeros(len(decision_scores), dtype=int)
    z = (decision_scores - mu) / sigma
    return (z < 0).astype(int)  # True in paper = anomaly


def run_stream(name):
    os.makedirs(OUT_DIR, exist_ok=True)
    X = np.load(os.path.join(FEAT_DIR, f"X_{name}.npy"))
    y = np.load(os.path.join(FEAT_DIR, f"y_{name}.npy")).astype(int)
    print(f"\n{'='*70}\n[{name}] X{X.shape} pos={int(y.sum())}\n{'='*70}")

    x_train, y_train = X[:BENIGN_LIMIT], y[:BENIGN_LIMIT]
    x_test, y_test = X[BENIGN_LIMIT:], y[BENIGN_LIMIT:]
    assert y_train.sum() == 0, f"{name}: training region must be all benign"

    # Paper: IsolationForest(random_state=42), fit on benign, decision_function
    model = IsolationForest(random_state=42, n_jobs=-1)
    model.fit(x_train)

    decision = model.decision_function(x_test)  # higher = more normal
    scores = (-decision).astype(np.float64)     # higher = more anomalous (Tenko polarity)
    preds_z = paper_zscore_preds(decision)

    np.savez(os.path.join(OUT_DIR, f"iforest_{name}.npz"),
             y_test=y_test, scores=scores, decision=decision, preds_zscore=preds_z)

    roc = roc_auc_score(y_test, scores)
    prauc = average_precision_score(y_test, scores)
    # best-F1 over score thresholds (fair comparator)
    from sklearn.metrics import precision_recall_curve
    prec_c, rec_c, _ = precision_recall_curve(y_test, scores)
    f1s = 2 * prec_c * rec_c / (prec_c + rec_c + 1e-12)
    f1_best = float(np.nanmax(f1s))
    # paper operating point (Z-score on decision_function)
    f1_z = f1_score(y_test, preds_z, zero_division=0)
    p_z = precision_score(y_test, preds_z, zero_division=0)
    r_z = recall_score(y_test, preds_z, zero_division=0)
    tpr1, _ = fpr_at(y_test, scores, 0.01)

    print(f"[{name}] ROC-AUC={roc:.4f} PR-AUC={prauc:.4f} f1_best={f1_best:.4f} "
          f"TPR@1%FPR={tpr1:.4f}")
    print(f"[{name}] paper Z-score OP: P={p_z:.4f} R={r_z:.4f} F1={f1_z:.4f}")
    return dict(stream=name, roc_auc=roc, pr_auc=prauc, f1_best=f1_best,
                tpr_at_1fpr=tpr1, f1_zscore=f1_z, prec_zscore=p_z, rec_zscore=r_z)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stream", default=None)
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    if not a.all and not a.stream:
        ap.error("pass --stream NAME or --all")
    targets = STREAMS if a.all else [a.stream]
    rows = []
    for s in targets:
        rows.append(run_stream(s))
    print("\n==== IsolationForest (Ramkumar/more-than-zero recipe) summary ====")
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
