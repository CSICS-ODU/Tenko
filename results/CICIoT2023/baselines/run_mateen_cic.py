"""
Run Mateen (ICL-ml4csec/Mateen) natively on the CICIoT2023 streams, using the
same 100-dim AfterImage/Kitsune features that Tenko's KitNET consumes.

Protocol (matches Tenko's benignLimit=60000 split):
    x_train = X[:60000]  (all benign)          -> Mateen initial + benign_train
    x_test  = X[60000:]  (benign_test+attack)  -> streamed in windows, adapted
Features are MinMax-scaled (fit on x_train) exactly as Mateen's prepare_data does.

Mateen is run "as it runs": adaptive_ensemble() with the repo's default
hyperparameters. Per-packet anomaly scores (RMSE) and binary predictions over
the test region are saved so a common metrics table can be built later.

Usage (torch env):
    .venv_mateen/bin/python results/CICIoT2023/baselines/run_mateen_cic.py --stream mixed
    .venv_mateen/bin/python results/CICIoT2023/baselines/run_mateen_cic.py --all
"""
import os
import sys
import argparse
import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MATEEN_UTILS = os.path.join(REPO_ROOT, "external", "Mateen-upstream", "MateenUtils")
sys.path.insert(0, MATEEN_UTILS)

import torch  # noqa: E402
from sklearn.preprocessing import MinMaxScaler  # noqa: E402
from sklearn.metrics import (roc_auc_score, average_precision_score, f1_score,  # noqa: E402
                             precision_score, recall_score)

import main as Mateen_main  # noqa: E402  (MateenUtils/main.py)
import data_processing as dp  # noqa: E402

# Mateen was written for torch 2.0 (torch.load weights_only=False default).
# torch >=2.6 flipped this default; the checkpoints we save this session hold a
# full AE object, so restore the old behaviour (trusted, self-produced files).
_orig_torch_load = torch.load
def _torch_load_compat(*a, **k):  # noqa: E306
    k.setdefault("weights_only", False)
    return _orig_torch_load(*a, **k)
torch.load = _torch_load_compat

FEAT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "features")
OUT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "mateen")

BENIGN_LIMIT = 60000
WINDOW_SIZE = 50000

STREAMS = ["mixed", "indep_DDoS-UDP_Flood", "indep_DoS-SYN_Flood",
           "indep_Recon-OSScan", "indep_MITM-ArpSpoofing",
           "indep_Mirai-greeth_flood", "indep_DictionaryBruteForce"]


def make_args(name):
    # Mateen repo defaults (README / Mateen.py argparse defaults).
    return type("args", (), {
        "dataset_name": name,
        "window_size": WINDOW_SIZE,
        "performance_thres": 0.99,
        "max_ensemble_length": 3,
        "selection_budget": 0.01,
        "mini_batch_size": 1000,
        "retention_rate": 0.3,
        "lambda_0": 0.1,
        "shift_threshold": 0.05,
    })()


def fpr_at(y, score, target_fpr=0.01):
    """Threshold picked on benign scores to hit target FPR; return TPR there."""
    benign = score[y == 0]
    attack = score[y == 1]
    if len(benign) == 0 or len(attack) == 0:
        return float("nan"), float("nan")
    thr = np.quantile(benign, 1.0 - target_fpr)
    tpr = float((attack > thr).mean())
    fpr = float((benign > thr).mean())
    return tpr, fpr


def run_stream(name):
    # Run inside the output dir so Mateen's relative Models/{scenario}.pth
    # (saved by us, loaded by adaptive_ensemble) resolves consistently.
    os.makedirs(OUT_DIR, exist_ok=True)
    os.chdir(OUT_DIR)
    X = np.load(os.path.join(FEAT_DIR, f"X_{name}.npy"))
    y = np.load(os.path.join(FEAT_DIR, f"y_{name}.npy")).astype(int)
    print(f"\n{'='*70}\n[{name}] X{X.shape} pos={int(y.sum())}\n{'='*70}")

    x_train, y_train = X[:BENIGN_LIMIT], y[:BENIGN_LIMIT]
    x_test, y_test = X[BENIGN_LIMIT:], y[BENIGN_LIMIT:]
    assert y_train.sum() == 0, f"{name}: training region must be all benign"

    scaler = MinMaxScaler().fit(x_train)
    x_train = scaler.transform(x_train).astype(np.float32)
    x_test = scaler.transform(x_test).astype(np.float32)

    args = make_args(name)
    x_slice, y_slice = dp.partition_array(x_data=x_test, y_data=y_test,
                                          slice_size=args.window_size)

    # Upstream adaptive_ensemble() loads a pre-trained checkpoint from
    # Models/{scenario}.pth (shipped via their Google Drive). Reproduce their
    # workflow by training the initial AE once and saving it, then let
    # adaptive_ensemble load + adapt it exactly as written.
    os.makedirs("Models", exist_ok=True)
    ckpt = f"Models/{name}.pth"
    if not os.path.exists(ckpt):
        print(f"[{name}] pre-training initial Mateen AE (100 epochs)...")
        init_model = Mateen_main.ensemble_training(
            x_train, y_train=y_train, num_epochs=100, mode="init",
            scenario=name, load_mode="new")
        torch.save(init_model, ckpt)
        print(f"[{name}] saved {ckpt}")

    predictions, probs = Mateen_main.adaptive_ensemble(
        x_train, y_train, x_slice, y_slice, args)

    predictions = np.asarray(predictions).astype(int)
    probs = np.asarray(probs, dtype=np.float64)
    y_test = np.asarray(y_test).astype(int)
    n = min(len(predictions), len(probs), len(y_test))
    predictions, probs, y_test = predictions[:n], probs[:n], y_test[:n]

    os.makedirs(OUT_DIR, exist_ok=True)
    np.savez(os.path.join(OUT_DIR, f"mateen_{name}.npz"),
             y_test=y_test, scores=probs, preds=predictions)

    roc = roc_auc_score(y_test, probs)
    prauc = average_precision_score(y_test, probs)
    f1 = f1_score(y_test, predictions)
    prec = precision_score(y_test, predictions, zero_division=0)
    rec = recall_score(y_test, predictions, zero_division=0)
    tpr1, fpr1 = fpr_at(y_test, probs, 0.01)
    print(f"[{name}] ROC-AUC={roc:.4f} PR-AUC={prauc:.4f} F1={f1:.4f} "
          f"P={prec:.4f} R={rec:.4f} TPR@1%FPR={tpr1:.4f}")
    return dict(stream=name, roc_auc=roc, pr_auc=prauc, f1=f1,
                precision=prec, recall=rec, tpr_at_1fpr=tpr1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stream", default=None)
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    targets = STREAMS if a.all else [a.stream]
    rows = []
    for s in targets:
        rows.append(run_stream(s))
    print("\n==== Mateen summary ====")
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
