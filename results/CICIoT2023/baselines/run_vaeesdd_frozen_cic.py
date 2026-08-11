"""
Frozen-after-benign VAEESDD VAE on CICIoT2023 streams.

Protocol matches Tenko/Kitsune (no unsupervised updates on attack traffic):
  - MinMaxScaler fit on X[:benignLimit] (all benign)
  - Train one VAE on that benign train region only
  - Threshold = 95th percentile of train reconstruction+KL scores
  - Score / predict on test region [benignLimit:] with the frozen model

Outputs overwrite results/CICIoT2023/baselines/vaeesdd/vaeesdd_<stream>.npz
(the previous streaming-baseline npzs are moved to vaeesdd/streaming_baseline/).

Run outside the tool sandbox (TF segfaults under it):
  .venv_vae/bin/python results/CICIoT2023/baselines/run_vaeesdd_frozen_cic.py --all
"""
import os
import sys
import shutil
import argparse
import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
VAE_DIR = os.path.join(REPO_ROOT, "external", "VAEESDD-upstream")
FEAT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "features")
OUT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "vaeesdd")
ARCHIVE_DIR = os.path.join(OUT_DIR, "streaming_baseline")

sys.path.insert(0, VAE_DIR)
os.chdir(VAE_DIR)

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")

from sklearn.preprocessing import MinMaxScaler  # noqa: E402
from sklearn.metrics import (roc_auc_score, average_precision_score, f1_score,  # noqa: E402
                             precision_score, recall_score)
from class_nn_ae_variational import VAE  # noqa: E402
from aux_loss_functions import calc_reconstruction_loss_vec, calc_kl_loss_vec  # noqa: E402
import tensorflow as tf  # noqa: E402

BENIGN_LIMIT = 60000
NUM_EPOCHS = 50
BATCH_SIZE = 256
SCORE_BATCH = 4096
THR_PERCENTILE = 95.0
BETA = 1.0
SEED = 7654

STREAMS = ["mixed", "indep_DDoS-UDP_Flood", "indep_DoS-SYN_Flood",
           "indep_Recon-OSScan", "indep_MITM-ArpSpoofing",
           "indep_Mirai-greeth_flood", "indep_DictionaryBruteForce"]


def archive_old_streaming():
    """Keep previous streaming-baseline npzs so we don't lose them."""
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    for name in STREAMS:
        src = os.path.join(OUT_DIR, f"vaeesdd_{name}.npz")
        dst = os.path.join(ARCHIVE_DIR, f"vaeesdd_{name}.npz")
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.move(src, dst)
            print(f"  archived streaming baseline -> {dst}")


def make_vae(n_features):
    return VAE(layer_dims=[n_features, 64, 32],
               learning_rate=0.0001,
               loss_function="square_error",
               num_epochs=NUM_EPOCHS,
               batch_size=64,
               beta=BETA,
               dropout_rate=0.0,
               seed=SEED)


def vae_scores(vae, X, batch_size=SCORE_BATCH):
    """Per-row VAE loss = reconstruction + beta*KL, batched."""
    scores = np.empty(len(X), dtype=np.float64)
    for i in range(0, len(X), batch_size):
        xb = X[i:i + batch_size]
        z_mean, z_log_var, recon = vae.prediction(xb)
        ae = calc_reconstruction_loss_vec(xb, recon, vae.loss_function_name)
        kl = calc_kl_loss_vec(z_log_var, z_mean, vae.beta)
        ae = tf.cast(ae, tf.float64)
        kl = tf.cast(kl, tf.float64)
        total = (ae + kl).numpy()
        scores[i:i + batch_size] = np.asarray(total, dtype=np.float64).reshape(-1)
    return np.nan_to_num(scores, nan=0.0, posinf=1e12, neginf=0.0)


def fpr_at(y, score, target_fpr=0.01):
    benign, attack = score[y == 0], score[y == 1]
    if len(benign) == 0 or len(attack) == 0:
        return float("nan"), float("nan")
    thr = np.quantile(benign, 1.0 - target_fpr)
    return float((attack > thr).mean()), float((benign > thr).mean())


def run_stream(name):
    X = np.load(os.path.join(FEAT_DIR, f"X_{name}.npy"))
    y = np.load(os.path.join(FEAT_DIR, f"y_{name}.npy")).astype(int)
    assert y[:BENIGN_LIMIT].sum() == 0, f"{name}: train region must be all benign"
    print(f"\n{'='*70}\n[VAE frozen] {name}: X{X.shape} pos={int(y.sum())}\n{'='*70}")

    scaler = MinMaxScaler().fit(X[:BENIGN_LIMIT])
    Xs = scaler.transform(X).astype(np.float32)
    x_train = Xs[:BENIGN_LIMIT]
    x_test = Xs[BENIGN_LIMIT:]
    y_test = y[BENIGN_LIMIT:]

    tf.keras.backend.clear_session()
    np.random.seed(SEED)
    tf.random.set_seed(SEED)
    vae = make_vae(x_train.shape[1])
    print(f"  training VAE on {len(x_train)} benign packets ({NUM_EPOCHS} epochs)...")
    vae.train(data=x_train, verbose=0)

    train_scores = vae_scores(vae, x_train)
    thr = float(np.percentile(train_scores, THR_PERCENTILE))
    print(f"  train-score p{THR_PERCENTILE:.0f} threshold = {thr:.6f}")

    test_scores = vae_scores(vae, x_test)
    preds = (test_scores > thr).astype(int)

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"vaeesdd_{name}.npz")
    np.savez(out, y_test=y_test, scores=test_scores, preds=preds,
             threshold=np.array([thr]), protocol="frozen_after_benign")
    print(f"  saved {out}")

    roc = roc_auc_score(y_test, test_scores)
    prauc = average_precision_score(y_test, test_scores)
    f1 = f1_score(y_test, preds, zero_division=0)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    tpr = float(preds[y_test == 1].mean()) if (y_test == 1).any() else float("nan")
    fpr = float(preds[y_test == 0].mean()) if (y_test == 0).any() else float("nan")
    tpr1, _ = fpr_at(y_test, test_scores, 0.01)
    print(f"[{name}] ROC-AUC={roc:.4f} PR-AUC={prauc:.4f} Acc="
          f"{((preds == y_test).mean()):.4f} F1={f1:.4f} P={prec:.4f} "
          f"TPR={tpr:.4f} FPR={fpr:.4f} TPR@1%FPR={tpr1:.4f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stream", default=None)
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    archive_old_streaming()
    targets = STREAMS if a.all else [a.stream]
    for s in targets:
        run_stream(s)


if __name__ == "__main__":
    main()
