"""
Run VAEESDD (Jin000001/VAEESDD) on the CICIoT2023 streams using its own
streaming VAE detector, on the same 100-dim AfterImage/Kitsune features.

Per the requested scope we run the plain VAE *baseline* strategy (strategy=
'baseline', method='vae'): a variational autoencoder trained on a sliding
window of the (unlabelled) stream and periodically re-trained, producing a
per-packet reconstruction+KL anomaly score. This is VAEESDD's base detector
without the two-level ensembling / drift-detector voting.

The upstream repo ships without its data/ loaders; instead of using their
main.py dataset plumbing we construct the streaming environment directly and
call their unmodified main_exp.run(). We stream the whole stream (as the method
is designed for) and report metrics on Tenko's test region [benignLimit:].

Because TensorFlow segfaults under the tool sandbox, run this OUTSIDE the
sandbox with the TF env:
    .venv_vae/bin/python results/CICIoT2023/baselines/run_vaeesdd_cic.py --stream indep_DoS-SYN_Flood
    .venv_vae/bin/python results/CICIoT2023/baselines/run_vaeesdd_cic.py --all
"""
import os
import sys
import argparse
import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
VAE_DIR = os.path.join(REPO_ROOT, "external", "VAEESDD-upstream")
FEAT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "features")
OUT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "vaeesdd")

sys.path.insert(0, VAE_DIR)
# main_exp.run() writes a small metric file under ./exps/
os.makedirs(os.path.join(VAE_DIR, "exps"), exist_ok=True)
os.chdir(VAE_DIR)

from sklearn.preprocessing import MinMaxScaler  # noqa: E402
from sklearn.metrics import (roc_auc_score, average_precision_score, f1_score,  # noqa: E402
                             precision_score, recall_score)
from class_nn_ae_variational import VAE  # noqa: E402
import main_exp  # noqa: E402

BENIGN_LIMIT = 60000

STREAMS = ["mixed", "indep_DDoS-UDP_Flood", "indep_DoS-SYN_Flood",
           "indep_Recon-OSScan", "indep_MITM-ArpSpoofing",
           "indep_Mirai-greeth_flood", "indep_DictionaryBruteForce"]

# streaming baseline hyper-parameters (sized for a large NIDS stream on CPU)
WIN = 2000            # unsupervised/drift window
MOV_WIN = 2000        # training window
NUM_EPOCHS = 20       # VAE epochs per (re)train
BETA = 1.0
LAYER_DIMS = [None, 64, 32]  # filled with num_features


def make_vae(d_env):
    dims = [d_env["num_features"], 64, 32]
    return VAE(layer_dims=dims, learning_rate=0.0001,
               loss_function="square_error", num_epochs=d_env["num_epochs"],
               batch_size=64, beta=d_env["beta"], dropout_rate=0.0,
               seed=d_env["seed"])


def build_params(name, X, y):
    scaler = MinMaxScaler().fit(X[:BENIGN_LIMIT])
    Xs = scaler.transform(X).astype(np.float32)
    y = y.astype(np.float32).reshape(-1, 1)
    data_arr = np.hstack([Xs, y]).astype(np.float32)

    p = {
        "data_source": f"cic_{name}",      # no 'drift'/'mnist' substrings
        "strategy": "baseline",
        "method": "vae",
        "unsupervised_win_size": WIN,
        "mov_win_size": MOV_WIN,
        "ae_threshold_percentile": 95,
        "unsupervised_win_size_update": 1.0,
        "beta": BETA,
        "noise_gaussian_avg": 0, "noise_gaussian_std": 0,
        "lamda": 0, "reg_l1": 0,
        "Pthre": 2, "Dthre": "nodd", "incr": "yes",
        "Esnum": 1, "palarm": 0.001, "index": "esdd",
        "adaptive": "yes", "num_epochs": NUM_EPOCHS, "lr": 0.0001,
        "seed": 7654,
        "random_state": np.random.RandomState(7654),
        "preq_fading_factor": 0.99,
        "unsupervised_flag_incremental": True,
        "num_features": Xs.shape[1],
        "time_steps": data_arr.shape[0],
        "num_classes": int(len(np.unique(y))),
        "data_arr": data_arr,
        "data_init_unlabelled": Xs[:MOV_WIN],
        "data_init_unlabelled_first": Xs[:2000],
        "t_drift": int(data_arr.shape[0]),   # int -> no drift-reset path
        "fun_create_vae": make_vae,
        "fun_create_ae": make_vae,
    }
    p["update_time"] = int(p["unsupervised_win_size"] * p["unsupervised_win_size_update"])
    return p


def fpr_at(y, score, target_fpr=0.01):
    benign, attack = score[y == 0], score[y == 1]
    if len(benign) == 0 or len(attack) == 0:
        return float("nan"), float("nan")
    thr = np.quantile(benign, 1.0 - target_fpr)
    return float((attack > thr).mean()), float((benign > thr).mean())


def run_stream(name):
    X = np.load(os.path.join(FEAT_DIR, f"X_{name}.npy"))
    y = np.load(os.path.join(FEAT_DIR, f"y_{name}.npy")).astype(int)
    print(f"\n{'='*70}\n[VAEESDD baseline] {name}: X{X.shape} pos={int(y.sum())}\n{'='*70}")

    params = build_params(name, X, y)
    out = main_exp.run(params)
    pred_list, score_list = out[-2], out[-1]

    preds = np.asarray(pred_list).astype(int)
    scores = np.nan_to_num(np.asarray(score_list, dtype=np.float64),
                           nan=0.0, posinf=0.0, neginf=0.0)

    # Evaluate on Tenko's test region only, for a comparable table.
    yt = y[BENIGN_LIMIT:]
    st = scores[BENIGN_LIMIT:]
    pt = preds[BENIGN_LIMIT:]

    os.makedirs(OUT_DIR, exist_ok=True)
    np.savez(os.path.join(OUT_DIR, f"vaeesdd_{name}.npz"),
             y_test=yt, scores=st, preds=pt,
             scores_full=scores, preds_full=preds, y_full=y)

    roc = roc_auc_score(yt, st)
    prauc = average_precision_score(yt, st)
    f1 = f1_score(yt, pt, zero_division=0)
    prec = precision_score(yt, pt, zero_division=0)
    rec = recall_score(yt, pt, zero_division=0)
    tpr1, fpr1 = fpr_at(yt, st, 0.01)
    print(f"[{name}] ROC-AUC={roc:.4f} PR-AUC={prauc:.4f} F1={f1:.4f} "
          f"P={prec:.4f} R={rec:.4f} TPR@1%FPR={tpr1:.4f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stream", default=None)
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    targets = STREAMS if a.all else [a.stream]
    for s in targets:
        run_stream(s)


if __name__ == "__main__":
    main()
