#!/usr/bin/env python3
"""INDEPENDENT-benign-window CICIoT2023 driver for Tenko (X1-X4) vs Kitsune.

Each of the 6 attacks has its OWN distinct 120k benign window (built by
build_indep_streams.sh) merged with its 50k attack _sub. Stream = 170k packets.

  KitNET training (FM5k+AD50k) : stream [0     : 55000 ]
  Tenko pattern-model training : stream [55001 : 60000 ]   benignLimit=60000
  benign_test (FPR negatives)  : stream [60000 : 120000]   (60,000)
  attack (TPR positives)       : stream [120000: 170000]   (50,000)

TEST region = stream [60000:170000] (len 110000); test_idx = stream_idx - 60000.
  benign_test  -> test_idx [0     : 60000 ]
  attack       -> test_idx [60000 : 110000]
  calib half   -> test_idx [0     : 30000 ]  (stream 60k:90k) benign-only eta selection
  eval  half   -> test_idx [30000 : 60000 ]  (stream 90k:120k) benign-only eval negatives

Single-tanh reporting: feed RAW rmse into results.get_adversarial_IPs_weighted_pattern
so its internal tanh (results.py:805) is the ONLY normalization.

Self-contained + pandas-free label reading (results.build_label_list uses pandas;
we read the label CSV with the csv module instead). `import results` still pulls
pandas at module load, but that is available in the venv.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time

import numpy as np
from sklearn.metrics import roc_curve, auc as sk_auc

# Ensure the repo root is importable regardless of invocation cwd (Python puts
# the SCRIPT dir on sys.path[0], not the repo root).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))  # indep -> CICIoT2023 -> results -> Tenko
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from Kitsune import Kitsune
import results as R

# --- Fixed pipeline constants (match example.py / results.py) ---
MAXAE = 10
FMGRACE = 5000
ADGRACE = 50000
TRAIN_START_IDX = FMGRACE + ADGRACE + 1   # 55001, first benign calibration index
MAD_K = 3.0                               # Kitsune threshold = median + K*1.4826*MAD

BENIGN_LIMIT = 60000
N_BEN_TEST = 60000
N_ATK = 50000

INDEP = os.path.dirname(os.path.abspath(__file__))

ATTACKS = [
    "DDoS-UDP_Flood",
    "DoS-SYN_Flood",
    "Recon-OSScan",
    "MITM-ArpSpoofing",
    "Mirai-greeth_flood",
    "DictionaryBruteForce",
]

# test_idx regions
BEN_TEST = slice(0, N_BEN_TEST)             # negatives (committed OP)
ATK = slice(N_BEN_TEST, N_BEN_TEST + N_ATK)  # positives
CALIB = slice(0, 30000)                      # benign-only eta selection
EVAL = slice(30000, 60000)                   # benign-only eval negatives

COMMITTED_ETA_G = 50.0
COMMITTED_ETA_S = 20.0
FPR_TARGETS = [0.01, 0.05]


# ----------------------------------------------------------------------------
def read_labels(path: str) -> list[int]:
    """Pandas-free label reader (header line 'x', then 0/1 per packet)."""
    with open(path, "rt") as f:
        rdr = csv.reader(f)
        header = next(rdr)
        col = header.index("x") if "x" in header else 0
        return [int(row[col]) for row in rdr if row and row[col] != ""]


def load_provenance() -> dict[str, dict]:
    prov = {}
    with open(os.path.join(INDEP, "benign_window_provenance.csv")) as f:
        for row in csv.DictReader(f):
            prov[row["attack"]] = row
    return prov


def run_x1(tsv_path: str):
    """Stream TSV through KitNET; return raw RMSEs aligned 1:1 with packets."""
    K = Kitsune(tsv_path, np.inf, MAXAE, FMGRACE, ADGRACE)
    limit = K.packet_limit
    rmses_raw = np.empty(limit, dtype=float)
    n = 0
    t0 = time.time()
    while n < limit:
        rmse, _msg, _src, _ae_t = K.proc_next_packet()
        if rmse == -1:
            if K.FE.curPacketIndx >= K.FE.limit:
                break  # genuine EOF
            rmses_raw[n] = 0.0  # unparseable packet -> neutral score, keep alignment
            n += 1
            continue
        rmses_raw[n] = rmse
        n += 1
    dt = time.time() - t0
    rmses_raw = rmses_raw[:n]
    print(f"    X1 done: {n} RMSEs in {dt:.1f}s ({1000*dt/max(n,1):.3f} ms/pkt)")
    return rmses_raw, dt


def metrics_from_flags(atk_flag: np.ndarray, ben_flag: np.ndarray) -> dict:
    tp = int(atk_flag.sum()); fn = int((~atk_flag).sum())
    fp = int(ben_flag.sum()); tn = int((~ben_flag).sum())
    tpr = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else float("nan")
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else float("nan")
    return dict(TPR=tpr, FPR=fpr, Precision=prec, F1=f1, Accuracy=acc,
                tp=tp, fp=fp, fn=fn, tn=tn)


def auc_eer(scores_neg: np.ndarray, scores_pos: np.ndarray):
    y = np.concatenate([np.zeros(len(scores_neg), int), np.ones(len(scores_pos), int)])
    s = np.concatenate([scores_neg, scores_pos])
    if y.sum() == 0 or y.sum() == len(y):
        return float("nan"), float("nan")
    fpr, tpr, _ = roc_curve(y, s)
    a = float(sk_auc(fpr, tpr))
    fnr = 1 - tpr
    i = int(np.nanargmin(np.abs(fpr - fnr)))
    eer = float((fpr[i] + fnr[i]) / 2.0)
    return a, eer


def calib_quantile_eta(cndg: np.ndarray, cnds: np.ndarray, target: float):
    """Pick (eta_g, eta_s) by benign quantile on the calib half targeting `target` FPR.

    Mirrors results/CICIoT2023/_analyze_cleansplit.py::calib_q: sweep a shared
    quantile q for both channels, prefer the largest FPR that stays <= target.
    """
    qs = np.concatenate([np.linspace(0.50, 0.90, 41), np.linspace(0.9001, 0.99999, 1500)])
    best = None
    for q in qs:
        eg = float(np.quantile(cndg, q)); es = float(np.quantile(cnds, q))
        fpr = float(np.mean((cndg > eg) | (cnds > es)))
        key = (0 if fpr <= target + 1e-9 else 1, abs(fpr - target))
        if best is None or key < best[0]:
            best = (key, eg, es, fpr)
    return best[1], best[2], best[3]  # eta_g, eta_s, calib_fpr


def kitsune_baseline(rmse_tanh: np.ndarray, labels: list[int]):
    """tanh(rmse) with benign Median+MAD threshold from [55001:60000]; eval on TEST."""
    cal = rmse_tanh[TRAIN_START_IDX:BENIGN_LIMIT]
    med = float(np.median(cal))
    mad = float(np.median(np.abs(cal - med)))
    thr = med + MAD_K * 1.4826 * mad
    test_scores = rmse_tanh[BENIGN_LIMIT:]
    gold = np.asarray(labels[BENIGN_LIMIT:])
    ben = test_scores[:N_BEN_TEST]
    atk = test_scores[N_BEN_TEST:]
    m = metrics_from_flags(atk > thr, ben > thr)
    a, e = auc_eer(ben, atk)
    m.update(auc=a, eer=e, threshold=thr, median=med, mad=mad)
    return m, gold, test_scores


def run_attack(attack: str, prov: dict, use_cached_rmse: bool):
    tsv = os.path.join(INDEP, f"stream_{attack}.pcap.tsv")
    lab = os.path.join(INDEP, f"labels_{attack}.csv")
    print(f"\n================ {attack} ================")
    print(f"  TSV:    {tsv}")

    labels = read_labels(lab)
    IPs, IPd = R.build_IP_list(tsv)
    n_pkts = len(IPs)
    assert n_pkts == len(labels) == 170000, f"{attack}: IPs={n_pkts} labels={len(labels)}"
    assert set(labels[:120000]) == {0}, f"{attack}: benign region has non-zero labels"
    assert set(labels[120000:]) == {1}, f"{attack}: attack region has non-one labels"
    print(f"  packets={n_pkts} labels={len(labels)} (benign 120000 + attack 50000) OK")

    # ---- X1 (KitNET RMSEs, cached) ----
    cache = os.path.join(INDEP, f"rmse_raw_{attack}.npy")
    x1_dt = float("nan")
    if use_cached_rmse and os.path.exists(cache):
        rmse_raw = np.load(cache)
        print(f"    X1 loaded from cache: {len(rmse_raw)} RMSEs")
    else:
        rmse_raw, x1_dt = run_x1(tsv)
        np.save(cache, rmse_raw)
    assert len(rmse_raw) == n_pkts, f"RMSE/packet misalignment {len(rmse_raw)} vs {n_pkts}"
    rmse_tanh = np.tanh(rmse_raw)

    # ---- Kitsune baseline (single tanh, Median+MAD) ----
    kpm, kgold, kscores = kitsune_baseline(rmse_tanh, labels)
    print(f"  [Kitsune] thr={kpm['threshold']:.6f} TPR={kpm['TPR']:.4f} FPR={kpm['FPR']:.4f} "
          f"P={kpm['Precision']:.4f} F1={kpm['F1']:.4f} AUC={kpm['auc']:.4f} EER={kpm['eer']:.4f}")
    np.save(os.path.join(INDEP, f"arr_kitsune_{attack}_indep.npy"), np.asarray(kscores))

    # ---- Tenko X2-X4 (single-tanh: feed RAW rmse) ----
    out = R.get_adversarial_IPs_weighted_pattern(
        IPs=IPs, IPd=IPd, LABELS=labels, RMSEs=list(rmse_raw),
        memorySize=60, blockchainMode="offline",
        pattern_window_size=100, pattern_segments=10,
        global_pool_tol_factor=50, single_agg_tol_factor=20,
        weight_global=0.5, weight_single=0.5, ensemble_threshold=0.5,
        benignLimit=BENIGN_LIMIT, return_scores=True,
    )
    tgold = np.asarray(out[0])
    tpred = np.asarray(out[1])
    cont = np.asarray(out[9])
    ndg = np.asarray(out[11])
    nds = np.asarray(out[12])
    assert len(tgold) == len(cont) == len(ndg) == len(nds) == (N_BEN_TEST + N_ATK), \
        f"{attack}: test-array length {len(cont)} != {N_BEN_TEST + N_ATK}"
    assert int(tgold[BEN_TEST].sum()) == 0 and int(tgold[ATK].sum()) == N_ATK, \
        f"{attack}: gold region mismatch"

    np.save(os.path.join(INDEP, f"arr_gold_{attack}_indep.npy"), tgold)
    np.save(os.path.join(INDEP, f"arr_ndg_{attack}_indep.npy"), ndg)
    np.save(os.path.join(INDEP, f"arr_nds_{attack}_indep.npy"), nds)
    np.save(os.path.join(INDEP, f"arr_cont_{attack}_indep.npy"), cont)

    # threshold-independent AUC/EER on the fused continuous score (full TEST region)
    A, E = auc_eer(cont[BEN_TEST], cont[ATK])

    rows = []
    p = prov[attack]
    prov_cols = dict(benign_src=p["benign_src"],
                     offset_start=p["offset_start_1based"],
                     offset_end=p["offset_end_1based"])

    # (1) committed eta = 50/20 (benign-only fixed OP); evaluate on full benign_test
    atk_flag = (ndg[ATK] > COMMITTED_ETA_G) | (nds[ATK] > COMMITTED_ETA_S)
    ben_flag = (ndg[BEN_TEST] > COMMITTED_ETA_G) | (nds[BEN_TEST] > COMMITTED_ETA_S)
    m = metrics_from_flags(atk_flag, ben_flag)
    # cross-check against the function's own committed binary prediction
    op_pred = ((ndg > COMMITTED_ETA_G) | (nds > COMMITTED_ETA_S)).astype(int)
    assert np.array_equal(op_pred, tpred.astype(int)), \
        f"{attack}: recomputed committed pred != out[1]"
    rows.append(dict(attack=attack, method="Tenko_committed_50_20", eta_g=COMMITTED_ETA_G,
                     eta_s=COMMITTED_ETA_S, AUC=A, EER=E, n_benign_test=N_BEN_TEST,
                     n_attack=N_ATK, **m, **prov_cols))

    # (2) benign-only quantile calibration on calib half -> eval on eval half + attack
    for t in FPR_TARGETS:
        eg, es, cf = calib_quantile_eta(ndg[CALIB], nds[CALIB], t)
        atk_flag = (ndg[ATK] > eg) | (nds[ATK] > es)
        ben_flag = (ndg[EVAL] > eg) | (nds[EVAL] > es)
        m = metrics_from_flags(atk_flag, ben_flag)
        rows.append(dict(attack=attack, method=f"Tenko_benign_calib@{int(t*100)}%",
                         eta_g=eg, eta_s=es, AUC=A, EER=E,
                         n_benign_test=30000, n_attack=N_ATK, **m, **prov_cols))

    # (3) Kitsune baseline row (median+MAD threshold; eval on full TEST)
    rows.append(dict(attack=attack, method="Kitsune_median_mad", eta_g=kpm["threshold"],
                     eta_s=float("nan"), AUC=kpm["auc"], EER=kpm["eer"],
                     n_benign_test=N_BEN_TEST, n_attack=N_ATK,
                     TPR=kpm["TPR"], FPR=kpm["FPR"], Precision=kpm["Precision"],
                     F1=kpm["F1"], Accuracy=kpm["Accuracy"],
                     tp=kpm["tp"], fp=kpm["fp"], fn=kpm["fn"], tn=kpm["tn"], **prov_cols))

    # console summary for this attack
    c = rows[0]
    print(f"  [Tenko committed 50/20] TPR={c['TPR']:.4f} FPR={c['FPR']:.4f} "
          f"P={c['Precision']:.4f} F1={c['F1']:.4f} Acc={c['Accuracy']:.4f} "
          f"AUC={A:.4f} EER={E:.4f}")
    return rows, x1_dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks", default="all")
    ap.add_argument("--use-cached-rmse", action="store_true")
    args = ap.parse_args()
    attacks = ATTACKS if args.attacks == "all" else args.attacks.split(",")

    prov = load_provenance()
    all_rows = []
    timings = {}
    t_all = time.time()
    for a in attacks:
        rows, dt = run_attack(a, prov, args.use_cached_rmse)
        all_rows.extend(rows)
        timings[a] = dt

    # ---- write CSV ----
    fields = ["attack", "method", "benign_src", "offset_start", "offset_end",
              "eta_g", "eta_s", "TPR", "FPR", "Precision", "F1", "Accuracy",
              "AUC", "EER", "tp", "fp", "fn", "tn", "n_benign_test", "n_attack"]
    out_csv = os.path.join(INDEP, "ciciot2023_independent_streams_metrics.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: (f"{r[k]:.6f}" if isinstance(r.get(k), float) else r.get(k, ""))
                        for k in fields})

    # ---- printed summary: committed 50/20 ----
    def line(vals, W):
        return " ".join(str(v).ljust(w) if i == 0 else str(v).rjust(w)
                        for i, (v, w) in enumerate(zip(vals, W)))
    W = [22, 8, 8, 9, 8, 9, 8, 8]
    hdr = ["attack", "TPR", "FPR", "Prec", "F1", "Acc", "AUC", "EER"]
    comm = [r for r in all_rows if r["method"] == "Tenko_committed_50_20"]
    print("\n===== INDEPENDENT STREAMS — Tenko committed eta=50/20 (benign_test 60k neg / attack 50k pos) =====")
    print(line(hdr, W))
    for r in comm:
        print(line([r["attack"], f"{r['TPR']:.4f}", f"{r['FPR']:.4f}", f"{r['Precision']:.4f}",
                    f"{r['F1']:.4f}", f"{r['Accuracy']:.4f}", f"{r['AUC']:.4f}", f"{r['EER']:.4f}"], W))
    def mean(key):
        vals = [r[key] for r in comm if not (isinstance(r[key], float) and np.isnan(r[key]))]
        return sum(vals) / len(vals) if vals else float("nan")
    print(line(["MEAN", f"{mean('TPR'):.4f}", f"{mean('FPR'):.4f}", f"{mean('Precision'):.4f}",
                f"{mean('F1'):.4f}", f"{mean('Accuracy'):.4f}", f"{mean('AUC'):.4f}", f"{mean('EER'):.4f}"], W))

    fprs = [r["FPR"] for r in comm]
    print(f"\nKEY RESULT — per-attack committed FPR range: min={min(fprs):.4f} max={max(fprs):.4f} "
          f"spread={max(fprs)-min(fprs):.4f}")
    print(f"\nWrote {out_csv}")
    print(f"X1 timings (s): " + ", ".join(f"{a}={timings[a]:.1f}" for a in attacks if not np.isnan(timings.get(a, float('nan')))))
    print(f"ALL DONE in {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()
