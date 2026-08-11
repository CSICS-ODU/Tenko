#!/usr/bin/env python3
"""Combined "mixed" CICIoT2023 driver: ONE physically-concatenated stream
(shared benign + all 6 attacks back-to-back) run through KitNET(X1) + Tenko(X2-X4)
once, with node state carried across the WHOLE stream. Self-contained, pandas-free,
single-tanh. Reports aggregate metrics in the paper's Table-9 format plus a
per-attack breakdown.

Stream layout (0-indexed):
  benign            [     0 : 120000]  label 0
  DoS-SYN_Flood     [120000 : 170000]  label 1
  DDoS-UDP_Flood    [170000 : 220000]  label 1
  Recon-OSScan      [220000 : 270000]  label 1
  MITM-ArpSpoofing  [270000 : 320000]  label 1
  Mirai-greeth_flood[320000 : 370000]  label 1
  DictionaryBruteForce[370000:420000]  label 1

benignLimit=60000 (KitNET trains [0:55000]; Tenko pattern on [55001:60000]).
Test region = [60000:420000] = 60k benign negatives + 300k attack positives.

single-tanh: feed RAW rmse to results.get_adversarial_IPs_weighted_pattern;
results.py applies its ONE internal tanh (results.py:805). The Kitsune baseline
uses a single tanh (tanh(raw)) with a benign Median+MAD threshold.
"""
from __future__ import annotations

import csv
import os
import sys
import time

import numpy as np

# Run from repo root so `import results` / `from Kitsune import Kitsune` work.
REPO = "/Users/sbhola/Desktop/Tenko"
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from Kitsune import Kitsune
import results as R

# ---- Fixed pipeline constants (match example.py / run_ciciot2023.py) ----
MAXAE = 10
FMGRACE = 5000
ADGRACE = 50000
TRAIN_START_IDX = FMGRACE + ADGRACE + 1   # 55001: first benign packet for calibration
MAD_K = 3.0

BENIGN_LIMIT = 60000
N_BENIGN = 120000
N_ATK = 50000
N_TOTAL = 420000

MIX = os.path.join(REPO, "results/CICIoT2023/mixed")
TSV = os.path.join(MIX, "stream_mixed.pcap.tsv")
LAB = os.path.join(MIX, "labels_mixed.csv")

# Fixed attack order + stream blocks (0-indexed, absolute stream indices).
ATTACK_BLOCKS = [
    ("DoS-SYN_Flood",        120000, 170000),
    ("DDoS-UDP_Flood",       170000, 220000),
    ("Recon-OSScan",         220000, 270000),
    ("MITM-ArpSpoofing",     270000, 320000),
    ("Mirai-greeth_flood",   320000, 370000),
    ("DictionaryBruteForce", 370000, 420000),
]


def load_labels_csv(path: str, col: str = "x") -> np.ndarray:
    """pandas-free label loader (header row names the column)."""
    with open(path, "r", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        idx = header.index(col)
        labels = [int(row[idx]) for row in reader if row]
    return np.asarray(labels, dtype=int)


def run_x1(tsv_path: str):
    """Stream the TSV through KitNET; raw RMSEs aligned 1:1 with packets.

    Mirrors run_ciciot2023.run_x1: unparseable packet -> neutral 0.0 (keeps
    alignment); genuine EOF detected via FE.curPacketIndx >= FE.limit.
    """
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
            rmses_raw[n] = 0.0
            n += 1
            continue
        rmses_raw[n] = rmse
        n += 1
    dt = time.time() - t0
    rmses_raw = rmses_raw[:n]
    print(f"    X1 done: {n} RMSEs in {dt:.1f}s ({1000*dt/max(n,1):.3f} ms/pkt)")
    return rmses_raw, dt


# --------------------------- metric helpers ---------------------------

def _f1_from_counts(tp, fp, fn):
    denom = 2 * tp + fp + fn
    return (2 * tp / denom) if denom > 0 else float("nan")


def binary_point_metrics(pred_benign, pred_attack):
    """pred_benign/pred_attack: 0/1 arrays over the benign negatives and the
    (pooled) attack positives respectively."""
    fp = int(pred_benign.sum())
    tn = int((pred_benign == 0).sum())
    tp = int(pred_attack.sum())
    fn = int((pred_attack == 0).sum())
    total = tp + tn + fp + fn
    tpr = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
    prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    f1 = _f1_from_counts(tp, fp, fn)
    acc = (tp + tn) / total if total > 0 else float("nan")
    return dict(Accuracy=acc, F1=f1, TPR=tpr, FPR=fpr, Precision=prec,
                tp=tp, fp=fp, fn=fn, tn=tn)


def auc_eer(labels, scores):
    from sklearn.metrics import roc_curve, auc as sk_auc
    labels = np.asarray(labels)
    if labels.sum() == 0 or labels.sum() == len(labels):
        return float("nan"), float("nan")
    fpr, tpr, _ = roc_curve(labels, scores)
    roc_auc = float(sk_auc(fpr, tpr))
    fnr = 1 - tpr
    i = int(np.nanargmin(np.abs(fpr - fnr)))
    eer = float((fpr[i] + fnr[i]) / 2.0)
    return roc_auc, eer


def main():
    t_all = time.time()
    os.makedirs(MIX, exist_ok=True)

    # ---- Labels ----
    labels = load_labels_csv(LAB, "x")
    assert len(labels) == N_TOTAL, f"labels {len(labels)} != {N_TOTAL}"
    assert labels[:N_BENIGN].sum() == 0, "benign region has non-zero labels"
    assert labels[N_BENIGN:].sum() == (N_TOTAL - N_BENIGN), "attack region not all ones"
    print(f"labels OK: {len(labels)} rows, {int(labels.sum())} positives")

    # ---- IPs ----
    IPs, IPd = R.build_IP_list(TSV)
    assert len(IPs) == N_TOTAL, f"IPs {len(IPs)} != {N_TOTAL}"
    print(f"IPs OK: {len(IPs)}")

    # ---- X1 (KitNET) ----
    cache = os.path.join(MIX, "rmse_raw_mixed.npy")
    x1_dt = float("nan")
    if os.path.exists(cache):
        rmse_raw = np.load(cache)
        print(f"    X1 loaded from cache: {len(rmse_raw)} RMSEs")
    else:
        rmse_raw, x1_dt = run_x1(TSV)
        np.save(cache, rmse_raw)
    assert len(rmse_raw) == N_TOTAL, f"RMSE/packet misalignment {len(rmse_raw)} vs {N_TOTAL}"
    rmse_tanh1 = np.tanh(rmse_raw)   # single tanh, for the Kitsune baseline

    # ================= Kitsune baseline (single tanh, Median+MAD) =================
    cal = rmse_tanh1[TRAIN_START_IDX:BENIGN_LIMIT]
    med = float(np.median(cal))
    mad = float(np.median(np.abs(cal - med)))
    thr = med + MAD_K * 1.4826 * mad
    kit_scores_test = rmse_tanh1[BENIGN_LIMIT:]           # aligns with test region
    kit_pred_test = (kit_scores_test > thr).astype(int)
    np.save(os.path.join(MIX, "kitsune_testscores_mixed.npy"), kit_scores_test)

    # ================= Tenko X2-X4 (single-tanh: feed RAW rmse) =================
    out = R.get_adversarial_IPs_weighted_pattern(
        IPs=IPs, IPd=IPd, LABELS=list(labels), RMSEs=list(rmse_raw),
        memorySize=60, blockchainMode="offline",
        pattern_window_size=100, pattern_segments=10,
        global_pool_tol_factor=50, single_agg_tol_factor=20,
        weight_global=0.5, weight_single=0.5, ensemble_threshold=0.5,
        benignLimit=BENIGN_LIMIT, return_scores=True,
    )
    tgold = np.asarray(out[0])          # labels[60000:], len 360000
    tpred = np.asarray(out[1])          # committed eta=50/20 binary pred
    cont = np.asarray(out[9])           # fused continuous score (AUC/EER)
    nd_g = np.asarray(out[11])
    nd_s = np.asarray(out[12])
    assert len(tgold) == N_TOTAL - BENIGN_LIMIT == 360000, f"gold len {len(tgold)}"

    # Recompute committed pred from nd_g/nd_s and cross-check against out[1].
    pred_recomp = ((nd_g > 50.0) | (nd_s > 20.0)).astype(int)
    mismatch = int(np.sum(pred_recomp != tpred))
    print(f"  committed-pred vs out[1] mismatches: {mismatch} (should be 0)")

    # Persist Tenko arrays.
    np.save(os.path.join(MIX, "arr_gold_mixed.npy"), tgold)
    np.save(os.path.join(MIX, "arr_ndg_mixed.npy"), nd_g)
    np.save(os.path.join(MIX, "arr_nds_mixed.npy"), nd_s)
    np.save(os.path.join(MIX, "arr_cont_mixed.npy"), cont)
    np.save(os.path.join(MIX, "arr_pred_mixed.npy"), tpred)

    # ----- test-region index map (test_idx = stream_idx - benignLimit) -----
    # benign negatives: stream [60000:120000] -> test_idx [0:60000]
    ben_sl = slice(0, N_BENIGN - BENIGN_LIMIT)  # [0:60000]
    n_ben = N_BENIGN - BENIGN_LIMIT             # 60000
    blocks_test = [(a, s - BENIGN_LIMIT, e - BENIGN_LIMIT) for (a, s, e) in ATTACK_BLOCKS]

    # sanity: gold layout
    assert tgold[ben_sl].sum() == 0, "benign test negatives not all 0"
    for (a, ts, te) in blocks_test:
        assert tgold[ts:te].sum() == (te - ts), f"{a} block not all attack"

    def aggregate_metrics(pred_test, cont_scores_test):
        """pred_test: 0/1 over full test region (len 360000);
        cont_scores_test: continuous score over full test region for AUC/EER."""
        pred_ben = pred_test[ben_sl]
        pred_atk = pred_test[n_ben:]                 # all 300k attack packets
        m = binary_point_metrics(pred_ben, pred_atk)
        # Macro-F1 = mean of 6 per-attack F1 (each block vs the SHARED 60k benign)
        fp_shared = int(pred_ben.sum())
        per_f1 = []
        for (a, ts, te) in blocks_test:
            blk = pred_test[ts:te]
            tp = int(blk.sum()); fn = int((blk == 0).sum())
            per_f1.append(_f1_from_counts(tp, fp_shared, fn))
        macro_f1 = float(np.mean(per_f1))
        # AUC/EER: benign(0) vs all-attack(1) on continuous score
        lab = np.concatenate([np.zeros(n_ben, int), np.ones(len(cont_scores_test) - n_ben, int)])
        a_auc, a_eer = auc_eer(lab, cont_scores_test)
        m.update(MacroF1=macro_f1, AUC_ROC=a_auc, EER=a_eer, per_attack_f1=per_f1)
        return m

    # For AUC we need a continuous score aligned with the test region for BOTH models.
    tenko_agg = aggregate_metrics(tpred, cont)
    # Kitsune: pred over test region + tanh score over test region.
    kit_agg = aggregate_metrics(kit_pred_test, kit_scores_test)

    # ----- Per-attack breakdown (Tenko): TPR (recall), F1 vs shared benign, AUC (block vs benign) -----
    fp_shared_tenko = int(tpred[ben_sl].sum())
    fp_shared_kit = int(kit_pred_test[ben_sl].sum())
    per_attack_rows = []
    for (a, ts, te) in blocks_test:
        n_pos = te - ts
        # Tenko
        blk_pred = tpred[ts:te]
        tp = int(blk_pred.sum()); fn = n_pos - tp
        tpr_t = tp / n_pos if n_pos else float("nan")
        f1_t = _f1_from_counts(tp, fp_shared_tenko, fn)
        fpr_t = fp_shared_tenko / n_ben if n_ben else float("nan")
        prec_t = tp / (tp + fp_shared_tenko) if (tp + fp_shared_tenko) > 0 else float("nan")
        acc_t = (tp + (n_ben - fp_shared_tenko)) / (n_pos + n_ben)
        # AUC block vs shared benign on continuous fused score
        lab_b = np.concatenate([np.zeros(n_ben, int), np.ones(n_pos, int)])
        sc_b = np.concatenate([cont[ben_sl], cont[ts:te]])
        auc_t, eer_t = auc_eer(lab_b, sc_b)
        # Kitsune (for the same block)
        blk_predk = kit_pred_test[ts:te]
        tpk = int(blk_predk.sum()); fnk = n_pos - tpk
        tpr_k = tpk / n_pos if n_pos else float("nan")
        f1_k = _f1_from_counts(tpk, fp_shared_kit, fnk)
        sc_bk = np.concatenate([kit_scores_test[ben_sl], kit_scores_test[ts:te]])
        auc_k, eer_k = auc_eer(lab_b, sc_bk)
        per_attack_rows.append(dict(
            attack=a, n_pos=n_pos,
            tenko_TPR=tpr_t, tenko_F1=f1_t, tenko_FPR=fpr_t, tenko_Precision=prec_t,
            tenko_Accuracy=acc_t, tenko_AUC=auc_t, tenko_EER=eer_t,
            kit_TPR=tpr_k, kit_F1=f1_k, kit_AUC=auc_k, kit_EER=eer_k,
        ))

    # =============================== OUTPUT ===============================
    def fmt(x):
        return f"{x:.6f}" if isinstance(x, float) and not np.isnan(x) else ("nan" if isinstance(x, float) else str(x))

    csv_path = os.path.join(MIX, "ciciot2023_mixed_stream_metrics.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scope", "model", "attack", "Accuracy", "F1", "MacroF1",
                    "AUC_ROC", "EER", "TPR", "FPR", "Precision", "n_benign", "n_pos"])
        # aggregate rows
        for model, m in (("Tenko", tenko_agg), ("Kitsune", kit_agg)):
            w.writerow(["aggregate", model, "ALL",
                        fmt(m["Accuracy"]), fmt(m["F1"]), fmt(m["MacroF1"]),
                        fmt(m["AUC_ROC"]), fmt(m["EER"]), fmt(m["TPR"]),
                        fmt(m["FPR"]), fmt(m["Precision"]), n_ben, N_TOTAL - N_BENIGN])
        # per-attack rows (Tenko primary; Kitsune companion)
        for r in per_attack_rows:
            w.writerow(["per_attack", "Tenko", r["attack"],
                        fmt(r["tenko_Accuracy"]), fmt(r["tenko_F1"]), "nan",
                        fmt(r["tenko_AUC"]), fmt(r["tenko_EER"]), fmt(r["tenko_TPR"]),
                        fmt(r["tenko_FPR"]), fmt(r["tenko_Precision"]), n_ben, r["n_pos"]])
        for r in per_attack_rows:
            w.writerow(["per_attack", "Kitsune", r["attack"],
                        "nan", fmt(r["kit_F1"]), "nan",
                        fmt(r["kit_AUC"]), fmt(r["kit_EER"]), fmt(r["kit_TPR"]),
                        "nan", "nan", n_ben, r["n_pos"]])

    # ------------------------- printed summary -------------------------
    print("\n" + "=" * 78)
    print("MIXED STREAM (420k pkts: 120k shared benign + 6x50k attacks concatenated)")
    print("Test region [60000:420000] = 60,000 benign negatives + 300,000 attack positives")
    print("=" * 78)
    print(f"\nKitsune baseline threshold: thr={thr:.6f} (median={med:.6f}, mad={mad:.6e})")
    print(f"X1 KitNET time: {x1_dt if not np.isnan(x1_dt) else 'cached'}"
          + (f"  ({1000*x1_dt/N_TOTAL:.3f} ms/pkt)" if not np.isnan(x1_dt) else ""))

    print("\n---- AGGREGATE (Table-9 format) ----")
    hdr = f"{'model':10} {'Acc':>8} {'F1':>8} {'MacroF1':>8} {'AUC-ROC':>8} {'EER':>8} {'TPR':>8} {'FPR':>8} {'Prec':>8}"
    print(hdr)
    for model, m in (("Tenko", tenko_agg), ("Kitsune", kit_agg)):
        print(f"{model:10} {m['Accuracy']:8.4f} {m['F1']:8.4f} {m['MacroF1']:8.4f} "
              f"{m['AUC_ROC']:8.4f} {m['EER']:8.4f} {m['TPR']:8.4f} {m['FPR']:8.4f} {m['Precision']:8.4f}")

    print("\n---- PER-ATTACK BREAKDOWN (Tenko) ----")
    print(f"{'attack':22} {'TPR':>8} {'F1':>8} {'AUC':>8} {'EER':>8}")
    for r in per_attack_rows:
        print(f"{r['attack']:22} {r['tenko_TPR']:8.4f} {r['tenko_F1']:8.4f} "
              f"{r['tenko_AUC']:8.4f} {r['tenko_EER']:8.4f}")

    print("\n---- PER-ATTACK BREAKDOWN (Kitsune) ----")
    print(f"{'attack':22} {'TPR':>8} {'F1':>8} {'AUC':>8} {'EER':>8}")
    for r in per_attack_rows:
        print(f"{r['attack']:22} {r['kit_TPR']:8.4f} {r['kit_F1']:8.4f} "
              f"{r['kit_AUC']:8.4f} {r['kit_EER']:8.4f}")

    # Machine-readable dump for the memo generator.
    import json
    summary = dict(
        thr=thr, med=med, mad=mad, x1_dt=(None if np.isnan(x1_dt) else x1_dt),
        committed_pred_mismatch=mismatch,
        tenko=dict(Accuracy=tenko_agg["Accuracy"], F1=tenko_agg["F1"],
                   MacroF1=tenko_agg["MacroF1"], AUC_ROC=tenko_agg["AUC_ROC"],
                   EER=tenko_agg["EER"], TPR=tenko_agg["TPR"], FPR=tenko_agg["FPR"],
                   Precision=tenko_agg["Precision"], per_attack_f1=tenko_agg["per_attack_f1"]),
        kitsune=dict(Accuracy=kit_agg["Accuracy"], F1=kit_agg["F1"],
                     MacroF1=kit_agg["MacroF1"], AUC_ROC=kit_agg["AUC_ROC"],
                     EER=kit_agg["EER"], TPR=kit_agg["TPR"], FPR=kit_agg["FPR"],
                     Precision=kit_agg["Precision"]),
        per_attack=per_attack_rows,
    )
    with open(os.path.join(MIX, "mixed_summary.json"), "w") as jf:
        json.dump(summary, jf, indent=2, default=lambda o: (None if isinstance(o, float) and np.isnan(o) else o))

    print(f"\nWrote: {csv_path}")
    print(f"Wrote: {os.path.join(MIX, 'mixed_summary.json')}")
    print(f"\nTOTAL wall time: {time.time()-t_all:.1f}s")


if __name__ == "__main__":
    main()
