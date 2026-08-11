#!/usr/bin/env python3
"""Per-attack-class CICIoT2023 driver for Tenko (X1-X4) vs a Kitsune baseline.

For each per-attack stream ([benign_lead][benign_test][attack]) this:
  1. Runs X1 (KitNET) to get per-packet RMSEs (raw + tanh), with strict
     RMSE<->packet<->label alignment (never breaks mid-stream on a parse error).
  2. Runs the Kitsune baseline: score = tanh(RMSE), benign-derived Median+MAD
     threshold from the calibration region, evaluated on the TEST region only.
  3. Runs Tenko X2-X4 via results.get_adversarial_IPs_weighted_pattern with
     benignLimit set to the benign_lead length (so the TEST region is
     benign_test negatives + attack positives).
  4. Computes TPR/FPR/Precision/F1 (point) and AUC/EER (threshold-independent)
     for both models and appends rows to a summary CSV.

Faithfulness note: the committed pipeline applies tanh twice for Tenko
(example.py stores tanh(raw) in RMSEs.pkl; results.py:809 applies tanh again).
We reproduce that exactly by feeding tanh(raw) into the Tenko function. The
Kitsune baseline uses a single tanh (raw per-packet tanh(RMSE)), per the task.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time

import numpy as np

from Kitsune import Kitsune
import results as R

# --- Fixed pipeline constants (match example.py / results.py) ---
MAXAE = 10
FMGRACE = 5000
ADGRACE = 50000
TRAIN_START_IDX = FMGRACE + ADGRACE + 1  # first index used for benign calibration
MAD_K = 3.0                               # Kitsune threshold = median + K*1.4826*MAD

BIG_DIR = "/Users/sbhola/Desktop/cic/pilot"
OUT_DIR = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"

ATTACKS = [
    "DDoS-UDP_Flood",
    "DoS-SYN_Flood",
    "Recon-OSScan",
    "MITM-ArpSpoofing",
    "Mirai-greeth_flood",
    "DictionaryBruteForce",
]


def run_x1(tsv_path: str):
    """Stream the TSV through KitNET; return raw RMSEs aligned 1:1 with packets.

    Guarantees len(rmses_raw) == number of TSV data rows: a mid-stream parse
    failure (get_next_vector -> []) yields rmse == -1; we detect EOF vs error via
    FE.curPacketIndx and, on error, append a neutral 0.0 and continue instead of
    breaking (which is what example.py does, and which would truncate/misalign).
    """
    K = Kitsune(tsv_path, np.inf, MAXAE, FMGRACE, ADGRACE)
    limit = K.packet_limit
    rmses_raw = np.empty(limit, dtype=float)
    n = 0
    t0 = time.time()
    while n < limit:
        rmse, _msg, _src, _ae_t = K.proc_next_packet()
        if rmse == -1:
            # EOF or parse error. Distinguish via FE index.
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
    return rmses_raw, limit


def point_metrics(gold, pred):
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(gold, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    tpr = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
    prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else float("nan")
    return dict(tpr=tpr, fpr=fpr, precision=prec, f1=f1,
               tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))


def auc_eer(gold, scores):
    from sklearn.metrics import roc_curve, auc
    gold = np.asarray(gold)
    if gold.sum() == 0 or gold.sum() == len(gold):
        return float("nan"), float("nan")  # degenerate: only one class present
    fpr, tpr, _thr = roc_curve(gold, scores)
    roc_auc = auc(fpr, tpr)
    fnr = 1 - tpr
    eer_idx = int(np.nanargmin(np.abs(fpr - fnr)))
    eer = float((fpr[eer_idx] + fnr[eer_idx]) / 2.0)
    return float(roc_auc), eer


def kitsune_baseline(rmse_tanh, labels, benignLimit):
    """Raw per-packet tanh(RMSE) with a benign-derived Median+MAD threshold.

    Calibration region = [TRAIN_START_IDX : benignLimit] (post-KitNET-training
    benign packets). Threshold = median + K * 1.4826 * MAD. Evaluated on the
    TEST region [benignLimit:] so negatives=benign_test, positives=attack.
    """
    cal = rmse_tanh[TRAIN_START_IDX:benignLimit]
    med = float(np.median(cal))
    mad = float(np.median(np.abs(cal - med)))
    thr = med + MAD_K * 1.4826 * mad
    gold = list(labels[benignLimit:])
    test_scores = rmse_tanh[benignLimit:]
    pred = (test_scores > thr).astype(int).tolist()
    pm = point_metrics(gold, pred)
    a, e = auc_eer(gold, test_scores)
    pm.update(auc=a, eer=e, threshold=thr, median=med, mad=mad)
    return pm, gold, test_scores


def run_attack(attack: str, writer, fh, breakdown_writer=None, use_cached_rmse=False,
               tanh_mode="double", tag="double"):
    tsv = os.path.join(BIG_DIR, f"stream_{attack}.pcap.tsv")
    lab = os.path.join(OUT_DIR, f"labels_{attack}.csv")
    print(f"\n================ {attack} ================")
    print(f"  TSV:    {tsv}")
    print(f"  labels: {lab}")

    labels = R.build_label_list(lab, label_col="x")
    IPs, IPd = R.build_IP_list(tsv)
    n_pkts = len(IPs)
    print(f"  packets(IPs)={n_pkts}  labels={len(labels)}")

    # benignLimit = benign_lead length = index of first benign_test packet.
    # labels layout: [0]*(n_lead+n_test) + [1]*n_attack. n_lead comes from the
    # stream_counts.csv produced by the build script.
    import pandas as pd
    counts = pd.read_csv(os.path.join(OUT_DIR, "stream_counts.csv"))
    row = counts[counts["attack"] == attack].iloc[0]
    n_lead = int(row["n_lead"]); n_test = int(row["n_test"]); n_atk = int(row["n_attack"])
    benignLimit = n_lead
    assert len(labels) == n_pkts == (n_lead + n_test + n_atk), (
        f"alignment mismatch: labels={len(labels)} IPs={n_pkts} sum={n_lead+n_test+n_atk}")
    # sanity: label boundaries
    assert set(labels[:n_lead + n_test]) == {0}, "benign region has non-zero labels"
    assert set(labels[n_lead + n_test:]) == {1}, "attack region has non-one labels"

    # ---- X1 (KitNET RMSEs) ----
    cache = os.path.join(OUT_DIR, f"rmse_raw_{attack}.npy")
    if use_cached_rmse and os.path.exists(cache):
        rmse_raw = np.load(cache)
        print(f"    X1 loaded from cache: {len(rmse_raw)} RMSEs")
    else:
        rmse_raw, _limit = run_x1(tsv)
        np.save(cache, rmse_raw)
    assert len(rmse_raw) == n_pkts, f"RMSE/packet misalignment {len(rmse_raw)} vs {n_pkts}"
    rmse_tanh1 = np.tanh(rmse_raw)                    # == what example.py stores (single tanh)

    # Tenko input depends on the tanh variant:
    #   double  -> feed tanh(raw); results.py applies tanh again == committed pipeline (tanh(tanh(raw)))
    #   single  -> feed raw; results.py's single tanh is the ONLY normalization (tanh(raw))
    tenko_input = rmse_tanh1 if tanh_mode == "double" else rmse_raw

    # ---- Kitsune baseline (single tanh, Median+MAD threshold) -- variant-independent ----
    kpm, kgold, kscores = kitsune_baseline(rmse_tanh1, labels, benignLimit)
    print(f"  [Kitsune] thr={kpm['threshold']:.6f} (med={kpm['median']:.6f}, mad={kpm['mad']:.6e}) "
          f"TPR={kpm['tpr']:.4f} FPR={kpm['fpr']:.4f} P={kpm['precision']:.4f} "
          f"F1={kpm['f1']:.4f} AUC={kpm['auc']:.4f} EER={kpm['eer']:.4f}")
    np.save(os.path.join(OUT_DIR, f"kitsune_testscores_{attack}.npy"), kscores)

    # ---- Tenko X2-X4 (feed tanh(raw); function applies tanh again == committed) ----
    out = R.get_adversarial_IPs_weighted_pattern(
        IPs=IPs, IPd=IPd, LABELS=labels, RMSEs=list(tenko_input),
        memorySize=60, blockchainMode="offline",
        pattern_window_size=100, pattern_segments=10,
        global_pool_tol_factor=50, single_agg_tol_factor=20,
        weight_global=0.5, weight_single=0.5, ensemble_threshold=0.5,
        benignLimit=benignLimit, return_scores=True,
    )
    tgold, tpred = out[0], out[1]
    disc_scores = out[8]    # discrete weighted-flag score {0, .5, 1}
    cont_scores = out[9]    # fused eta-normalized pattern distance (threshold-independent)
    node_scores = out[10]   # per-test-packet X2 node anomaly score
    nd_g = np.asarray(out[11])  # per-test-packet global normalized pattern distance
    nd_s = np.asarray(out[12])  # per-test-packet single-aggregate normalized pattern distance
    # Persist arrays for offline benign-only eta calibration + single/double comparison.
    np.save(os.path.join(OUT_DIR, f"arr_gold_{attack}.npy"), np.asarray(tgold))
    np.save(os.path.join(OUT_DIR, f"arr_ndg_{attack}_{tag}.npy"), nd_g)
    np.save(os.path.join(OUT_DIR, f"arr_nds_{attack}_{tag}.npy"), nd_s)
    np.save(os.path.join(OUT_DIR, f"arr_node_{attack}_{tag}.npy"), np.asarray(node_scores))
    np.save(os.path.join(OUT_DIR, f"arr_cont_{attack}_{tag}.npy"), np.asarray(cont_scores))
    np.save(os.path.join(OUT_DIR, f"arr_kitsune_{attack}.npy"), np.asarray(kscores))

    # Point (operating-point) metrics come from the binary fused prediction.
    tpm = point_metrics(tgold, tpred)
    # AUC/EER (threshold-independent) come from the continuous pattern distance.
    auc_cont, eer_cont = auc_eer(tgold, cont_scores)
    auc_node, eer_node = auc_eer(tgold, node_scores)
    auc_disc, eer_disc = auc_eer(tgold, disc_scores)
    tpm.update(auc=auc_cont, eer=eer_cont)
    degenerate = (tpm["tp"] + tpm["fp"] == 0)  # operating point fired nothing
    print(f"  [Tenko]   (operating pt) TPR={tpm['tpr']:.4f} FPR={tpm['fpr']:.4f} "
          f"P={tpm['precision']} F1={tpm['f1']:.4f}  degenerate={degenerate}")
    print(f"  [Tenko]   AUC/EER  pattern={auc_cont:.4f}/{eer_cont:.4f}  "
          f"nodescore={auc_node:.4f}/{eer_node:.4f}  discrete={auc_disc:.4f}/{eer_disc:.4f}")
    np.save(os.path.join(OUT_DIR, f"tenko_patterndist_{attack}.npy"), np.asarray(cont_scores))
    np.save(os.path.join(OUT_DIR, f"tenko_nodescore_{attack}.npy"), np.asarray(node_scores))

    # ---- write summary rows (required schema) ----
    for model, m in (("Kitsune", kpm), ("Tenko", tpm)):
        writer.writerow([
            attack, model,
            f"{m['tpr']:.6f}", f"{m['fpr']:.6f}", f"{m['precision']:.6f}", f"{m['f1']:.6f}",
            f"{m['auc']:.6f}", f"{m['eer']:.6f}", n_test, n_atk, benignLimit,
        ])
    fh.flush()

    # ---- supplementary Tenko signal breakdown (for deliverable c / honesty) ----
    if breakdown_writer is not None:
        breakdown_writer.writerow([
            attack,
            f"{tpm['tpr']:.6f}", f"{tpm['fpr']:.6f}", f"{tpm['precision']}", f"{tpm['f1']:.6f}",
            int(degenerate),
            f"{auc_cont:.6f}", f"{eer_cont:.6f}",
            f"{auc_node:.6f}", f"{eer_node:.6f}",
            f"{auc_disc:.6f}", f"{eer_disc:.6f}",
            f"{kpm['auc']:.6f}", f"{kpm['eer']:.6f}",
        ])
    return kpm, tpm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks", default="all", help="comma-separated attack names or 'all'")
    ap.add_argument("--use-cached-rmse", action="store_true",
                    help="load cached rmse_raw_<attack>.npy instead of re-running X1")
    ap.add_argument("--tanh", choices=["double", "single"], default="double",
                    help="double = committed tanh(tanh(raw)); single = tanh(raw) only")
    args = ap.parse_args()
    attacks = ATTACKS if args.attacks == "all" else args.attacks.split(",")
    tag = args.tanh

    os.makedirs(OUT_DIR, exist_ok=True)
    summary_path = os.path.join(OUT_DIR, f"ciciot2023_committedEta_{tag}.csv")
    breakdown_path = os.path.join(OUT_DIR, f"ciciot2023_signal_breakdown_{tag}.csv")
    fh = open(summary_path, "w", newline="")
    writer = csv.writer(fh)
    writer.writerow([
        "attack", "model", "TPR", "FPR", "Precision", "F1", "AUC", "EER",
        "n_benign_test", "n_attack", "benignLimit_used",
    ])
    fh.flush()
    bfh = open(breakdown_path, "w", newline="")
    bw = csv.writer(bfh)
    bw.writerow([
        "attack", "tenko_op_TPR", "tenko_op_FPR", "tenko_op_Precision", "tenko_op_F1",
        "tenko_op_degenerate",
        "tenko_AUC_patterndist", "tenko_EER_patterndist",
        "tenko_AUC_nodescore", "tenko_EER_nodescore",
        "tenko_AUC_discreteflag", "tenko_EER_discreteflag",
        "kitsune_AUC", "kitsune_EER",
    ])
    bfh.flush()

    t_all = time.time()
    for a in attacks:
        run_attack(a, writer, fh, breakdown_writer=bw, use_cached_rmse=args.use_cached_rmse,
                   tanh_mode=args.tanh, tag=tag)
        bfh.flush()
    fh.close(); bfh.close()
    print(f"\nALL ATTACKS DONE in {time.time()-t_all:.1f}s -> {summary_path}")


if __name__ == "__main__":
    main()
