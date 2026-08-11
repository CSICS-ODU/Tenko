#!/usr/bin/env python3
"""Export explicit CSVs behind the CICIoT2023 figures (reviewer R1.7).

Reviewers asked whether Figures (RMSE timelines, ROC) came from execution logs or
were hand-curated, and requested the raw CSV / plotting scripts. The figures are
produced programmatically by plot_cic_rmse.py / plot_cic_roc.py / mixed/plot_mixed_rmse.py
from cached per-packet score arrays. This script exports the underlying numbers of
those figures to CSV so every figure has a committed data table, not just a script.

Outputs (under results/CICIoT2023/figs/data/):
  rmse_timeline_<attack>.csv     per-packet (stride-downsampled) score timeline:
                                 packet_index, label, kitsune_tanh_rmse, tenko_node_score
  rmse_thresholds.csv            benign Median+MAD threshold per detector/attack
  roc_points_<stream>.csv        ROC curve points (fpr, tpr, threshold) per detector
  roc_summary.csv                AUC per detector/stream (matches the metric CSVs)

Everything is recomputed from committed .npy arrays; no PCAP/TSV or model re-run.

Run:
  .venv/bin/python results/CICIoT2023/export_figure_data.py
"""
from __future__ import annotations

import csv
import os

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

HERE = os.path.dirname(os.path.abspath(__file__))
MIX = os.path.join(HERE, "mixed")
DATA = os.path.join(HERE, "figs", "data")

# Per-attack held-out test stream layout (stream_counts.csv): 30k benign_test + 50k attack.
N_TEST = 30000
MAD_K = 3.0

# Attacks shown in the RMSE timeline figures (plot_cic_rmse.py default set).
RMSE_ATTACKS = ["DoS-SYN_Flood", "MITM-ArpSpoofing"]
DOWNSAMPLE = 10  # matches plot_cic_rmse.py --downsample default


def mad_threshold(x, k=MAD_K):
    med = float(np.median(x))
    mad = float(np.median(np.abs(x - med)))
    return med + k * 1.4826 * mad


def export_rmse_timelines():
    thr_rows = []
    for attack in RMSE_ATTACKS:
        kit = np.load(os.path.join(HERE, f"arr_kitsune_{attack}.npy"))
        node = np.load(os.path.join(HERE, f"arr_node_{attack}_double.npy"))
        gold = np.load(os.path.join(HERE, f"arr_gold_{attack}.npy"))
        assert len(kit) == len(node) == len(gold)

        thr_kit = mad_threshold(kit[:N_TEST])
        thr_node = mad_threshold(node[:N_TEST])
        thr_rows.append([attack, "kitsune", "tanh(RMSE)", f"{thr_kit:.6f}"])
        thr_rows.append([attack, "tenko", "node_score_S(n)", f"{thr_node:.6f}"])

        idx = np.arange(len(kit))[::DOWNSAMPLE]
        out = os.path.join(DATA, f"rmse_timeline_{attack}.csv")
        with open(out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["packet_index", "label", "kitsune_tanh_rmse", "tenko_node_score"])
            for i in idx:
                w.writerow([int(i), int(gold[i]),
                            f"{kit[i]:.6f}", f"{node[i]:.6f}"])
        print(f"wrote {os.path.relpath(out, HERE)}  ({len(idx)} rows, stride {DOWNSAMPLE})")

    thr_out = os.path.join(DATA, "rmse_thresholds.csv")
    with open(thr_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "detector", "score", "benign_median_mad_threshold"])
        w.writerows(thr_rows)
    print(f"wrote {os.path.relpath(thr_out, HERE)}")


def _roc_csv(name, y, score, downsample=50):
    fpr, tpr, thr = roc_curve(y, score)
    # roc_curve can return tens of thousands of points; stride-downsample but always
    # keep the first and last so the curve endpoints are exact.
    keep = sorted(set(list(range(0, len(fpr), downsample)) + [len(fpr) - 1]))
    out = os.path.join(DATA, f"roc_points_{name}.csv")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["fpr", "tpr", "threshold"])
        for i in keep:
            t = thr[i]
            w.writerow([f"{fpr[i]:.6f}", f"{tpr[i]:.6f}",
                        ("inf" if np.isinf(t) else f"{t:.6f}")])
    return roc_auc_score(y, score), len(keep), out


def export_roc():
    summary = []

    # Mixed stream: Tenko fused continuous score vs Kitsune tanh(RMSE).
    y = np.load(os.path.join(MIX, "arr_gold_mixed.npy")).astype(int)
    cont = np.load(os.path.join(MIX, "arr_cont_mixed.npy"))
    kit = np.load(os.path.join(MIX, "kitsune_testscores_mixed.npy"))
    for name, score in [("mixed_tenko", cont), ("mixed_kitsune", kit)]:
        auc, npts, out = _roc_csv(name, y, score)
        summary.append(["mixed", name.split("_")[1], f"{auc:.6f}", npts])
        print(f"wrote {os.path.relpath(out, HERE)}  (AUC={auc:.4f}, {npts} pts)")

    # MITM per-attack "clear win" ROC (plot_cic_roc.py figure).
    a = "MITM-ArpSpoofing"
    ga = np.load(os.path.join(HERE, f"arr_gold_{a}.npy")).astype(int)
    ca = np.load(os.path.join(HERE, f"arr_cont_{a}_double.npy"))
    ka = np.load(os.path.join(HERE, f"arr_kitsune_{a}.npy"))
    for name, score in [(f"{a}_tenko", ca), (f"{a}_kitsune", ka)]:
        auc, npts, out = _roc_csv(name, ga, score)
        summary.append([a, name.split("_")[-1], f"{auc:.6f}", npts])
        print(f"wrote {os.path.relpath(out, HERE)}  (AUC={auc:.4f}, {npts} pts)")

    sout = os.path.join(DATA, "roc_summary.csv")
    with open(sout, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["stream", "detector", "auc_roc", "n_curve_points"])
        w.writerows(summary)
    print(f"wrote {os.path.relpath(sout, HERE)}")


def main():
    os.makedirs(DATA, exist_ok=True)
    export_rmse_timelines()
    export_roc()


if __name__ == "__main__":
    main()
