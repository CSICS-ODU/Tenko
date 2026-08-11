#!/usr/bin/env python3
"""Export RMSE score timelines to CSV and regenerate plots from those CSVs.

Reads committed .npy score arrays (no PCAP re-run). Writes:
  figs/data/rmse_timeline_<attack>.csv
  figs/data/rmse_timeline_mixed.csv
  figs/data/rmse_thresholds.csv
then plots from the CSVs into figs/.

  python results/CICIoT2023/figs/plot_rmse_from_csv.py
"""
from __future__ import annotations

import csv
import os

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

HERE = os.path.dirname(os.path.abspath(__file__))
CIC = os.path.dirname(HERE)
MIX = os.path.join(CIC, "mixed")
DATA = os.path.join(HERE, "data")

N_TEST = 30000
MAD_K = 3.0
DOWNSAMPLE_ATTACK = 10
RMSE_ATTACKS = ["DoS-SYN_Flood", "MITM-ArpSpoofing"]

# Mixed-stream layout (matches mixed/plot_mixed_rmse.py).
CALIB_END = 60000
BENIGN_TEST_END = 120000
N_TOTAL = 420000
DOWNSAMPLE_MIXED = 15
KIT_THR = 0.009577977360449396

BENIGN_COLOR = "#2c6fbb"
ATTACK_COLOR = "#d1442f"


def mad_threshold(x, k=MAD_K):
    med = float(np.median(x))
    mad = float(np.median(np.abs(x - med)))
    return med + k * 1.4826 * mad


def export_attack_csvs():
    thr_rows = []
    for attack in RMSE_ATTACKS:
        kit = np.load(os.path.join(CIC, f"arr_kitsune_{attack}.npy"))
        node = np.load(os.path.join(CIC, f"arr_node_{attack}_double.npy"))
        gold = np.load(os.path.join(CIC, f"arr_gold_{attack}.npy"))
        assert len(kit) == len(node) == len(gold)

        thr_kit = mad_threshold(kit[:N_TEST])
        thr_node = mad_threshold(node[:N_TEST])
        thr_rows.append([attack, "kitsune", "tanh(RMSE)", f"{thr_kit:.6f}"])
        thr_rows.append([attack, "tenko", "node_score_S(n)", f"{thr_node:.6f}"])

        idx = np.arange(len(kit))[::DOWNSAMPLE_ATTACK]
        out = os.path.join(DATA, f"rmse_timeline_{attack}.csv")
        with open(out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["packet_index", "label", "kitsune_tanh_rmse", "tenko_node_score"])
            for i in idx:
                w.writerow([int(i), int(gold[i]), f"{kit[i]:.6f}", f"{node[i]:.6f}"])
        print(f"wrote {out} ({len(idx)} rows)")

    thr_out = os.path.join(DATA, "rmse_thresholds.csv")
    with open(thr_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "detector", "score", "benign_median_mad_threshold"])
        w.writerows(thr_rows)
    print(f"wrote {thr_out}")
    return {r[0]: {r[1]: float(r[3])} for r in thr_rows}


def export_mixed_csv():
    raw = np.load(os.path.join(MIX, "rmse_raw_mixed.npy"))
    cont = np.load(os.path.join(MIX, "arr_cont_mixed.npy"))
    ndg = np.load(os.path.join(MIX, "arr_ndg_mixed.npy"))
    nds = np.load(os.path.join(MIX, "arr_nds_mixed.npy"))
    gold = np.load(os.path.join(MIX, "arr_gold_mixed.npy"))
    assert raw.shape[0] == N_TOTAL
    assert cont.shape[0] == N_TOTAL - CALIB_END

    kit = np.tanh(raw)
    out = os.path.join(DATA, "rmse_timeline_mixed.csv")
    idx = np.arange(N_TOTAL)[::DOWNSAMPLE_MIXED]
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "stream_index", "label", "kitsune_tanh_rmse",
            "tenko_fused", "tenko_nd_g", "tenko_nd_s",
        ])
        for i in idx:
            label = 1 if i >= BENIGN_TEST_END else 0
            if i >= CALIB_END:
                j = i - CALIB_END
                # Prefer array gold in the scored region.
                label = int(gold[j])
                row = [
                    int(i), label, f"{kit[i]:.6f}",
                    f"{cont[j]:.6f}", f"{ndg[j]:.6f}", f"{nds[j]:.6f}",
                ]
            else:
                row = [int(i), label, f"{kit[i]:.6f}", "", "", ""]
            w.writerow(row)
    print(f"wrote {out} ({len(idx)} rows)")
    return out


def _load_attack_csv(attack):
    path = os.path.join(DATA, f"rmse_timeline_{attack}.csv")
    idx, lab, kit, node = [], [], [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            idx.append(int(row["packet_index"]))
            lab.append(int(row["label"]))
            kit.append(float(row["kitsune_tanh_rmse"]))
            node.append(float(row["tenko_node_score"]))
    return (
        np.asarray(idx), np.asarray(lab),
        np.asarray(kit), np.asarray(node),
    )


def _load_thresholds():
    thr = {}
    with open(os.path.join(DATA, "rmse_thresholds.csv"), newline="") as f:
        for row in csv.DictReader(f):
            thr[(row["attack"], row["detector"])] = float(row["benign_median_mad_threshold"])
    return thr


def plot_attack_from_csv(attack, thr):
    idx, lab, kit, node = _load_attack_csv(attack)
    series = [
        ("kitsune", kit, thr[(attack, "kitsune")], r"Anomaly score  $\tanh(\mathrm{RMSE})$"),
        ("tenko", node, thr[(attack, "tenko")], r"Node anomaly score  $S(n)$"),
    ]
    outs = []
    for name, y, threshold, ylabel in series:
        fig, ax = plt.subplots(figsize=(7.2, 3.3))
        ben = lab == 0
        att = lab == 1
        ax.scatter(idx[ben], np.clip(y[ben], 1e-6, None), s=2.2, c=BENIGN_COLOR,
                   alpha=0.55, linewidths=0, rasterized=True)
        ax.scatter(idx[att], np.clip(y[att], 1e-6, None), s=2.2, c=ATTACK_COLOR,
                   alpha=0.55, linewidths=0, rasterized=True)
        ax.axhline(threshold, color="#111111", ls="--", lw=1.3)
        ax.axvline(N_TEST, color="#555555", ls=":", lw=1.3)
        ax.set_yscale("log")
        ax.set_ylim(8e-4, 1.4)
        ax.set_xlabel("Packet index (held-out test stream)")
        ax.set_ylabel(ylabel)
        ax.set_title(f"{name} — {attack} (from CSV)")
        ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.5)
        ax.legend(handles=[
            Line2D([0], [0], marker="o", color="none", markerfacecolor=BENIGN_COLOR,
                   markersize=5, label="benign"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor=ATTACK_COLOR,
                   markersize=5, label="attack"),
            Line2D([0], [0], color="#111111", ls="--", lw=1.3,
                   label=f"thr={threshold:.4f}"),
        ], loc="lower right", framealpha=0.92)
        fig.tight_layout()
        base = os.path.join(HERE, f"cic_{name}_rmse_{attack}_from_csv")
        for ext in (".png", ".pdf"):
            fig.savefig(base + ext, dpi=300 if ext == ".png" else None, bbox_inches="tight")
        plt.close(fig)
        outs.append(base + ".png")
        print(f"wrote {base}.png")
    return outs


def plot_mixed_from_csv():
    path = os.path.join(DATA, "rmse_timeline_mixed.csv")
    idx, lab, kit, fused = [], [], [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            i = int(row["stream_index"])
            idx.append(i)
            lab.append(int(row["label"]))
            kit.append(float(row["kitsune_tanh_rmse"]))
            fused.append(float(row["tenko_fused"]) if row["tenko_fused"] else np.nan)
    idx = np.asarray(idx)
    lab = np.asarray(lab)
    kit = np.asarray(kit)
    fused = np.asarray(fused)

    fig, (axk, axt) = plt.subplots(2, 1, figsize=(11.0, 6.6), sharex=True,
                                   gridspec_kw={"hspace": 0.18})
    for ax, y, ylabel, thr, thr_label, start_mask in (
        (axk, kit, r"Kitsune $\tanh(\mathrm{RMSE})$", KIT_THR, f"Kitsune thr={KIT_THR:.4f}",
         np.ones(len(idx), dtype=bool)),
        (axt, fused, r"Tenko fused $\frac{1}{2}nd_g+\frac{1}{2}nd_s$", None, None,
         ~np.isnan(fused)),
    ):
        xs = idx[start_mask]
        ys = np.clip(y[start_mask], 1e-3 if ax is axk else 1e-2, None)
        ls = lab[start_mask].astype(bool)
        ax.axvline(CALIB_END, color="#1b6b3a", ls="-.", lw=1.2, alpha=0.9)
        ax.axvline(BENIGN_TEST_END, color="#000000", ls=":", lw=1.6)
        ax.scatter(xs[~ls], ys[~ls], s=1.6, c="#009E73", alpha=0.35,
                   linewidths=0, rasterized=True)
        ax.scatter(xs[ls], ys[ls], s=1.6, c="#D55E00", alpha=0.35,
                   linewidths=0, rasterized=True)
        if thr is not None:
            ax.axhline(thr, color="#D55E00", ls="--", lw=1.4)
        ax.set_yscale("log")
        ax.set_xlim(0, N_TOTAL)
        ax.set_ylabel(ylabel)
        ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
        handles = [
            Line2D([0], [0], marker="o", color="none", markerfacecolor="#009E73",
                   markersize=5, label="benign"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor="#D55E00",
                   markersize=5, label="attack"),
        ]
        if thr is not None:
            handles.append(Line2D([0], [0], color="#D55E00", ls="--", lw=1.4, label=thr_label))
        ax.legend(handles=handles, loc="lower left", framealpha=0.92)

    axt.set_xlabel("Stream packet index")
    axk.set_title("Kitsune — CICIoT2023 mixed (from CSV)")
    axt.set_title("Tenko fused — CICIoT2023 mixed (from CSV)")
    fig.suptitle("CICIoT2023 mixed-stream RMSE / anomaly scores (CSV)", y=0.995)
    base = os.path.join(HERE, "mixed_rmse_from_csv")
    fig.savefig(base + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(base + ".pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {base}.png")
    return base + ".png"


def main():
    os.makedirs(DATA, exist_ok=True)
    export_attack_csvs()
    export_mixed_csv()
    thr = _load_thresholds()
    for attack in RMSE_ATTACKS:
        plot_attack_from_csv(attack, thr)
    plot_mixed_from_csv()


if __name__ == "__main__":
    main()
