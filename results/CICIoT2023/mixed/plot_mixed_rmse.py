#!/usr/bin/env python3
"""Annotated anomaly-score-over-time ("RMSE") timeline for the CICIoT2023 combined
MIXED stream — Kitsune (top) vs Tenko (bottom).

Single-tanh configuration on the reduced/rationalized benign split, committed operating
point eta_global=50 / eta_node=20, benignLimit=60000.

Full-stream protocol (stream packet index 0..420000):
  * KitNET feature-map grace ...... [0     : 5000]
  * KitNET anomaly-detector grace .. [5000  : 55000]   (=> 55k total KitNET training)
  * Tenko pattern-model calibration  [55000 : 60000]   (=> benign training limit @ 60000)
  * benign test .................... [60000 : 120000]
  * attack blocks .................. [120000: 420000]   (6 blocks, see attack_blocks.csv)

"Single-tanh" means the RAW KitNET RMSE was fed to Tenko so Tenko's internal tanh is the
only normalization; the Kitsune baseline score is tanh(raw RMSE).

This script RE-RUNS NOTHING. It only loads the cached arrays saved by the completed mixed
run and plots them:
  * rmse_raw_mixed.npy         RAW KitNET RMSE, FULL stream (len 420000, index==stream idx)
  * kitsune_testscores_mixed.npy tanh(raw) for the test region [60000:420000] (cross-check)
  * arr_cont_mixed.npy         Tenko fused score 0.5*nd_g+0.5*nd_s, test region (len 360000)
  * arr_ndg_mixed.npy          Tenko global-channel normalized deviation, test region
  * arr_nds_mixed.npy          Tenko node-channel normalized deviation, test region
  * arr_gold_mixed.npy         0/1 labels for the test region (len 360000)
  * attack_blocks.csv          exact stream-index boundaries of each attack block

Kitsune threshold (from mixed_summary.json): thr = median + 3*1.4826*MAD calibrated on the
benign calibration slice [55001:60000]; thr = 0.009577977360449396.

The Tenko committed decision is (nd_g > eta_global) OR (nd_s > eta_node) = (nd_g>50)|(nd_s>20).
Tenko has no score before stream index 60000 (calibration), so its traces start at x=60000.
"""
from __future__ import annotations

import csv
import os

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

# ------------------------------------------------------------------------------------- paths
HERE = os.path.dirname(os.path.abspath(__file__))                 # results/CICIoT2023/mixed
CIC = os.path.dirname(HERE)                                       # results/CICIoT2023
FIGS = os.path.join(CIC, "figs")

# ------------------------------------------------------------------- protocol / region layout
FM_GRACE_END = 5000        # KitNET feature-map grace  [0:5000]
AD_GRACE_END = 55000       # KitNET anomaly-detector grace ends -> 55k KitNET training total
CALIB_END = 60000          # Tenko pattern-model calibration ends == benign training limit
BENIGN_TEST_END = 120000   # benign test ends / first attack onset
N_TOTAL = 420000           # full mixed stream length
N_TEST = N_TOTAL - CALIB_END  # 360000

# Kitsune Median+MAD threshold (committed, from mixed_summary.json).
KIT_THR = 0.009577977360449396
KIT_MED = 0.004223319748494231
KIT_MAD = 0.0012038890264749235

# Tenko committed decision thresholds.
ETA_GLOBAL = 50.0
ETA_NODE = 20.0

# --------------------------------------------------------------------- colorblind-safe palette
# Okabe-Ito.
C_BENIGN = "#0072B2"   # blue
C_ATTACK = "#D55E00"   # vermillion
C_NDG = "#009E73"      # bluish green (global channel)
C_NDS = "#CC79A7"      # reddish purple (node channel)
C_THR = "#D55E00"      # threshold lines (red/vermillion, dashed)
C_ONSET = "#000000"    # attack onset
SH_TRAIN = "#F0E442"   # training band (yellow)
SH_CALIB = "#E69F00"   # calibration band (orange)
SH_BENIGN = "#56B4E9"  # benign-test band (sky)
SH_ATTACK = "#D55E00"  # attack band (vermillion)

PRETTY = {
    "DoS-SYN_Flood": "DoS SYN Flood",
    "DDoS-UDP_Flood": "DDoS UDP Flood",
    "Recon-OSScan": "Recon OS-Scan",
    "MITM-ArpSpoofing": "MITM ARP Spoof",
    "Mirai-greeth_flood": "Mirai greeth",
    "DictionaryBruteForce": "Dict. BruteForce",
}

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "legend.fontsize": 8.0,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "figure.dpi": 120,
})


def load_arrays():
    raw = np.load(os.path.join(HERE, "rmse_raw_mixed.npy"))
    kts = np.load(os.path.join(HERE, "kitsune_testscores_mixed.npy"))
    cont = np.load(os.path.join(HERE, "arr_cont_mixed.npy"))
    ndg = np.load(os.path.join(HERE, "arr_ndg_mixed.npy"))
    nds = np.load(os.path.join(HERE, "arr_nds_mixed.npy"))
    gold = np.load(os.path.join(HERE, "arr_gold_mixed.npy"))
    # Length invariants (fail loudly if the cache is inconsistent).
    assert raw.shape[0] == N_TOTAL, f"rmse_raw len {raw.shape[0]} != {N_TOTAL}"
    for name, a in (("kitsune_testscores", kts), ("arr_cont", cont),
                    ("arr_ndg", ndg), ("arr_nds", nds), ("arr_gold", gold)):
        assert a.shape[0] == N_TEST, f"{name} len {a.shape[0]} != {N_TEST}"
    # Single-tanh cross-check: tanh(raw[60000:]) must equal cached Kitsune test scores.
    dif = float(np.max(np.abs(np.tanh(raw[CALIB_END:]) - kts)))
    assert dif < 1e-9, f"tanh(raw) vs kitsune_testscores mismatch {dif}"
    return raw, kts, cont, ndg, nds, gold


def load_blocks():
    blocks = []
    with open(os.path.join(HERE, "attack_blocks.csv"), newline="") as fh:
        for row in csv.DictReader(fh):
            blocks.append((row["attack"], int(row["start_idx"]), int(row["end_idx"])))
    # Verify layout matches the expected onset at 120000 and 6 contiguous 50k blocks.
    assert blocks[0][1] == BENIGN_TEST_END, f"first block start {blocks[0][1]} != {BENIGN_TEST_END}"
    assert blocks[-1][2] == N_TOTAL, f"last block end {blocks[-1][2]} != {N_TOTAL}"
    for i in range(1, len(blocks)):
        assert blocks[i][1] == blocks[i - 1][2], "attack blocks are not contiguous"
    return blocks


def shade_regions(ax, blocks, ymax_frac=0.985, label_attacks=True, ymin_for_lines=None):
    """Draw the protocol region bands + boundary lines shared by both panels."""
    # Training / calibration / benign-test / attack bands.
    ax.axvspan(0, AD_GRACE_END, color=SH_TRAIN, alpha=0.16, zorder=0)
    ax.axvspan(AD_GRACE_END, CALIB_END, color=SH_CALIB, alpha=0.22, zorder=0)
    ax.axvspan(CALIB_END, BENIGN_TEST_END, color=SH_BENIGN, alpha=0.12, zorder=0)
    ax.axvspan(BENIGN_TEST_END, N_TOTAL, color=SH_ATTACK, alpha=0.06, zorder=0)

    # Internal training divider: FM-grace | AD-grace.
    ax.axvline(FM_GRACE_END, color="#8a7d00", ls=(0, (1, 2)), lw=0.9, alpha=0.7, zorder=2)
    # KitNET-train end (55k).
    ax.axvline(AD_GRACE_END, color="#8a5a00", ls=(0, (2, 2)), lw=1.0, alpha=0.8, zorder=2)
    # Benign training limit (60k) == Tenko calibration end / start of scored test.
    ax.axvline(CALIB_END, color="#1b6b3a", ls="-.", lw=1.2, alpha=0.9, zorder=3)
    # Attack onset (prominent).
    ax.axvline(BENIGN_TEST_END, color=C_ONSET, ls=":", lw=1.8, alpha=0.95, zorder=4)

    # Attack block dividers + names along the top.
    for name, s, e in blocks:
        ax.axvline(e, color="#7a2f1a", ls=(0, (2, 3)), lw=0.8, alpha=0.55, zorder=2)
        if label_attacks:
            ax.text((s + e) / 2.0, ymax_frac, PRETTY.get(name, name),
                    transform=ax.get_xaxis_transform(), ha="center", va="top",
                    rotation=0, fontsize=6.6, color="#7a2f1a", zorder=6,
                    bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.6))


def region_legend_handles():
    return [
        Patch(facecolor=SH_TRAIN, alpha=0.16, label="KitNET training [0:55k]"),
        Patch(facecolor=SH_CALIB, alpha=0.22, label="Tenko calib. [55k:60k]"),
        Patch(facecolor=SH_BENIGN, alpha=0.12, label="benign test [60k:120k]"),
        Patch(facecolor=SH_ATTACK, alpha=0.10, label="attack [120k:420k]"),
        Line2D([0], [0], color="#1b6b3a", ls="-.", lw=1.2, label="train limit (60k)"),
        Line2D([0], [0], color=C_ONSET, ls=":", lw=1.8, label="attack onset (120k)"),
    ]


def _xticks(ax):
    ticks = np.arange(0, N_TOTAL + 1, 60000)
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{t//1000}k" for t in ticks])


# ------------------------------------------------------------------------ Kitsune panel drawing
def draw_kitsune(ax, raw, blocks, downsample, label_attacks=True):
    ks = np.tanh(raw)                       # full-stream Kitsune score
    floor = 1e-3
    y = np.clip(ks, floor, None)
    x = np.arange(N_TOTAL)

    # benign (stream<120000) vs attack (>=120000) coloring for the scatter.
    xs = x[::downsample]
    ys = y[::downsample]
    is_attack = xs >= BENIGN_TEST_END
    shade_regions(ax, blocks, label_attacks=label_attacks)

    ax.scatter(xs[~is_attack], ys[~is_attack], s=1.6, c=C_BENIGN, alpha=0.35,
               linewidths=0, rasterized=True, zorder=3)
    ax.scatter(xs[is_attack], ys[is_attack], s=1.6, c=C_ATTACK, alpha=0.35,
               linewidths=0, rasterized=True, zorder=3)
    ax.axhline(KIT_THR, color=C_THR, ls="--", lw=1.4, zorder=5)

    ax.set_yscale("log")
    ax.set_ylim(floor, 1.6)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Kitsune score  $\tanh(\mathrm{RMSE})$")
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)

    handles = [
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_BENIGN,
               markersize=5, label="benign packets"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_ATTACK,
               markersize=5, label="attack packets"),
        Line2D([0], [0], color=C_THR, ls="--", lw=1.4,
               label=f"Kitsune Median+MAD threshold = {KIT_THR:.4f}"),
    ]
    ax.legend(handles=handles, loc="lower left", framealpha=0.92, ncol=1,
              handletextpad=0.5, borderpad=0.4)


# -------------------------------------------------------------------------- Tenko panel drawing
def draw_tenko(ax, ndg, nds, downsample, blocks, label_attacks=False):
    """Bottom panel, option (a): the two decision channels nd_g, nd_s with their eta lines."""
    floor = 1e-2
    x = np.arange(CALIB_END, N_TOTAL)       # Tenko scored from 60000
    yg = np.clip(ndg, floor, None)
    ysd = np.clip(nds, floor, None)

    xs = x[::downsample]
    yg_s = yg[::downsample]
    ysd_s = ysd[::downsample]

    shade_regions(ax, blocks, label_attacks=label_attacks)

    ax.scatter(xs, yg_s, s=1.6, c=C_NDG, alpha=0.35, linewidths=0,
               rasterized=True, zorder=3, label=r"$nd_g$ (global)")
    ax.scatter(xs, ysd_s, s=1.6, c=C_NDS, alpha=0.35, linewidths=0,
               rasterized=True, zorder=3, label=r"$nd_s$ (node)")
    ax.axhline(ETA_GLOBAL, color=C_NDG, ls="--", lw=1.4, zorder=5)
    ax.axhline(ETA_NODE, color=C_NDS, ls="--", lw=1.4, zorder=5)

    ax.set_yscale("log")
    ax.set_ylim(floor, 1.2e3)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Tenko normalized deviation")
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)

    handles = [
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_NDG,
               markersize=5, label=r"$nd_g$ (global channel)"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_NDS,
               markersize=5, label=r"$nd_s$ (node channel)"),
        Line2D([0], [0], color=C_NDG, ls="--", lw=1.4,
               label=r"$\eta_\mathrm{global}=50$"),
        Line2D([0], [0], color=C_NDS, ls="--", lw=1.4,
               label=r"$\eta_\mathrm{node}=20$"),
    ]
    ax.legend(handles=handles, loc="lower left", framealpha=0.92, ncol=2,
              handletextpad=0.5, borderpad=0.4, columnspacing=1.0)
    ax.text(0.5 * (CALIB_END) / N_TOTAL, 0.5, "no Tenko score\n(calibration)",
            transform=ax.transAxes, ha="center", va="center", fontsize=6.8,
            color="#555555", zorder=6)


def two_panel(raw, ndg, nds, blocks, downsample=15):
    fig, (axk, axt) = plt.subplots(2, 1, figsize=(11.0, 6.6), sharex=True,
                                   gridspec_kw={"hspace": 0.10})
    draw_kitsune(axk, raw, blocks, downsample, label_attacks=True)
    draw_tenko(axt, ndg, nds, downsample, blocks, label_attacks=False)

    # Shared region legend on the Kitsune axis (upper area), decision legends stay per-panel.
    reg_leg = axk.legend(handles=region_legend_handles(), loc="upper right",
                         framealpha=0.9, ncol=3, fontsize=7.0, handletextpad=0.5,
                         columnspacing=1.0, borderpad=0.4, title="protocol regions")
    reg_leg.get_title().set_fontsize(7.5)
    axk.add_artist(reg_leg)
    # Re-add the Kitsune detector legend (was replaced by region legend call).
    axk.legend(handles=[
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_BENIGN,
               markersize=5, label="benign packets"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_ATTACK,
               markersize=5, label="attack packets"),
        Line2D([0], [0], color=C_THR, ls="--", lw=1.4,
               label=f"Kitsune threshold = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.92, handletextpad=0.5, borderpad=0.4)

    fig.suptitle("CICIoT2023 combined stream — single-tanh, benignLimit=60000, "
                 r"committed $\eta=50/20$", y=0.985, fontsize=13)
    axk.set_title("Kitsune (per-packet RMSE anomaly score)", fontsize=10.5, loc="left")
    axt.set_title("Tenko (per-packet decision channels; flag if "
                  r"$nd_g>50$ OR $nd_s>20$)", fontsize=10.5, loc="left")

    fig.text(0.012, 0.012, f"every {downsample}\u1d57\u02b0 packet shown (scatter, rasterized)",
             fontsize=7, color="#666666")

    base = os.path.join(FIGS, "mixed_rmse_tenko_kitsune")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf


def kitsune_single(raw, blocks, downsample=15):
    fig, ax = plt.subplots(figsize=(11.0, 3.6))
    draw_kitsune(ax, raw, blocks, downsample, label_attacks=True)
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.legend(handles=region_legend_handles(), loc="upper right", framealpha=0.9,
              ncol=3, fontsize=6.8, borderpad=0.4)
    # keep detector legend too
    ax.add_artist(ax.legend(handles=[
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_BENIGN,
               markersize=5, label="benign packets"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_ATTACK,
               markersize=5, label="attack packets"),
        Line2D([0], [0], color=C_THR, ls="--", lw=1.4,
               label=f"Kitsune threshold = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.92))
    ax.set_title("Kitsune anomaly score — CICIoT2023 mixed stream (single-tanh)",
                 fontsize=11, loc="left")
    base = os.path.join(FIGS, "mixed_rmse_kitsune")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf


def tenko_single(cont, ndg, nds, blocks, downsample=15):
    """Single-panel Tenko variant, option (b): fused cont score + flagged shading."""
    fig, ax = plt.subplots(figsize=(11.0, 3.6))
    floor = 1e-2
    x = np.arange(CALIB_END, N_TOTAL)
    y = np.clip(cont, floor, None)
    flag = (ndg > ETA_GLOBAL) | (nds > ETA_NODE)

    shade_regions(ax, blocks, label_attacks=True)
    xs = x[::downsample]
    ys = y[::downsample]
    fs = flag[::downsample]
    ax.scatter(xs[~fs], ys[~fs], s=1.6, c=C_BENIGN, alpha=0.30, linewidths=0,
               rasterized=True, zorder=3)
    ax.scatter(xs[fs], ys[fs], s=1.8, c=C_ATTACK, alpha=0.45, linewidths=0,
               rasterized=True, zorder=4)

    ax.set_yscale("log")
    ax.set_ylim(floor, 5e2)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Tenko fused score  $\frac{1}{2}nd_g+\frac{1}{2}nd_s$")
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
    ax.legend(handles=[
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_BENIGN,
               markersize=5, label="not flagged"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_ATTACK,
               markersize=5, label=r"flagged: $nd_g>50$ OR $nd_s>20$"),
    ], loc="lower left", framealpha=0.92)
    ax.set_title("Tenko fused anomaly score — CICIoT2023 mixed stream (committed "
                 r"$\eta=50/20$)", fontsize=11, loc="left")
    base = os.path.join(FIGS, "mixed_rmse_tenko")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf


# ------------------------------------------------------ label-colored variant (benign/attack)
# Colorblind-safe green/red (Okabe-Ito bluish-green + vermillion).
C_LBL_BENIGN = "#009E73"   # benign -> green
C_LBL_ATTACK = "#D55E00"   # attack -> red


def _label_legend_handles():
    return [
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_LBL_BENIGN,
               markersize=6, label="Benign"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_LBL_ATTACK,
               markersize=6, label="Attack"),
    ]


def draw_kitsune_labelcolored(ax, raw, blocks, downsample, label_attacks=True):
    """Kitsune panel, points colored by GROUND-TRUTH label.

    Full-stream label: [0:120000] benign (green) -> training/calib/benign-test are all benign;
    [120000:420000] attack (red) -> the six attack blocks.
    """
    ks = np.tanh(raw)
    floor = 1e-3
    y = np.clip(ks, floor, None)
    x = np.arange(N_TOTAL)
    lbl = np.zeros(N_TOTAL, dtype=bool)          # False=benign, True=attack
    lbl[BENIGN_TEST_END:] = True

    xs = x[::downsample]
    ys = y[::downsample]
    ls = lbl[::downsample]

    shade_regions(ax, blocks, label_attacks=label_attacks)
    ax.scatter(xs[~ls], ys[~ls], s=1.6, c=C_LBL_BENIGN, alpha=0.35,
               linewidths=0, rasterized=True, zorder=3)
    ax.scatter(xs[ls], ys[ls], s=1.6, c=C_LBL_ATTACK, alpha=0.35,
               linewidths=0, rasterized=True, zorder=3)
    ax.axhline(KIT_THR, color=C_THR, ls="--", lw=1.4, zorder=5)

    ax.set_yscale("log")
    ax.set_ylim(floor, 1.6)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Kitsune score  $\tanh(\mathrm{RMSE})$")
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
    ax.legend(handles=_label_legend_handles() + [
        Line2D([0], [0], color=C_THR, ls="--", lw=1.4,
               label=f"Kitsune threshold = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.92, handletextpad=0.5, borderpad=0.4)


def draw_tenko_labelcolored(ax, cont, gold, blocks, downsample, label_attacks=False):
    """Tenko panel, fused score arr_cont colored by GROUND-TRUTH label (arr_gold_mixed).

    Test region only (x starts at 60000): gold [0:60000]=benign (stream[60k:120k]),
    gold[60000:]=attack (stream[120k:420k]).
    """
    floor = 1e-2
    x = np.arange(CALIB_END, N_TOTAL)
    y = np.clip(cont, floor, None)
    is_attack = gold.astype(bool)

    xs = x[::downsample]
    ys = y[::downsample]
    ls = is_attack[::downsample]

    shade_regions(ax, blocks, label_attacks=label_attacks)
    ax.scatter(xs[~ls], ys[~ls], s=1.6, c=C_LBL_BENIGN, alpha=0.35,
               linewidths=0, rasterized=True, zorder=3)
    ax.scatter(xs[ls], ys[ls], s=1.6, c=C_LBL_ATTACK, alpha=0.35,
               linewidths=0, rasterized=True, zorder=3)
    # eta reference lines (channel thresholds; shown on the fused nd scale for reference).
    ax.axhline(ETA_GLOBAL, color="#555555", ls="--", lw=1.1, alpha=0.8, zorder=5)
    ax.axhline(ETA_NODE, color="#999999", ls=(0, (4, 2)), lw=1.1, alpha=0.8, zorder=5)

    ax.set_yscale("log")
    ax.set_ylim(floor, 5e2)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Tenko fused score  $\frac{1}{2}nd_g+\frac{1}{2}nd_s$")
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
    ax.legend(handles=_label_legend_handles() + [
        Line2D([0], [0], color="#555555", ls="--", lw=1.1,
               label=r"$\eta_\mathrm{global}=50$ (ref.)"),
        Line2D([0], [0], color="#999999", ls=(0, (4, 2)), lw=1.1,
               label=r"$\eta_\mathrm{node}=20$ (ref.)"),
    ], loc="lower left", framealpha=0.92, ncol=2, handletextpad=0.5,
       borderpad=0.4, columnspacing=1.0)
    ax.text(0.5 * CALIB_END / N_TOTAL, 0.5, "no Tenko score\n(calibration)",
            transform=ax.transAxes, ha="center", va="center", fontsize=6.8,
            color="#555555", zorder=6)


def two_panel_labelcolored(raw, cont, gold, blocks, downsample=15):
    fig, (axk, axt) = plt.subplots(2, 1, figsize=(11.0, 6.6), sharex=True,
                                   gridspec_kw={"hspace": 0.10})
    draw_kitsune_labelcolored(axk, raw, blocks, downsample, label_attacks=True)
    draw_tenko_labelcolored(axt, cont, gold, blocks, downsample, label_attacks=False)

    reg_leg = axk.legend(handles=region_legend_handles(), loc="upper right",
                         framealpha=0.9, ncol=3, fontsize=7.0, handletextpad=0.5,
                         columnspacing=1.0, borderpad=0.4, title="protocol regions")
    reg_leg.get_title().set_fontsize(7.5)
    axk.add_artist(reg_leg)
    axk.legend(handles=_label_legend_handles() + [
        Line2D([0], [0], color=C_THR, ls="--", lw=1.4,
               label=f"Kitsune threshold = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.92, handletextpad=0.5, borderpad=0.4)

    fig.suptitle("CICIoT2023 combined stream (label-colored) — single-tanh, "
                 r"benignLimit=60000, committed $\eta=50/20$", y=0.985, fontsize=13)
    axk.set_title("Kitsune (per-packet RMSE anomaly score) — points colored by ground truth",
                  fontsize=10.5, loc="left")
    axt.set_title("Tenko (fused decision score) — points colored by ground truth",
                  fontsize=10.5, loc="left")
    fig.text(0.012, 0.012, f"every {downsample}\u1d57\u02b0 packet shown (scatter, rasterized)",
             fontsize=7, color="#666666")

    base = os.path.join(FIGS, "mixed_rmse_labelcolored")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf


def kitsune_single_labelcolored(raw, blocks, downsample=15):
    fig, ax = plt.subplots(figsize=(11.0, 3.6))
    draw_kitsune_labelcolored(ax, raw, blocks, downsample, label_attacks=True)
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.add_artist(ax.legend(handles=region_legend_handles(), loc="upper right",
                            framealpha=0.9, ncol=3, fontsize=6.8, borderpad=0.4))
    ax.legend(handles=_label_legend_handles() + [
        Line2D([0], [0], color=C_THR, ls="--", lw=1.4,
               label=f"Kitsune threshold = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.92)
    ax.set_title("Kitsune anomaly score (label-colored) — CICIoT2023 mixed stream",
                 fontsize=11, loc="left")
    base = os.path.join(FIGS, "mixed_rmse_kitsune_labelcolored")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf


def tenko_single_labelcolored(cont, gold, blocks, downsample=15):
    fig, ax = plt.subplots(figsize=(11.0, 3.6))
    draw_tenko_labelcolored(ax, cont, gold, blocks, downsample, label_attacks=True)
    ax.set_title("Tenko fused anomaly score (label-colored) — CICIoT2023 mixed stream",
                 fontsize=11, loc="left")
    base = os.path.join(FIGS, "mixed_rmse_tenko_labelcolored")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf


# ------------------------------------------------------ four-way confusion-colored variant
# Colorblind-safe palette; FP/FN are highlighted (bigger, darker, on top).
C_TN = "#009E73"   # true negative  (benign->benign)  green
C_TP = "#D55E00"   # true positive  (attack->attack)  red
C_FP = "#E69F00"   # false positive (benign->attack)  orange   <- highlight
C_FN = "#0072B2"   # false negative (attack->benign)  blue     <- highlight


def _confusion_masks(pred: np.ndarray, gold: np.ndarray):
    pred = pred.astype(bool)
    gold = gold.astype(bool)
    tn = ~gold & ~pred
    tp = gold & pred
    fp = ~gold & pred
    fn = gold & ~pred
    return tn, tp, fp, fn


def _scatter_confusion(ax, x, y, tn, tp, fp, fn, downsample):
    """Scatter with four confusion colors.

    TP/TN (dense masses) are stride-downsampled; ALL FP and FN points are plotted (they are the
    highlight) with larger, darker, higher-zorder markers so none are dropped by downsampling.
    """
    sl = slice(None, None, downsample)
    # dense correct masses (downsampled, faint, small)
    ax.scatter(x[tn][sl], y[tn][sl], s=1.5, c=C_TN, alpha=0.30, linewidths=0,
               rasterized=True, zorder=2)
    ax.scatter(x[tp][sl], y[tp][sl], s=1.5, c=C_TP, alpha=0.30, linewidths=0,
               rasterized=True, zorder=2)
    # highlighted errors: ALL points, bigger, opaque, on top
    ax.scatter(x[fn], y[fn], s=7.0, c=C_FN, alpha=0.85, linewidths=0,
               rasterized=True, zorder=5)
    ax.scatter(x[fp], y[fp], s=7.0, c=C_FP, alpha=0.90, linewidths=0,
               rasterized=True, zorder=6)


def _confusion_legend_handles(tp, tn, fp, fn):
    return [
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_TN,
               markersize=5, label=f"TN benign\u2192benign ({tn:,})"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_TP,
               markersize=5, label=f"TP attack\u2192attack ({tp:,})"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_FP,
               markersize=7, label=f"FP benign\u2192attack ({fp:,})"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=C_FN,
               markersize=7, label=f"FN attack\u2192benign ({fn:,})"),
    ]


def draw_kitsune_confusion(ax, raw, blocks, downsample, label_attacks=True):
    ks = np.tanh(raw)
    floor = 1e-3
    y = np.clip(ks, floor, None)
    x = np.arange(N_TOTAL)
    gold = np.zeros(N_TOTAL, dtype=bool)
    gold[BENIGN_TEST_END:] = True
    pred = ks > KIT_THR
    tn, tp, fp, fn = _confusion_masks(pred, gold)

    shade_regions(ax, blocks, label_attacks=label_attacks)
    _scatter_confusion(ax, x, y, tn, tp, fp, fn, downsample)
    ax.axhline(KIT_THR, color="#333333", ls="--", lw=1.3, zorder=7)

    ax.set_yscale("log")
    ax.set_ylim(floor, 1.6)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Kitsune score  $\tanh(\mathrm{RMSE})$")
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
    counts = dict(TP=int(tp.sum()), TN=int(tn.sum()), FP=int(fp.sum()), FN=int(fn.sum()))
    ax.legend(handles=_confusion_legend_handles(counts["TP"], counts["TN"],
                                                counts["FP"], counts["FN"]) + [
        Line2D([0], [0], color="#333333", ls="--", lw=1.3,
               label=f"Median+MAD thr = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.93, handletextpad=0.5, borderpad=0.4)
    return counts


def draw_tenko_confusion(ax, cont, pred, gold, blocks, downsample, label_attacks=False):
    floor = 1e-2
    x = np.arange(CALIB_END, N_TOTAL)
    y = np.clip(cont, floor, None)
    tn, tp, fp, fn = _confusion_masks(pred, gold)

    shade_regions(ax, blocks, label_attacks=label_attacks)
    _scatter_confusion(ax, x, y, tn, tp, fp, fn, downsample)
    ax.axhline(ETA_GLOBAL, color="#555555", ls="--", lw=1.0, alpha=0.8, zorder=7)
    ax.axhline(ETA_NODE, color="#999999", ls=(0, (4, 2)), lw=1.0, alpha=0.8, zorder=7)

    ax.set_yscale("log")
    ax.set_ylim(floor, 5e2)
    ax.set_xlim(0, N_TOTAL)
    ax.set_ylabel(r"Tenko fused score  $\frac{1}{2}nd_g+\frac{1}{2}nd_s$")
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.45)
    counts = dict(TP=int(tp.sum()), TN=int(tn.sum()), FP=int(fp.sum()), FN=int(fn.sum()))
    ax.legend(handles=_confusion_legend_handles(counts["TP"], counts["TN"],
                                                counts["FP"], counts["FN"]) + [
        Line2D([0], [0], color="#555555", ls="--", lw=1.0, label=r"$\eta_\mathrm{global}=50$ (ref.)"),
        Line2D([0], [0], color="#999999", ls=(0, (4, 2)), lw=1.0, label=r"$\eta_\mathrm{node}=20$ (ref.)"),
    ], loc="lower left", framealpha=0.93, ncol=1, handletextpad=0.5, borderpad=0.4)
    ax.text(0.5 * CALIB_END / N_TOTAL, 0.5, "no Tenko score\n(calibration)",
            transform=ax.transAxes, ha="center", va="center", fontsize=6.8,
            color="#555555", zorder=8)
    return counts


def two_panel_confusion(raw, cont, pred, gold, blocks, downsample=15):
    fig, (axk, axt) = plt.subplots(2, 1, figsize=(11.0, 6.6), sharex=True,
                                   gridspec_kw={"hspace": 0.10})
    kc = draw_kitsune_confusion(axk, raw, blocks, downsample, label_attacks=True)
    tc = draw_tenko_confusion(axt, cont, pred, gold, blocks, downsample, label_attacks=False)

    reg_leg = axk.legend(handles=region_legend_handles(), loc="upper right",
                         framealpha=0.9, ncol=3, fontsize=7.0, handletextpad=0.5,
                         columnspacing=1.0, borderpad=0.4, title="protocol regions")
    reg_leg.get_title().set_fontsize(7.5)
    axk.add_artist(reg_leg)
    axk.legend(handles=_confusion_legend_handles(kc["TP"], kc["TN"], kc["FP"], kc["FN"]) + [
        Line2D([0], [0], color="#333333", ls="--", lw=1.3,
               label=f"Median+MAD thr = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.93, handletextpad=0.5, borderpad=0.4)

    fig.suptitle("CICIoT2023 combined stream (confusion outcomes) — single-tanh, "
                 r"benignLimit=60000, committed $\eta=50/20$", y=0.985, fontsize=12.5)
    axk.set_title("Kitsune — points colored by confusion class at Median+MAD threshold",
                  fontsize=10.5, loc="left")
    axt.set_title(r"Tenko — points colored by confusion class at committed $\eta=50/20$",
                  fontsize=10.5, loc="left")
    fig.text(0.012, 0.012,
             f"TP/TN downsampled (every {downsample}\u1d57\u02b0); ALL FP & FN plotted "
             f"(highlighted). rasterized.", fontsize=7, color="#666666")

    base = os.path.join(FIGS, "mixed_rmse_confusion")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf, kc, tc


def kitsune_single_confusion(raw, blocks, downsample=15):
    fig, ax = plt.subplots(figsize=(11.0, 3.6))
    kc = draw_kitsune_confusion(ax, raw, blocks, downsample, label_attacks=True)
    ax.set_xlabel("Stream packet index")
    _xticks(ax)
    ax.add_artist(ax.legend(handles=region_legend_handles(), loc="upper right",
                            framealpha=0.9, ncol=3, fontsize=6.8, borderpad=0.4))
    ax.legend(handles=_confusion_legend_handles(kc["TP"], kc["TN"], kc["FP"], kc["FN"]) + [
        Line2D([0], [0], color="#333333", ls="--", lw=1.3,
               label=f"Median+MAD thr = {KIT_THR:.4f}"),
    ], loc="lower left", framealpha=0.93)
    ax.set_title("Kitsune confusion outcomes — CICIoT2023 mixed stream", fontsize=11, loc="left")
    base = os.path.join(FIGS, "mixed_rmse_kitsune_confusion")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf, kc


def tenko_single_confusion(cont, pred, gold, blocks, downsample=15):
    fig, ax = plt.subplots(figsize=(11.0, 3.6))
    tc = draw_tenko_confusion(ax, cont, pred, gold, blocks, downsample, label_attacks=True)
    ax.set_title(r"Tenko confusion outcomes (committed $\eta=50/20$) — CICIoT2023 mixed stream",
                 fontsize=11, loc="left")
    base = os.path.join(FIGS, "mixed_rmse_tenko_confusion")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    return png, pdf, tc


def main():
    os.makedirs(FIGS, exist_ok=True)
    raw, kts, cont, ndg, nds, gold = load_arrays()
    blocks = load_blocks()

    # Reported operating stats (for provenance / console).
    ks_full = np.tanh(raw)
    kit_benign_fpr = float((ks_full[CALIB_END:BENIGN_TEST_END] > KIT_THR).mean())
    flag = (ndg > ETA_GLOBAL) | (nds > ETA_NODE)
    tenko_benign_fpr = float(flag[:BENIGN_TEST_END - CALIB_END].mean())
    tenko_attack_tpr = float(flag[BENIGN_TEST_END - CALIB_END:].mean())

    png2, pdf2 = two_panel(raw, ndg, nds, blocks)
    pngk, pdfk = kitsune_single(raw, blocks)
    pngt, pdft = tenko_single(cont, ndg, nds, blocks)

    # Label-colored variants (benign=green, attack=red).
    pnglc, pdflc = two_panel_labelcolored(raw, cont, gold, blocks)
    pngklc, pdfklc = kitsune_single_labelcolored(raw, blocks)
    pngtlc, pdftlc = tenko_single_labelcolored(cont, gold, blocks)

    # Confusion-colored variants (TP/TN/FP/FN) at the committed operating point.
    pred = np.load(os.path.join(HERE, "arr_pred_mixed.npy"))
    assert pred.shape[0] == N_TEST, f"arr_pred len {pred.shape[0]} != {N_TEST}"
    rule = ((ndg > ETA_GLOBAL) | (nds > ETA_NODE)).astype(pred.dtype)
    assert np.array_equal(pred, rule), "arr_pred_mixed != (nd_g>50)|(nd_s>20)"
    pngcf, pdfcf, kc, tc = two_panel_confusion(raw, cont, pred, gold, blocks)
    pngkcf, pdfkcf, _ = kitsune_single_confusion(raw, blocks)
    pngtcf, pdftcf, _ = tenko_single_confusion(cont, pred, gold, blocks)

    print("Wrote:")
    for p in (png2, pdf2, pngk, pdfk, pngt, pdft,
              pnglc, pdflc, pngklc, pdfklc, pngtlc, pdftlc,
              pngcf, pdfcf, pngkcf, pdfkcf, pngtcf, pdftcf):
        print("  ", p)

    exp = dict(TP=263791, TN=59583, FP=417, FN=36209)
    print(f"Kitsune confusion (full stream): {kc}")
    print(f"Tenko   confusion (test region): {tc}")
    print(f"Tenko   expected               : {exp}  match={tc == exp}")
    print(f"Kitsune benign-test FPR (>thr): {kit_benign_fpr:.4f}")
    print(f"Tenko  benign-test flag rate  : {tenko_benign_fpr:.4f}")
    print(f"Tenko  attack flag rate (TPR) : {tenko_attack_tpr:.4f}")
    print("attack blocks:", blocks)


if __name__ == "__main__":
    main()
