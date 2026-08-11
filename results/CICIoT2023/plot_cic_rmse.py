#!/usr/bin/env python3
"""Kitsune-style RMSE / anomaly-score timeline plots for CICIoT2023.

Produces the paper's Fig-4 / Fig-5 analogues:

  * Fig-4 analogue  (Kitsune) : per-packet reconstruction anomaly score = tanh(RMSE),
                                the X1/KitNET output. Source array: arr_kitsune_<attack>.npy
  * Fig-5 analogue  (Tenko)   : node-aggregated anomaly score S(n) (Tenko X2), the
                                per-packet node score. Source array: arr_node_<attack>_double.npy
                                (== tenko_nodescore_<attack>.npy). Its threshold-independent
                                AUC (tenko_AUC_nodescore) matches the headline pattern-distance
                                AUC to ~1e-3, so it is a faithful "score used for AUC".

Both arrays are per-TEST-packet, aligned 1:1 with arr_gold_<attack>.npy over the held-out
test stream = [benign_test (30k negatives)] + [attack (50k positives)], 80k packets total
(see stream_counts.csv). Index 0 = first benign_test packet; the attack begins at n_test.

Styling mirrors the Kitsune-style RMSE timeline (cf. the commented visualization in
results.py: scatter colored by true label, dashed benign threshold line, dashed train/test
split marker) and Mirsky's log-scale RMSE convention. The two panels use identical figure
size, fonts, log-y axis, and y-range so they sit as directly comparable Fig 4 & Fig 5.

Threshold line = benign-calibrated Median+MAD cutoff, thr = median + 3*1.4826*MAD, computed
on the benign_test negatives (the plotted benign region), i.e. the report's Kitsune Median+MAD
recipe applied to each detector's own plotted benign region. (The run_ciciot2023.py driver
calibrates Kitsune's threshold on the earlier benign_lead slice; that value is numerically
similar -- see README.)

Downsampling: every DOWNSAMPLE-th test packet is plotted (stride subsample) for legibility.
The attack-onset transition and threshold-crossing structure are preserved because the flood
signal is sustained. The factor is annotated on each figure and recorded in the README.

No data is re-generated here: this reads only the cached arrays saved by run_ciciot2023.py.
"""
from __future__ import annotations

import argparse
import os

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

OUT = os.path.dirname(os.path.abspath(__file__))
FIGS = os.path.join(OUT, "figs")

# Benign_test length (negatives) = attack onset index in the test stream. From stream_counts.csv.
N_TEST_DEFAULT = 30000
MAD_K = 3.0  # matches run_ciciot2023.py Kitsune threshold recipe

# Consistent, publication-style rcParams for both panels.
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "legend.fontsize": 8.5,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "figure.dpi": 120,
})

# Human-readable attack titles.
PRETTY = {
    "DoS-SYN_Flood": "DoS SYN Flood",
    "DDoS-UDP_Flood": "DDoS UDP Flood",
    "MITM-ArpSpoofing": "MITM ARP Spoofing",
    "Mirai-greeth_flood": "Mirai (greeth Flood)",
    "Recon-OSScan": "Recon (OS Scan)",
    "DictionaryBruteForce": "Dictionary Brute Force",
}

# Per-detector plotting spec.
DETECTORS = {
    "kitsune": {
        "array": lambda a: f"arr_kitsune_{a}.npy",
        "ylabel": r"Anomaly score  $\tanh(\mathrm{RMSE})$",
        "label_short": "Kitsune",
        "desc": "per-packet RMSE",
    },
    "tenko": {
        "array": lambda a: f"arr_node_{a}_double.npy",
        "ylabel": r"Node anomaly score  $S(n)$",
        "label_short": "Tenko",
        "desc": "node-aggregated score",
    },
}

BENIGN_COLOR = "#2c6fbb"   # steel blue
ATTACK_COLOR = "#d1442f"   # brick red
THR_COLOR = "#111111"
ONSET_COLOR = "#555555"
SHADE_COLOR = "#d1442f"


def mad_threshold(x: np.ndarray, k: float = MAD_K) -> float:
    """Benign-calibrated Median+MAD cutoff: median + k * 1.4826 * MAD."""
    med = float(np.median(x))
    mad = float(np.median(np.abs(x - med)))
    return med + k * 1.4826 * mad


def plot_detector(detector: str, attack: str, n_test: int, downsample: int,
                  ylim: tuple[float, float]) -> dict:
    spec = DETECTORS[detector]
    scores = np.load(os.path.join(OUT, spec["array"](attack)))
    gold = np.load(os.path.join(OUT, f"arr_gold_{attack}.npy"))
    assert len(scores) == len(gold), f"score/label mismatch {len(scores)} vs {len(gold)}"

    # Benign-calibrated threshold from the benign_test negatives (plotted benign region).
    thr = mad_threshold(scores[:n_test])

    x = np.arange(len(scores))
    # Positive floor for log-scale (guard against exact zeros; these arrays are strictly > 0).
    floor = max(ylim[0] * 0.5, 1e-6)
    y = np.clip(scores, floor, None)

    # Stride downsample, keeping benign/attack masks aligned.
    xs = x[::downsample]
    ys = y[::downsample]
    gs = gold[::downsample]
    benign = gs == 0
    attack_m = gs == 1

    fig, ax = plt.subplots(figsize=(7.2, 3.3))

    # Shade the attack region.
    ax.axvspan(n_test, len(scores), color=SHADE_COLOR, alpha=0.06, zorder=0)

    ax.scatter(xs[benign], ys[benign], s=2.2, c=BENIGN_COLOR, alpha=0.55,
               linewidths=0, rasterized=True, label="benign packets")
    ax.scatter(xs[attack_m], ys[attack_m], s=2.2, c=ATTACK_COLOR, alpha=0.55,
               linewidths=0, rasterized=True, label="attack packets")

    ax.axhline(thr, color=THR_COLOR, ls="--", lw=1.3,
               label=f"benign threshold = {thr:.4f}")
    ax.axvline(n_test, color=ONSET_COLOR, ls=":", lw=1.3, label="attack onset")

    ax.set_yscale("log")
    ax.set_ylim(*ylim)
    ax.set_xlim(0, len(scores))
    ax.set_xlabel("Packet index (held-out test stream)")
    ax.set_ylabel(spec["ylabel"])
    ax.set_title(f"{spec['label_short']} ({spec['desc']}) — {PRETTY.get(attack, attack)} (CICIoT2023)")
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.5)

    # Compact custom legend (scatter proxies + lines).
    handles = [
        Line2D([0], [0], marker="o", color="none", markerfacecolor=BENIGN_COLOR,
               markersize=5, label="benign packets"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=ATTACK_COLOR,
               markersize=5, label="attack packets"),
        Line2D([0], [0], color=THR_COLOR, ls="--", lw=1.3,
               label=f"benign threshold = {thr:.4f}"),
        Line2D([0], [0], color=ONSET_COLOR, ls=":", lw=1.3, label="attack onset"),
        Patch(facecolor=SHADE_COLOR, alpha=0.12, label="attack region"),
    ]
    ax.legend(handles=handles, loc="lower right", framealpha=0.92, ncol=1,
              handletextpad=0.5, borderpad=0.5)

    # Annotate downsampling factor.
    ax.text(0.012, 0.03, f"every {downsample}\u1d57\u02b0 packet shown",
            transform=ax.transAxes, fontsize=7.5, color="#666666", va="bottom")

    fig.tight_layout()
    base = os.path.join(FIGS, f"cic_{detector}_rmse_{attack}")
    png = base + ".png"
    pdf = base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)

    benign_scores = scores[:n_test]
    attack_scores = scores[n_test:]
    return {
        "detector": detector,
        "attack": attack,
        "png": png,
        "pdf": pdf,
        "array": spec["array"](attack),
        "threshold": thr,
        "n_test": n_test,
        "n_attack": len(scores) - n_test,
        "downsample": downsample,
        "benign_median": float(np.median(benign_scores)),
        "attack_median": float(np.median(attack_scores)),
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
    }


# Per-detector colors for the OVERLAY figure (Okabe-Ito, colorblind-safe). In the
# overlay the two streams are distinguished by DETECTOR (not by benign/attack), so we use
# one color per detector for both its scatter and its threshold line.
OVERLAY_COLORS = {
    "kitsune": "#0072B2",  # blue
    "tenko": "#E69F00",    # orange
}


def block_median(x: np.ndarray, window: int) -> tuple[np.ndarray, np.ndarray]:
    """Median-pool x into consecutive blocks of `window` samples.

    Returns (centers, medians): a smoothed envelope robust to spiky benign points.
    The last (short) block is included so the attack tail is not dropped.
    """
    n = len(x)
    nblocks = int(np.ceil(n / window))
    centers = np.empty(nblocks)
    meds = np.empty(nblocks)
    for b in range(nblocks):
        lo = b * window
        hi = min((b + 1) * window, n)
        seg = x[lo:hi]
        centers[b] = (lo + hi - 1) / 2.0
        meds[b] = float(np.median(seg))
    return centers, meds


def plot_overlay(attack: str, n_test: int, downsample: int, smooth_window: int,
                 ylim: tuple[float, float]) -> dict:
    """Single figure with BOTH detectors on shared log-y / x axes.

    Faint downsampled scatter per detector (raw density) + a bold block-median line per
    detector (clean benign-band vs attack-band envelope) + both benign-calibrated
    Median+MAD thresholds as dashed lines in each detector's color.
    """
    kit = np.load(os.path.join(OUT, DETECTORS["kitsune"]["array"](attack)))
    node = np.load(os.path.join(OUT, DETECTORS["tenko"]["array"](attack)))
    gold = np.load(os.path.join(OUT, f"arr_gold_{attack}.npy"))
    assert len(kit) == len(node) == len(gold), "overlay array length mismatch"
    n = len(kit)

    thr_kit = mad_threshold(kit[:n_test])
    thr_node = mad_threshold(node[:n_test])

    floor = max(ylim[0] * 0.5, 1e-6)
    x = np.arange(n)
    streams = {
        "kitsune": (np.clip(kit, floor, None), DETECTORS["kitsune"]["label_short"], thr_kit),
        "tenko": (np.clip(node, floor, None), DETECTORS["tenko"]["label_short"], thr_node),
    }

    fig, ax = plt.subplots(figsize=(7.6, 3.6))
    ax.axvspan(n_test, n, color="#777777", alpha=0.07, zorder=0)

    handles = []
    for det, (y, short, thr) in streams.items():
        c = OVERLAY_COLORS[det]
        # faint raw scatter (context / density)
        ax.scatter(x[::downsample], y[::downsample], s=1.6, c=c, alpha=0.16,
                   linewidths=0, rasterized=True, zorder=1)
        # bold smoothed envelope
        cx, cy = block_median(y, smooth_window)
        ax.plot(cx, cy, color=c, lw=1.9, zorder=3, solid_capstyle="round")
        # per-detector benign threshold
        ax.axhline(thr, color=c, ls="--", lw=1.2, alpha=0.9, zorder=2)
        handles.append(Line2D([0], [0], color=c, lw=2.2,
                              label=f"{short}  (median-pooled)"))
        handles.append(Line2D([0], [0], color=c, ls="--", lw=1.2,
                              label=f"{short} benign thr = {thr:.4f}"))

    ax.axvline(n_test, color="#333333", ls=":", lw=1.3, zorder=2)
    handles.append(Line2D([0], [0], color="#333333", ls=":", lw=1.3, label="attack onset"))
    handles.append(Patch(facecolor="#777777", alpha=0.14, label="attack region"))

    ax.set_yscale("log")
    ax.set_ylim(*ylim)
    ax.set_xlim(0, n)
    ax.set_xlabel("Packet index (held-out test stream)")
    ax.set_ylabel("Per-packet anomaly score")
    ax.set_title(f"Tenko vs Kitsune anomaly score — {PRETTY.get(attack, attack)} (CICIoT2023)")
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.5)
    ax.legend(handles=handles, loc="lower right", framealpha=0.93, ncol=1,
              handletextpad=0.6, borderpad=0.5, labelspacing=0.35)

    ax.text(0.012, 0.03,
            f"faint pts: every {downsample}\u1d57\u02b0 pkt · lines: median pool /{smooth_window} pkt",
            transform=ax.transAxes, fontsize=7.5, color="#666666", va="bottom")

    fig.tight_layout()
    base = os.path.join(FIGS, f"cic_overlay_rmse_{attack}")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)

    return {
        "attack": attack, "png": png, "pdf": pdf,
        "thr_kitsune": thr_kit, "thr_tenko": thr_node,
        "downsample": downsample, "smooth_window": smooth_window,
        "n_test": n_test, "n_attack": n - n_test,
    }


# Full-stream region boundaries (stream_counts.csv + run_ciciot2023.py:34-37).
N_LEAD = 150000          # benign_lead: KitNET train + eta/threshold calibration
GRACE_END = 55001        # FMgrace(5000)+ADgrace(50000)+1: benign threshold calibration starts here
N_TEST_FS = 30000        # benign_test negatives
ATTACK_ONSET = N_LEAD + N_TEST_FS  # 180000
N_TOTAL = 230000


def plot_fullstream_overlay(attack: str, downsample: int, smooth_window: int,
                            ylim: tuple[float, float]) -> dict:
    """Full-stream (0..230k) Tenko-vs-Kitsune overlay marking the TRAINING period.

    Kitsune spans the whole stream via tanh(rmse_raw) (cached full-stream RMSE). Tenko's
    per-packet node score S(n) is cached for the TEST region only (run_ciciot2023.py persists
    test-region arrays), so its curve starts at N_LEAD=150000; the benign-lead training region
    is still shaded/labelled to show the full protocol (Kitsune-style Fig 4/5 layout).
    """
    raw = np.load(os.path.join(OUT, f"rmse_raw_{attack}.npy"))
    assert len(raw) == N_TOTAL, f"rmse_raw len {len(raw)} != {N_TOTAL}"
    kit_full = np.tanh(raw)                                   # Kitsune, full 230k stream
    node = np.load(os.path.join(OUT, f"arr_node_{attack}_double.npy"))  # Tenko S(n), test region (80k)
    assert len(node) == (N_TOTAL - N_LEAD), f"arr_node len {len(node)} != {N_TOTAL-N_LEAD}"

    # Benign-calibrated Median+MAD thresholds (same recipe as the other figures).
    thr_kit = mad_threshold(kit_full[N_LEAD:ATTACK_ONSET])    # benign_test slice
    thr_node = mad_threshold(node[:N_TEST_FS])               # benign_test slice of S(n)

    floor = max(ylim[0] * 0.5, 1e-6)
    kit_y = np.clip(kit_full, floor, None)
    node_y = np.clip(node, floor, None)
    x_kit = np.arange(N_TOTAL)
    x_node = np.arange(N_LEAD, N_TOTAL)                       # Tenko starts at 150k

    fig, ax = plt.subplots(figsize=(9.2, 3.7))

    # --- region shading ---
    ax.axvspan(0, N_LEAD, color="#3b7dd8", alpha=0.07, zorder=0)          # training (benign only)
    ax.axvspan(N_LEAD, ATTACK_ONSET, color="#7a7a7a", alpha=0.06, zorder=0)  # benign test
    ax.axvspan(ATTACK_ONSET, N_TOTAL, color=ATTACK_COLOR, alpha=0.07, zorder=0)  # attack

    # --- Kitsune (blue), full stream ---
    ck = OVERLAY_COLORS["kitsune"]
    ax.scatter(x_kit[::downsample], kit_y[::downsample], s=1.4, c=ck, alpha=0.14,
               linewidths=0, rasterized=True, zorder=1)
    cxk, cyk = block_median(kit_y, smooth_window)
    ax.plot(cxk, cyk, color=ck, lw=1.8, zorder=3, solid_capstyle="round")
    ax.axhline(thr_kit, color=ck, ls="--", lw=1.15, alpha=0.9, zorder=2)

    # --- Tenko (orange), test region only ---
    ct = OVERLAY_COLORS["tenko"]
    ax.scatter(x_node[::downsample], node_y[::downsample], s=1.4, c=ct, alpha=0.16,
               linewidths=0, rasterized=True, zorder=1)
    cxt, cyt = block_median(node_y, smooth_window)
    ax.plot(cxt + N_LEAD, cyt, color=ct, lw=1.9, zorder=4, solid_capstyle="round")
    ax.axhline(thr_node, color=ct, ls="--", lw=1.15, alpha=0.9, zorder=2)

    # --- boundary lines ---
    ax.axvline(GRACE_END, color="#3b6ea5", ls=(0, (2, 3)), lw=1.0, alpha=0.8, zorder=2)
    ax.axvline(N_LEAD, color="#333333", ls="-.", lw=1.1, alpha=0.8, zorder=2)
    ax.axvline(ATTACK_ONSET, color="#333333", ls=":", lw=1.4, zorder=2)

    ax.set_yscale("log")
    ax.set_ylim(*ylim)
    ax.set_xlim(0, N_TOTAL)

    # --- region labels (top of plot) ---
    ytxt = ylim[1] * 0.55
    ax.text(N_LEAD / 2, ytxt, "Training (benign only)\nKitNET + $\\eta$/threshold calib.",
            ha="center", va="center", fontsize=8, color="#1f4e79")
    ax.text((N_LEAD + ATTACK_ONSET) / 2, ylim[1] * 0.28, "benign\ntest",
            ha="center", va="center", fontsize=7.5, color="#444444")
    ax.text((ATTACK_ONSET + N_TOTAL) / 2, ytxt, "Attack",
            ha="center", va="center", fontsize=9, color="#8a2b1f")

    ax.set_xlabel("Packet index (full per-attack stream)")
    ax.set_ylabel("Per-packet anomaly score")
    ax.set_title(f"Tenko vs Kitsune anomaly score, full stream — {PRETTY.get(attack, attack)} (CICIoT2023)")
    ax.grid(True, which="both", ls=":", lw=0.4, alpha=0.5)

    handles = [
        Line2D([0], [0], color=ct, lw=2.2, label="Tenko $S(n)$ (median-pooled)"),
        Line2D([0], [0], color=ct, ls="--", lw=1.15, label=f"Tenko benign thr = {thr_node:.4f}"),
        Line2D([0], [0], color=ck, lw=2.0, label="Kitsune $\\tanh$(RMSE) (median-pooled)"),
        Line2D([0], [0], color=ck, ls="--", lw=1.15, label=f"Kitsune benign thr = {thr_kit:.4f}"),
        Line2D([0], [0], color="#3b6ea5", ls=(0, (2, 3)), lw=1.0, label=f"calib. start (pkt {GRACE_END})"),
        Line2D([0], [0], color="#333333", ls="-.", lw=1.1, label=f"train/test split (pkt {N_LEAD//1000}k)"),
        Line2D([0], [0], color="#333333", ls=":", lw=1.4, label=f"attack onset (pkt {ATTACK_ONSET//1000}k)"),
    ]
    ax.legend(handles=handles, loc="lower right", framealpha=0.93, ncol=1,
              handletextpad=0.6, borderpad=0.5, labelspacing=0.3, fontsize=8)

    ax.text(0.006, 0.03,
            f"faint pts: every {downsample}\u1d57\u02b0 pkt · lines: median pool /{smooth_window} pkt · "
            f"Tenko S(n) cached for test region only (pkt {N_LEAD//1000}k+)",
            transform=ax.transAxes, fontsize=7, color="#666666", va="bottom")

    fig.tight_layout()
    base = os.path.join(FIGS, f"cic_fullstream_overlay_{attack}")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)

    return {
        "attack": attack, "png": png, "pdf": pdf,
        "thr_kitsune": thr_kit, "thr_tenko": thr_node,
        "downsample": downsample, "smooth_window": smooth_window,
        "grace_end": GRACE_END, "train_end": N_LEAD, "attack_onset": ATTACK_ONSET,
        "n_total": N_TOTAL,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks", default="DoS-SYN_Flood,MITM-ArpSpoofing",
                    help="comma-separated attack names")
    ap.add_argument("--downsample", type=int, default=10,
                    help="plot every k-th test packet (stride subsample)")
    ap.add_argument("--overlay-window", type=int, default=250,
                    help="block-median pool window (packets) for overlay smoothing lines")
    ap.add_argument("--fullstream-downsample", type=int, default=20,
                    help="stride subsample for the 230k full-stream overlay")
    ap.add_argument("--mode", choices=["per-detector", "overlay", "fullstream", "both"],
                    default="both", help="which figures to generate")
    args = ap.parse_args()

    os.makedirs(FIGS, exist_ok=True)
    attacks = args.attacks.split(",")

    # Shared y-range so the two detectors' panels line up for each attack.
    ylim = (8e-4, 1.4)

    infos = []
    if args.mode in ("per-detector", "both"):
        for attack in attacks:
            for detector in ("kitsune", "tenko"):
                info = plot_detector(detector, attack, N_TEST_DEFAULT, args.downsample, ylim)
                infos.append(info)
                print(f"[{info['detector']:>7}] {attack:>18}  thr={info['threshold']:.5f}  "
                      f"benign_med={info['benign_median']:.4f}  attack_med={info['attack_median']:.4f}  "
                      f"-> {os.path.basename(info['png'])}")
    if args.mode in ("overlay", "both"):
        for attack in attacks:
            info = plot_overlay(attack, N_TEST_DEFAULT, args.downsample,
                                args.overlay_window, ylim)
            infos.append(info)
            print(f"[overlay] {attack:>18}  thr_kit={info['thr_kitsune']:.5f}  "
                  f"thr_tenko={info['thr_tenko']:.5f}  pool=/{info['smooth_window']}  "
                  f"-> {os.path.basename(info['png'])}")
    if args.mode == "fullstream":
        for attack in attacks:
            info = plot_fullstream_overlay(attack, args.fullstream_downsample,
                                           args.overlay_window, ylim)
            infos.append(info)
            print(f"[fullstream] {attack:>18}  thr_kit={info['thr_kitsune']:.5f}  "
                  f"thr_tenko={info['thr_tenko']:.5f}  train_end={info['train_end']}  "
                  f"onset={info['attack_onset']}  -> {os.path.basename(info['png'])}")
    return infos


if __name__ == "__main__":
    main()
