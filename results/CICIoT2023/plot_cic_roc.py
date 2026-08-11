#!/usr/bin/env python3
"""ROC-curve overlay: Tenko vs Kitsune on CICIoT2023 MITM-ArpSpoofing.

The single clearest "Tenko wins" plot for MITM is the SOURCE / DEVICE-LEVEL ROC. At the
packet level the two detectors are near-tied (AUC 0.949 vs 0.942); the decisive gap appears
when per-packet scores are aggregated to a per-device verdict (the operationally meaningful
"which device is malicious?" question): Tenko ROC-AUC 0.839 vs Kitsune 0.647.

This script reproduces the exact per-device scoring of source_level_experiment.py
(max aggregation, internal 192.168.x attacker devices with >=50 attack packets and >=99% of
their packets in the attack region, sources with >=5 test packets), computes the ROC curve for
each detector, and overlays them on shared axes. It confirms the AUCs against
ciciot2023_source_level_metrics.csv before saving.

Detector signals (identical to source_level_experiment.py):
  * Kitsune per-source = MAX of per-packet tanh(RMSE)      -> arr_kitsune_<attack>.npy
  * Tenko   per-source = MAX of per-packet pattern distance -> arr_cont_<attack>_double.npy
Per-packet source IPs are read live from the pilot TSV (same reader as the source script).

Cached arrays only; no pipeline re-run; nothing invented. Does not import or modify
plot_cic_rmse.py.
"""
from __future__ import annotations

import csv
import os
from collections import Counter

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, roc_auc_score

OUT = os.path.dirname(os.path.abspath(__file__))
FIGS = os.path.join(OUT, "figs")
PILOT = "/Users/sbhola/Desktop/cic/pilot"  # same as source_level_experiment.py / run driver

# Stream layout (stream_counts.csv): [benign_lead][benign_test][attack].
N_LEAD, N_TEST, N_ATK = 150000, 30000, 50000

ATTACK = "MITM-ArpSpoofing"

# Established detector colors (Okabe-Ito), matching the overlay figures.
KIT_COLOR = "#0072B2"   # Kitsune blue
TEN_COLOR = "#E69F00"   # Tenko orange

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "legend.fontsize": 9.5,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "figure.dpi": 120,
})


def read_src(tsv: str) -> list[str]:
    """Per-packet source IP (col 4 IPv4, else col 17 IPv6) -- matches source_level_experiment.read_src."""
    src = []
    with open(tsv, "rt", encoding="utf8") as f:
        r = csv.reader(f, delimiter="\t")
        next(r)
        for row in r:
            s = ""
            if len(row) > 5 and row[4] and row[5]:
                s = row[4]
            elif len(row) > 18 and row[17] and row[18]:
                s = row[17]
            src.append(s)
    return src


def is_internal(ip: str) -> bool:
    return ip.startswith("192.168.")


def attacker_set(c_atk: Counter, benign_all: Counter, min_atk: int, include_public: bool) -> set:
    s = set()
    for ip, cnt in c_atk.items():
        if ip == "":
            continue
        if not include_public and not is_internal(ip):
            continue
        tot = cnt + benign_all.get(ip, 0)
        if cnt >= min_atk and cnt / tot >= 0.99:
            s.add(ip)
    return s


def source_scores(attack: str, min_atk: int = 50, include_public: bool = False,
                  min_src_pkts: int = 5):
    """Reproduce source_level_experiment.source_table (how='max'): per-device labels + scores."""
    src_all = read_src(os.path.join(PILOT, f"stream_{attack}.pcap.tsv"))
    src_test = src_all[N_LEAD:]
    c_lead = Counter(src_all[:N_LEAD])
    c_test = Counter(src_all[N_LEAD:N_LEAD + N_TEST])
    c_atk = Counter(src_all[N_LEAD + N_TEST:])
    benign_all = c_lead + c_test

    kit = np.load(os.path.join(OUT, f"arr_kitsune_{attack}.npy"))
    cont = np.load(os.path.join(OUT, f"arr_cont_{attack}_double.npy"))
    assert len(src_test) == len(kit) == len(cont), (
        f"length mismatch: src_test={len(src_test)} kit={len(kit)} cont={len(cont)}")

    atk = attacker_set(c_atk, benign_all, min_atk, include_public)

    idx_by_src: dict[str, list[int]] = {}
    for i, s in enumerate(src_test):
        idx_by_src.setdefault(s, []).append(i)

    ys, sk, sc = [], [], []
    for s, idxs in idx_by_src.items():
        if s == "" or len(idxs) < min_src_pkts:
            continue
        idxs = np.array(idxs)
        ys.append(1 if s in atk else 0)
        sk.append(float(np.max(kit[idxs])))    # Kitsune per-device = max tanh(RMSE)
        sc.append(float(np.max(cont[idxs])))   # Tenko per-device   = max pattern distance
    return np.array(ys), np.array(sk), np.array(sc)


def packet_level_scores(attack: str):
    """Packet-level labels + scores (for the faded contrast curves)."""
    gold = np.load(os.path.join(OUT, f"arr_gold_{attack}.npy"))
    kit = np.load(os.path.join(OUT, f"arr_kitsune_{attack}.npy"))
    cont = np.load(os.path.join(OUT, f"arr_cont_{attack}_double.npy"))
    return gold, kit, cont


def expected_aucs(attack: str):
    """Read the committed source-level AUCs to confirm reproduction."""
    with open(os.path.join(OUT, "ciciot2023_source_level_metrics.csv")) as f:
        for row in csv.DictReader(f):
            if row["attack"] == attack:
                return float(row["kitsune_src_AUC"]), float(row["tenko_src_AUC"])
    return None, None


def main():
    os.makedirs(FIGS, exist_ok=True)

    # ---- device-level (primary) ----
    ys, sk, sc = source_scores(ATTACK)
    kit_auc = roc_auc_score(ys, sk)
    ten_auc = roc_auc_score(ys, sc)
    fpr_k, tpr_k, _ = roc_curve(ys, sk)
    fpr_t, tpr_t, _ = roc_curve(ys, sc)

    exp_k, exp_t = expected_aucs(ATTACK)
    print(f"device-level  n_attacker_dev={int(ys.sum())}  n_benign_dev={int((ys == 0).sum())}")
    print(f"  Kitsune AUC = {kit_auc:.6f}  (CSV {exp_k:.6f})")
    print(f"  Tenko   AUC = {ten_auc:.6f}  (CSV {exp_t:.6f})")
    assert abs(kit_auc - exp_k) < 1e-2, f"Kitsune AUC {kit_auc} != CSV {exp_k}"
    assert abs(ten_auc - exp_t) < 1e-2, f"Tenko AUC {ten_auc} != CSV {exp_t}"

    # ---- packet-level (faded contrast) ----
    gold, pkit, pcont = packet_level_scores(ATTACK)
    pk_kit_auc = roc_auc_score(gold, pkit)
    pk_ten_auc = roc_auc_score(gold, pcont)
    pfpr_k, ptpr_k, _ = roc_curve(gold, pkit)
    pfpr_t, ptpr_t, _ = roc_curve(gold, pcont)
    print(f"packet-level  Kitsune AUC = {pk_kit_auc:.6f}   Tenko AUC = {pk_ten_auc:.6f}")

    # ---- plot ----
    fig, ax = plt.subplots(figsize=(5.6, 5.4))

    # chance diagonal
    ax.plot([0, 1], [0, 1], ls=(0, (4, 4)), lw=1.2, color="#999999",
            label="chance (AUC = 0.50)", zorder=1)

    # packet-level contrast (thin, faded) -- shows the near-tie
    ax.plot(pfpr_t, ptpr_t, color=TEN_COLOR, lw=1.1, alpha=0.4, zorder=2)
    ax.plot(pfpr_k, ptpr_k, color=KIT_COLOR, lw=1.1, alpha=0.4, zorder=2)

    # device-level (bold) -- the clear win
    ax.plot(fpr_t, tpr_t, color=TEN_COLOR, lw=2.6, zorder=4,
            label=f"Tenko — per-device (AUC = {ten_auc:.2f})")
    ax.plot(fpr_k, tpr_k, color=KIT_COLOR, lw=2.6, zorder=3,
            label=f"Kitsune — per-device (AUC = {kit_auc:.2f})")

    # proxies for the faded packet-level pair (single combined legend entry)
    from matplotlib.lines import Line2D
    faded_proxy = Line2D([0], [0], color="#8a8a8a", lw=1.1, alpha=0.6,
                         label=(f"packet-level (near-tie): "
                                f"Tenko {pk_ten_auc:.2f}, Kitsune {pk_kit_auc:.2f}"))

    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.01)
    ax.set_aspect("equal")
    ax.set_xlabel("False positive rate (benign devices)")
    ax.set_ylabel("True positive rate (attacker devices)")
    ax.set_title("Per-device detection ROC — MITM ARP Spoofing (CICIoT2023)")
    ax.grid(True, ls=":", lw=0.4, alpha=0.5)

    handles, labels = ax.get_legend_handles_labels()
    handles.append(faded_proxy)
    labels.append(faded_proxy.get_label())
    ax.legend(handles, labels, loc="lower right", framealpha=0.94,
              handletextpad=0.6, borderpad=0.6, labelspacing=0.4)

    ax.text(0.03, 0.97,
            f"{int(ys.sum())} attacker vs {int((ys == 0).sum())} benign devices\n"
            f"per-device score = max over source packets",
            transform=ax.transAxes, fontsize=8, color="#444444", va="top")

    fig.tight_layout()
    base = os.path.join(FIGS, "cic_roc_mitm_clearwin")
    png, pdf = base + ".png", base + ".pdf"
    fig.savefig(png, dpi=300, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    plt.close(fig)
    print(f"[saved] {png}")
    print(f"[saved] {pdf}")
    return dict(kit_auc=kit_auc, ten_auc=ten_auc, pk_kit_auc=pk_kit_auc,
                pk_ten_auc=pk_ten_auc, png=png, pdf=pdf)


if __name__ == "__main__":
    main()
