#!/usr/bin/env python3
"""Kitsune-dataset RMSE timelines from committed CSVs (paper-style, results.py / plot.py).

Source series: authentic KitNET scores in ``../data/npz/<Attack>_scores.npz``
(produced by ``gen_scores.py`` / ``rebuild_8attacks.sh``; gitignored). CSVs under
``figs/data/`` are downsampled (interval=100) so the repo can regenerate figures
without the ~19 GB UCI archive.

  # plot from committed CSVs (no npz required):
  python results/main9attack/figs/plot_rmse_from_csv.py

  # re-export CSVs from local npz, then plot:
  python results/main9attack/figs/plot_rmse_from_csv.py --export-from-npz
"""
from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
from matplotlib.lines import Line2D

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
NPZ_DIR = HERE.parent / "data" / "npz"
GRACE = 55_000
INTERVAL = 100
DEFAULT_ATTACKS = ["OS Scan", "SSDP Flood"]

BENIGN_COLOR = "#2c6fbb"
ATTACK_COLOR = "#d1442f"


def _slug(attack: str) -> str:
    return attack.replace(" ", "_")


def export_from_npz(attacks: list[str]) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    thr_rows = []
    for attack in attacks:
        npz = NPZ_DIR / f"{attack}_scores.npz"
        if not npz.is_file():
            raise SystemExit(f"missing {npz} (run rebuild_8attacks.sh / gen_scores.py first)")
        z = np.load(npz)
        scores = z["scores"].astype(np.float64)
        labels = z["labels"].astype(np.int8)
        benign_cal = z["benign_cal"].astype(np.float64)
        train_max = float(np.max(benign_cal))
        thr = float(np.mean(benign_cal) + 3.0 * np.std(benign_cal))
        thr_rows.append(
            [attack, "kitsune_raw_rmse", f"{thr:.8g}", f"{train_max:.8g}",
             len(benign_cal), GRACE]
        )
        out = DATA / f"rmse_timeline_{_slug(attack)}.csv"
        idx = np.arange(0, len(scores), INTERVAL)
        with open(out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["packet_index", "eval_index", "label", "rmse", "tanh_rmse"])
            for i in idx:
                r = float(scores[i])
                w.writerow([int(GRACE + i), int(i), int(labels[i]),
                            f"{r:.8g}", f"{float(np.tanh(r)):.8g}"])
        print(f"wrote {out} ({len(idx)} rows)")

    thr_out = DATA / "rmse_thresholds.csv"
    with open(thr_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "detector", "mean_plus_3std", "benign_cal_max",
                    "benign_cal_n", "grace_packets"])
        w.writerows(thr_rows)
    print(f"wrote {thr_out}")


def _load_timeline(attack: str):
    path = DATA / f"rmse_timeline_{_slug(attack)}.csv"
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"missing/empty {path}")
    idx, lab, rmse, tanh = [], [], [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            idx.append(int(row["packet_index"]))
            lab.append(int(row["label"]))
            rmse.append(float(row["rmse"]))
            tanh.append(float(row["tanh_rmse"]))
    return (np.asarray(idx), np.asarray(lab),
            np.asarray(rmse), np.asarray(tanh))


def _load_thresholds() -> dict:
    path = DATA / "rmse_thresholds.csv"
    thr = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            thr[row["attack"]] = {
                "mean_plus_3std": float(row["mean_plus_3std"]),
                "benign_cal_max": float(row["benign_cal_max"]),
            }
    return thr


def plot_attack(attack: str, thr: dict) -> None:
    """Label-colored tanh(RMSE) timeline (results.py historical visualization)."""
    idx, lab, _rmse, tanh = _load_timeline(attack)
    t = thr[attack]
    fig, ax = plt.subplots(figsize=(10.0, 4.2))
    cmap = ListedColormap(["white", "orange"])
    ax.scatter(idx, tanh, s=0.8, c=lab, cmap=cmap, linewidths=0, rasterized=True)
    ax.axhline(np.tanh(t["mean_plus_3std"]), color="g", ls="--", lw=1.2,
               label="mean+3σ (tanh)")
    ax.axhline(np.tanh(t["benign_cal_max"]), color="r", ls="--", lw=1.2,
               label="benign max (tanh)")
    # First attack packet among downsampled points
    att = np.where(lab == 1)[0]
    if len(att):
        ax.axvline(idx[att[0]], color="k", ls="--", lw=1.0, label="first attack")
    ax.set_title(f"RMSE over Time — Kitsune {attack} (from CSV)")
    ax.set_ylabel("Score (tanh(RMSE))")
    ax.set_xlabel("Packet index")
    ax.legend(loc="upper right", fontsize="x-small",
              handles=[
                  Line2D([0], [0], marker="o", color="none", markerfacecolor="white",
                         markeredgecolor="#888", markersize=6, label="benign"),
                  Line2D([0], [0], marker="o", color="none", markerfacecolor="orange",
                         markersize=6, label="attack"),
                  Line2D([0], [0], color="g", ls="--", label="mean+3σ (tanh)"),
                  Line2D([0], [0], color="r", ls="--", label="benign max (tanh)"),
                  Line2D([0], [0], color="k", ls="--", label="first attack"),
              ])
    fig.tight_layout()
    base = HERE / f"kitsune_rmse_{_slug(attack)}_from_csv"
    fig.savefig(str(base) + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(str(base) + ".pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {base}.png")

    # Companion: raw RMSE log-y (plot.py / Kitsune execution-phase style)
    idx, lab, rmse, _ = _load_timeline(attack)
    fig, ax = plt.subplots(figsize=(10.0, 4.2))
    ben = lab == 0
    attm = lab == 1
    y = np.clip(rmse, 1e-4, 1e3)
    ax.scatter(idx[ben], y[ben], s=1.2, c=BENIGN_COLOR, alpha=0.45,
               linewidths=0, rasterized=True)
    ax.scatter(idx[attm], y[attm], s=1.2, c=ATTACK_COLOR, alpha=0.55,
               linewidths=0, rasterized=True)
    ax.axhline(t["mean_plus_3std"], color="g", ls="--", lw=1.2)
    ax.axhline(t["benign_cal_max"], color="r", ls="--", lw=1.2)
    if len(att):
        ax.axvline(idx[att[0]], color="k", ls="--", lw=1.0)
    ax.set_yscale("log")
    ax.set_title(f"Anomaly Scores — Kitsune {attack} (from CSV)")
    ax.set_ylabel("RMSE (log scaled)")
    ax.set_xlabel("Packet index")
    ax.legend(handles=[
        Line2D([0], [0], marker="o", color="none", markerfacecolor=BENIGN_COLOR,
               markersize=5, label="benign"),
        Line2D([0], [0], marker="o", color="none", markerfacecolor=ATTACK_COLOR,
               markersize=5, label="attack"),
        Line2D([0], [0], color="g", ls="--", label=f"mean+3σ={t['mean_plus_3std']:.4g}"),
        Line2D([0], [0], color="r", ls="--", label=f"max={t['benign_cal_max']:.4g}"),
    ], loc="upper right", fontsize="x-small")
    fig.tight_layout()
    base2 = HERE / f"kitsune_rmse_raw_{_slug(attack)}_from_csv"
    fig.savefig(str(base2) + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(str(base2) + ".pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {base2}.png")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-from-npz", action="store_true",
                    help="rebuild CSVs from ../data/npz/*_scores.npz")
    ap.add_argument("--attacks", default=",".join(DEFAULT_ATTACKS),
                    help="comma-separated Kitsune attack names")
    args = ap.parse_args()
    attacks = [a.strip() for a in args.attacks.split(",") if a.strip()]
    if args.export_from_npz:
        export_from_npz(attacks)
    thr = _load_thresholds()
    for attack in attacks:
        if attack not in thr:
            raise SystemExit(f"no threshold row for {attack!r} in {DATA/'rmse_thresholds.csv'}")
        plot_attack(attack, thr)


if __name__ == "__main__":
    main()
