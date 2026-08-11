#!/usr/bin/env python3
"""Regenerate OS Scan \"Adjusted Anomaly Scores\" via the original results.py plot path.

The titled plot lives inside the historical ``get_adversarial_IPs`` (active in older
commits; commented today in ``results.py`` / git ``TEST.py``). Exact block:

    scores[scores == 0] = np.nan
    plt.axhline(y=threshold, color='g', ls='--')
    plt.axhline(y=train_max, color='r', ls='--')
    plt.axvline(x=benignLimit/interval, color='k', ls='--')
    plt.scatter(..., scores[-1,:], ..., c='k', label='rmse scores')
    for each IP: plt.scatter(..., scores[k,:], ..., label=ip)
    plt.title(\"Adjusted Anomaly Scores\")

This script re-runs that collection + plot with OS Scan artifacts (memorySize=6,
blocking). Default scatter ``interval=100`` (denser than 1000, lighter than 1).
Override with ``--interval``. Does not edit ``results.py`` aesthetics.

  MPLBACKEND=Agg .venv/bin/python reproducibility/plots/plot_os_scan_adjusted_anomaly.py
  MPLBACKEND=Agg .venv/bin/python reproducibility/plots/plot_os_scan_adjusted_anomaly.py --interval 200
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use(os.environ.get("MPLBACKEND", "Agg"))
from matplotlib import pyplot as plt
from tqdm import tqdm

REPO = Path(__file__).resolve().parents[2]
MAIN9 = REPO / "results" / "main9attack"
sys.path.insert(0, str(REPO))

from tracker import nodeScore  # noqa: E402
import results as R  # noqa: E402

NPZ = MAIN9 / "data" / "npz" / "OS Scan_scores.npz"
LABELS_CSV = MAIN9 / "data" / "labels" / "OS Scan_labels_raw.csv"
TSV = MAIN9 / "data" / "ds" / "os_scan" / "OS_Scan_pcap.pcapng.tsv"
FIGS = MAIN9 / "figs"
DATA_OUT = FIGS / "data"

GRACE = 55_000  # FMgrace + ADgrace
BENIGN_LIMIT = 100_000
# memorySize/blocking match e458380 results.main; interval=100 is denser than the
# get_adversarial_IPs default (1000) without the overplot of main()'s interval=1.
INTERVAL = 100
MEMORY_SIZE = 6
BLOCKCHAIN_MODE = "blocking"


def load_rmse_full() -> np.ndarray:
    z = np.load(NPZ)
    scores = z["scores"].astype(np.float64)
    n = GRACE + len(scores)
    full = np.zeros(n, dtype=np.float64)
    full[GRACE:] = scores
    return full


def get_adversarial_IPs_adjusted_plot(
    IPs,
    IPd,
    LABELS,
    RMSEs,
    interval=INTERVAL,
    memorySize=MEMORY_SIZE,
    blockchainMode=BLOCKCHAIN_MODE,
    n_window=100000,
    quantile=0.5,
    rolling_window_size=500,
    smoothing_factor=0.9,
):
    """Historical ``get_adversarial_IPs`` body (e458380) that emits Adjusted Anomaly Scores.

    Logic/plotting copied from the original function; ``plt.show`` replaced by savefig.
    """
    benignLimit = BENIGN_LIMIT
    FMgrace = 5000
    ADgrace = 50000

    RMSEs = np.tanh(np.asarray(RMSEs, dtype=float))

    benignSample = RMSEs[FMgrace + ADgrace + 1 : benignLimit]
    mean = np.mean(benignSample)
    std = np.std(benignSample)
    train_max = max(benignSample)
    threshold = train_max + 3 * std
    print(threshold)
    _ = mean  # historical local; kept for parity

    SUS_IPs = dict()
    ALL_IPs = dict()
    first_occ = dict()
    last_occ = dict()
    target_IP = dict()
    _ = (SUS_IPs, ALL_IPs, first_occ, last_occ, target_IP)

    node_score = nodeScore(memorySize, mode=blockchainMode)

    scores = np.zeros((100, int((len(RMSEs) - benignLimit) / interval) + 1))

    invert = False
    gold = LABELS[benignLimit:]
    pred = []
    FPFNx = []
    FPFNy = []
    rolling_window = []

    for i in tqdm(range(benignLimit, len(RMSEs)), desc="Adjusted Anomaly Scores"):
        if invert:
            rmse = 1 - RMSEs[i]
        else:
            rmse = RMSEs[i]
        ip = IPs[i]
        ip_d = IPd[i]
        _ = ip_d

        node_score.update(ip, i, rmse)
        try:
            score = node_score.scores[ip].get_score()
        except Exception:
            score = rmse

        rolling_window.append(score)
        if len(rolling_window) > rolling_window_size:
            rolling_window = rolling_window[-rolling_window_size:]

        if (i - benignLimit) % (interval * n_window) == 0:
            all_scores = []
            for key in node_score.scores.keys():
                try:
                    s = node_score.scores[key].get_score()
                    all_scores.append(s)
                except Exception:
                    continue
            if all_scores and rolling_window:
                new_threshold = np.quantile(rolling_window, quantile)
                threshold = smoothing_factor * threshold + (1 - smoothing_factor) * new_threshold
                print("thresh", threshold, train_max + 3 * std)
                threshold = max(threshold, train_max + 3 * std)

        if score >= threshold:
            flag = 1
        else:
            flag = 0

        if LABELS[i] != flag:
            if ip == "192.168.2.1":
                flag = LABELS[i]
            else:
                # x-axis is interval bins (same units as scores columns)
                FPFNx.append((i - benignLimit) / interval)
                FPFNy.append(score)

        pred.append(flag)

        if i % 100000 == 0:
            node_score.finalize()

        if i % interval == 0:
            j = int((i - benignLimit) / interval)
            for k, key in enumerate(node_score.scores.keys()):
                try:
                    if key == ip:
                        scores[k, j] = score
                except Exception:
                    raise
            scores[-1, j] = rmse

    print(node_score.scores)

    scores[scores == 0] = np.nan

    # ---- original Adjusted Anomaly Scores plotting block (results.py / TEST.py) ----
    plt.figure(figsize=(10, 5))
    plt.axhline(y=threshold, color="g", ls="--")
    plt.axhline(y=train_max, color="r", ls="--")
    plt.axvline(x=benignLimit / interval, color="k", ls="--")

    plt.scatter(
        range(len(scores[-1, :])),
        scores[-1, :],
        s=1,
        marker="x",
        c="k",
        label="rmse scores",
    )
    for k, key in enumerate(node_score.scores.keys()):
        plt.scatter(range(len(scores[k, :])), scores[k, :], s=1, marker=".", label=key)

    plt.scatter(FPFNx, FPFNy, s=1, c="r", marker="o", label="FP")

    plt.title("Adjusted Anomaly Scores")
    plt.ylabel("Scores")
    plt.xlabel("Time elapsed [1000 mins]")
    plt.legend(loc="upper right", fontsize="x-small")
    plt.tight_layout()

    out_base = FIGS / "os_scan_adjusted_anomaly_scores"
    FIGS.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(out_base) + ".png", dpi=200, bbox_inches="tight")
    plt.savefig(str(out_base) + ".pdf", bbox_inches="tight")
    plt.close()
    print(f"wrote {out_base}.png")
    print(f"wrote {out_base}.pdf")

    return gold, pred, scores, list(node_score.scores.keys()), threshold, train_max


def export_scores_csv(
    scores, ip_keys, path: Path, interval: int = INTERVAL, stride: int = 1
) -> None:
    """Wide CSV: packet_index, kitsune_score, then one column per IP (blank where absent).

    Scores are already binned by ``interval``; default ``stride=1`` exports every bin
    (same downsampling as the scatter). Increase stride only for coarser CSV dumps.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    n = scores.shape[1]
    n_ip = min(len(ip_keys), scores.shape[0] - 1)
    header = ["packet_index", "kitsune_score"] + [ip_keys[k] for k in range(n_ip)]
    nrows = 0
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for j in range(0, n, stride):
            pkt = BENIGN_LIMIT + j * interval
            row = [pkt, _fmt(scores[-1, j])]
            for k in range(n_ip):
                row.append(_fmt(scores[k, j]))
            w.writerow(row)
            nrows += 1
    print(f"wrote {path} ({nrows} rows stride={stride}, interval={interval}, {n_ip} IP cols)")


def _fmt(v) -> str:
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return ""
    return f"{float(v):.8g}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--interval",
        type=int,
        default=INTERVAL,
        help=f"scatter / CSV bin size (default {INTERVAL}; try 200 if too heavy)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    interval = args.interval
    if interval < 1:
        raise SystemExit("--interval must be >= 1")

    for p in (NPZ, LABELS_CSV, TSV):
        if not p.is_file():
            raise SystemExit(f"missing required input: {p}")

    print("Loading RMSEs / labels / IPs...")
    print(f"interval={interval}")
    RMSEs = load_rmse_full().tolist()
    LABELS = R.build_label_list(str(LABELS_CSV), label_col="x")
    IPs, IPd = R.build_IP_list(str(TSV))
    print(f"Lengths — RMSEs={len(RMSEs)} IPs={len(IPs)} LABELS={len(LABELS)}")
    if not (len(RMSEs) == len(IPs) == len(LABELS)):
        raise SystemExit("length mismatch among RMSEs / IPs / LABELS")

    gold, pred, scores, ip_keys, threshold, train_max = get_adversarial_IPs_adjusted_plot(
        IPs, IPd, LABELS, RMSEs,
        interval=interval,
        memorySize=MEMORY_SIZE,
        blockchainMode=BLOCKCHAIN_MODE,
    )
    print(f"IPs in legend ({len(ip_keys)}): {ip_keys}")
    print(f"threshold={threshold:.6g} train_max={train_max:.6g}")
    print(f"gold len={len(gold)} pred sum={sum(pred)}")

    export_scores_csv(
        scores, ip_keys, DATA_OUT / "os_scan_adjusted_anomaly_scores.csv", interval=interval
    )


if __name__ == "__main__":
    main()
