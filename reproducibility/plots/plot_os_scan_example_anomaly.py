#!/usr/bin/env python3
"""Reproduce example.py's Kitsune anomaly-score plot via plot.plot_loss.

example.py streams a PCAP/TSV through Kitsune, applies ``np.tanh`` to each RMSE,
and (periodically / at the end of a long run) calls:

    plot_loss(RMSEs, interval=1, fig_name='Test_fig.png')

This glue loads the same OS Scan KitNET scores already under
``results/main9attack/data/npz/`` (no live Kitsune pass), applies tanh, and
calls ``plot.plot_loss`` unchanged.

  MPLBACKEND=Agg .venv/bin/python reproducibility/plots/plot_os_scan_example_anomaly.py
  MPLBACKEND=Agg .venv/bin/python reproducibility/plots/plot_os_scan_example_anomaly.py --interval 1
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use(os.environ.get("MPLBACKEND", "Agg"))

REPO = Path(__file__).resolve().parents[2]
MAIN9 = REPO / "results" / "main9attack"
sys.path.insert(0, str(REPO))

from plot import plot_loss  # noqa: E402

NPZ = MAIN9 / "data" / "npz" / "OS Scan_scores.npz"
FIGS = MAIN9 / "figs"
GRACE = 55_000  # FMgrace + ADgrace (matches example.py / gen_scores.py)
# plot_loss default is 100 (repo-friendly). example.py's mid-run call used 1.
DEFAULT_INTERVAL = 100


def load_rmses_tanh() -> list[float]:
    """Pad grace zeros + post-grace KitNET scores, then tanh (as example.py)."""
    if not NPZ.is_file():
        raise SystemExit(f"missing required input: {NPZ}")
    raw = np.load(NPZ)["scores"].astype(np.float64)
    full = np.zeros(GRACE + len(raw), dtype=np.float64)
    full[GRACE:] = raw
    return np.tanh(full).tolist()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"downsample step passed to plot_loss (default {DEFAULT_INTERVAL}, as example.py)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=FIGS / "os_scan_example_anomaly_scores.png",
        help="output figure path (PNG; plot_loss writes this path)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.interval < 1:
        raise SystemExit("--interval must be >= 1")

    RMSEs = load_rmses_tanh()
    out = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    print(f"RMSEs={len(RMSEs)} interval={args.interval} -> {out}")

    # Same call shape as example.py (interval=1, named fig → no plt.show).
    plot_loss(RMSEs, interval=args.interval, fig_name=str(out))
    print(f"wrote {out}")

    # Optional PDF sibling for paper packs (same figure, Agg-safe).
    if out.suffix.lower() == ".png":
        import matplotlib.pyplot as plt

        pdf = out.with_suffix(".pdf")
        # plot_loss already saved PNG and left the current figure open.
        plt.savefig(str(pdf), bbox_inches="tight")
        plt.close()
        print(f"wrote {pdf}")
    else:
        import matplotlib.pyplot as plt

        plt.close()


if __name__ == "__main__":
    main()
