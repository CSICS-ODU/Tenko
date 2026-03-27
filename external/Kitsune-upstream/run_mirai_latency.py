#!/usr/bin/env python3
"""
Run upstream Kitsune-py (paper defaults) on Mirai TSV; report KitNET / FE latency stats.

Paper-style hyperparameters: maxAE=10, FMgrace=5000, ADgrace=50000 (see upstream README / NDSS'18).
Execution-phase samples: packet index i > FMgrace + ADgrace (1-based), matching example.py.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

# Ensure local Kitsune package is used
sys.path.insert(0, str(Path(__file__).resolve().parent))

from Kitsune import Kitsune  # noqa: E402

# Paper / upstream demo defaults
DEFAULT_MAX_AE = 10
DEFAULT_FM = 5000
DEFAULT_AD = 50000


def _git_rev(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            text=True,
        ).strip()
    except Exception:
        return "unknown"


def main() -> None:
    here = Path(__file__).resolve().parent
    default_tsv = here.parent.parent / "dataset" / "Mirai" / "Mirai_pcap.pcap.tsv"

    p = argparse.ArgumentParser(description="Mirai latency — upstream Kitsune-py, paper config")
    p.add_argument(
        "--mirai-tsv",
        type=Path,
        default=default_tsv,
        help="Pre-parsed Mirai TSV (tshark fields; .tsv extension)",
    )
    p.add_argument("--max-ae", type=int, default=DEFAULT_MAX_AE)
    p.add_argument("--fm-grace", type=int, default=DEFAULT_FM)
    p.add_argument("--ad-grace", type=int, default=DEFAULT_AD)
    p.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop after this many packets total (including grace); default: all",
    )
    p.add_argument(
        "--target-exec-samples",
        type=int,
        default=None,
        help="Stop after collecting this many execution-phase KitNET timings (after grace)",
    )
    p.add_argument("--seed", type=int, default=42, help="Reserved (numpy not used for RNG here)")
    p.add_argument("--out-json", type=Path, default=here / "mirai_latency_report.json")
    args = p.parse_args()
    _ = args.seed

    if not args.mirai_tsv.is_file():
        print(f"ERROR: Mirai TSV not found: {args.mirai_tsv}", file=sys.stderr)
        sys.exit(1)

    max_ae = args.max_ae
    fm = args.fm_grace
    ad = args.ad_grace
    grace_end = fm + ad  # last training packet index (1-based): i <= grace_end is grace

    print(f"Mirai TSV: {args.mirai_tsv.resolve()}")
    print(f"KitNET params: maxAE={max_ae}, FMgrace={fm}, ADgrace={ad} (paper-style upstream demo)")
    print(f"Execution-phase (1-based i): i > {grace_end}")
    rev = _git_rev(here)
    print(f"Kitsune-py HEAD: {rev}")

    packet_limit = np.inf if args.max_packets is None else int(args.max_packets)
    t_build0 = time.perf_counter()
    K = Kitsune(str(args.mirai_tsv.resolve()), packet_limit, max_ae, fm, ad)
    t_build1 = time.perf_counter()

    kitnet_exec: list[float] = []
    fe_exec: list[float] = []
    kitnet_all: list[float] = []
    fe_all: list[float] = []

    i = 0
    t_loop0 = time.perf_counter()
    while True:
        i += 1
        rmse = K.proc_next_packet()
        if rmse == -1:
            break

        kt = float(K._last_kitnet_time_s)
        ft = float(K._last_fe_time_s)
        kitnet_all.append(kt)
        fe_all.append(ft)

        if i > grace_end:
            kitnet_exec.append(kt)
            fe_exec.append(ft)
            if args.target_exec_samples is not None and len(kitnet_exec) >= args.target_exec_samples:
                break

        if args.max_packets is not None and i >= args.max_packets:
            break

    t_loop1 = time.perf_counter()

    def stats(name: str, arr: list[float]) -> dict:
        a = np.array(arr, dtype=np.float64)
        if a.size == 0:
            return {"n": 0}
        return {
            "n": int(a.size),
            "mean_ms": float(np.mean(a) * 1000.0),
            "median_ms": float(np.median(a) * 1000.0),
            "std_ms": float(np.std(a) * 1000.0),
            "p99_ms": float(np.percentile(a, 99) * 1000.0),
            "implied_pps": float(1.0 / np.mean(a)) if np.mean(a) > 0 else 0.0,
        }

    report = {
        "python": sys.version,
        "platform": platform.platform(),
        "kitsune_py_git": rev,
        "mirai_tsv": str(args.mirai_tsv.resolve()),
        "hyperparameters": {"maxAE": max_ae, "FMgrace": fm, "ADgrace": ad},
        "packets_processed": i,
        "build_time_s": t_build1 - t_build0,
        "loop_wall_time_s": t_loop1 - t_loop0,
        "kitnet_execution_phase_ms": stats("kitnet_exec", kitnet_exec),
        "fe_execution_phase_ms": stats("fe_exec", fe_exec),
        "kitnet_all_packets_ms": stats("kitnet_all", kitnet_all),
        "note": (
            "KitNET time = AnomDetector.process() only (matches paper Python scope). "
            "Paper throughput numbers are from C++; Python is slower per upstream README."
        ),
    }

    print(json.dumps(report, indent=2))
    args.out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {args.out_json.resolve()}")


if __name__ == "__main__":
    main()
