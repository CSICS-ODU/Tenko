#!/usr/bin/env python3
"""
Compare X1-X4 latency and memory between two branches:
  - latency-memory-experiment: synthetic generation (generate_layer_figures.py)
  - Daksh (current): real measurements (workflow.py / example.py / results.py)

Outputs a side-by-side comparison table for execution-phase means.
"""

import csv
import pickle
import numpy as np
from pathlib import Path

RANDOM_SEED = 42
FM_GRACE = 5000
AD_GRACE = 50000
TRAINING_END = FM_GRACE + AD_GRACE  # 55_000

RMSE_PATH = Path("dataset/Mirai/Mirai_pcap_exp1_RMSEs.pkl")
CSV_PATH = Path("Mirai_X1_X4_layers.csv")


# ── Synthetic generators (exact copy from latency-memory-experiment branch) ──

def generate_X1_memory(N, rng):
    mem = np.empty(N)
    for i in range(N):
        if i < FM_GRACE:
            g = i / FM_GRACE
            mem[i] = 90 + 50 * g + rng.normal(0, 1.5)
        elif i < TRAINING_END:
            mem[i] = 130 + rng.normal(0, 3)
        else:
            mem[i] = 127 + rng.normal(0, 2.5)
    return mem


def generate_X2_memory(N, rng):
    mem = np.empty(N)
    for i in range(N):
        if i < FM_GRACE:
            g = i / FM_GRACE
            mem[i] = 45 + 20 * g + rng.normal(0, 1.0)
        elif i < TRAINING_END:
            mem[i] = 68 + rng.normal(0, 2)
        else:
            mem[i] = 67 + rng.normal(0, 1.5)
    return mem


def generate_X1_latency(N, rng):
    lat = np.empty(N)
    for i in range(N):
        if i < FM_GRACE:
            lat[i] = 0.3 + rng.normal(0, 0.08)
        elif i < TRAINING_END:
            lat[i] = 1.26 + rng.normal(0, 0.25)
        else:
            lat[i] = 1.26 + rng.normal(0, 0.22)
    return np.maximum(lat, 0.01)


def generate_X2_latency(N, rng):
    lat = np.empty(N)
    for i in range(N):
        if i < FM_GRACE:
            lat[i] = 0.15 + rng.normal(0, 0.04)
        elif i < TRAINING_END:
            lat[i] = 0.54 + rng.normal(0, 0.10)
        else:
            lat[i] = 0.54 + rng.normal(0, 0.08)
    return np.maximum(lat, 0.005)


def estimate_X3(X2, rng):
    X3_base = 1.10 * X2
    r3 = rng.uniform(-0.10, 0.10, size=len(X2))
    return X3_base, X3_base * (1.0 + r3)


def estimate_X4(X2, rng):
    X4_base = 0.25 * X2
    r4 = rng.uniform(-0.10, 0.10, size=len(X2))
    return X4_base, X4_base * (1.0 + r4)


# ── Load measured data from current branch CSV ──

def load_daksh_csv(csv_path):
    x1t, x1m, x2t, x2m, x3t, x3m, x4t, x4m = [], [], [], [], [], [], [], []
    with open(csv_path) as f:
        next(f)  # skip comment line
        reader = csv.DictReader(f)
        for row in reader:
            x1t.append(float(row["X1_time"]))
            x1m.append(float(row["X1_memory"]))
            x2t.append(float(row["X2_time"]))
            x2m.append(float(row["X2_memory"]))
            x3t.append(float(row["X3_time"]))
            x3m.append(float(row["X3_memory"]))
            x4t.append(float(row["X4_time"]))
            x4m.append(float(row["X4_memory"]))
    return {
        "X1_lat": np.array(x1t),
        "X1_mem": np.array(x1m),
        "X2_lat": np.array(x2t),
        "X2_mem": np.array(x2m),
        "X3_lat": np.array(x3t),
        "X3_mem": np.array(x3m),
        "X4_lat": np.array(x4t),
        "X4_mem": np.array(x4m),
    }


def main():
    # ── Determine N from RMSE pickle ─────────────────────────────────────
    with open(RMSE_PATH, "rb") as f:
        rmse = pickle.load(f)
    N = len(rmse)
    print(f"N (total RMSE samples) = {N:,}")

    # ══════════════════════════════════════════════════════════════════════
    # Branch A: latency-memory-experiment (synthetic)
    # ══════════════════════════════════════════════════════════════════════
    rng = np.random.default_rng(RANDOM_SEED)

    X1_lat_syn = generate_X1_latency(N, rng)
    X2_lat_syn = generate_X2_latency(N, rng)
    X1_mem_syn = generate_X1_memory(N, rng)
    X2_mem_syn = generate_X2_memory(N, rng)

    _, X3_lat_syn = estimate_X3(X2_lat_syn, rng)
    _, X4_lat_syn = estimate_X4(X2_lat_syn, rng)
    _, X3_mem_syn = estimate_X3(X2_mem_syn, rng)
    _, X4_mem_syn = estimate_X4(X2_mem_syn, rng)

    # ══════════════════════════════════════════════════════════════════════
    # Branch B: Daksh (measured)
    # ══════════════════════════════════════════════════════════════════════
    d = load_daksh_csv(CSV_PATH)
    # CSV values: time in seconds, memory in bytes -> convert to ms / MB
    SEC_TO_MS = 1000.0
    BYTES_TO_MB = 1.0 / (1024 * 1024)

    d_lat = {
        "X1": d["X1_lat"] * SEC_TO_MS,
        "X2": d["X2_lat"] * SEC_TO_MS,
        "X3": d["X3_lat"] * SEC_TO_MS,
        "X4": d["X4_lat"] * SEC_TO_MS,
    }
    d_mem = {
        "X1": d["X1_mem"] * BYTES_TO_MB,
        "X2": d["X2_mem"] * BYTES_TO_MB,
        "X3": d["X3_mem"] * BYTES_TO_MB,
        "X4": d["X4_mem"] * BYTES_TO_MB,
    }

    # ══════════════════════════════════════════════════════════════════════
    # Compute execution-phase means (samples >= TRAINING_END)
    # For synthetic: index >= 55_000
    # For measured CSV: all rows are already execution phase (packet_idx >= 55_001)
    # ══════════════════════════════════════════════════════════════════════
    ex = slice(TRAINING_END, None)

    syn_lat = {
        "X1": np.mean(X1_lat_syn[ex]),
        "X2": np.mean(X2_lat_syn[ex]),
        "X3": np.mean(X3_lat_syn[ex]),
        "X4": np.mean(X4_lat_syn[ex]),
    }
    syn_mem = {
        "X1": np.mean(X1_mem_syn[ex]),
        "X2": np.mean(X2_mem_syn[ex]),
        "X3": np.mean(X3_mem_syn[ex]),
        "X4": np.mean(X4_mem_syn[ex]),
    }

    meas_lat = {k: np.mean(v) for k, v in d_lat.items()}
    meas_mem = {k: np.mean(v) for k, v in d_mem.items()}

    # Totals
    syn_lat["Total"] = sum(syn_lat[k] for k in ("X1", "X2", "X3", "X4"))
    syn_mem["Total"] = sum(syn_mem[k] for k in ("X1", "X2", "X3", "X4"))
    meas_lat["Total"] = sum(meas_lat[k] for k in ("X1", "X2", "X3", "X4"))
    meas_mem["Total"] = sum(meas_mem[k] for k in ("X1", "X2", "X3", "X4"))

    # ══════════════════════════════════════════════════════════════════════
    # Print comparison tables
    # ══════════════════════════════════════════════════════════════════════
    layers = ["X1", "X2", "X3", "X4", "Total"]
    sep = "=" * 72

    print(f"\n{sep}")
    print("LATENCY COMPARISON (ms) — Execution Phase Means")
    print(f"{sep}")
    print(f"{'Layer':<10} {'latency-memory-exp':>20} {'Daksh (measured)':>20} {'Diff':>18}")
    print("-" * 72)
    for ly in layers:
        s = syn_lat[ly]
        m = meas_lat[ly]
        diff = m - s
        marker = "  <---" if ly == "Total" else ""
        print(f"{ly:<10} {s:>20.6f} {m:>20.6f} {diff:>+18.6f}{marker}")

    print(f"\n{sep}")
    print("MEMORY COMPARISON (MB) — Execution Phase Means")
    print(f"{sep}")
    print(f"{'Layer':<10} {'latency-memory-exp':>20} {'Daksh (measured)':>20} {'Diff':>18}")
    print("-" * 72)
    for ly in layers:
        s = syn_mem[ly]
        m = meas_mem[ly]
        diff = m - s
        marker = "  <---" if ly == "Total" else ""
        print(f"{ly:<10} {s:>20.4f} {m:>20.6f} {diff:>+18.4f}{marker}")

    print(f"\n{sep}")
    print("NOTES")
    print(f"{sep}")
    print("- latency-memory-exp: X1/X2 are SYNTHETIC (hardcoded means + Gaussian noise)")
    print("  X1 lat ~1.26 ms, X2 lat ~0.54 ms, X1 mem ~127 MB, X2 mem ~67 MB")
    print("- Daksh (measured): X1/X2 are REAL measurements via time.perf_counter / psutil.rss")
    print("  X1 wraps K.proc_next_packet() (pcap parse + feature extraction + autoencoder)")
    print("  X2 wraps nodeScore.update() + pattern recognizer + ensemble prediction")
    print("- Daksh per-sample memory deltas are mostly 0 (RSS page-granularity limitation)")
    print("- X3 = 1.1 * X2 * (1+U[-0.1,0.1]), X4 = 0.25 * X2 * (1+U[-0.1,0.1]) on both")
    print(f"- Random seed: {RANDOM_SEED}")
    print(sep)


if __name__ == "__main__":
    main()
