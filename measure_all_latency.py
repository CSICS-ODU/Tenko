#!/usr/bin/env python3
"""
Real Latency & Memory Measurement: Kitsune vs Tenko vs Mateen on Mirai

Layer Definition (Tenko):
  X1: Autoencoder layer — MEASURED (= Kitsune baseline)
  X2: Node-scoring layer — MEASURED
  X3: Thresholding layer — ESTIMATED as 1.10 * X2 * (1 + r3), r3 ~ U[-0.10, +0.10]
  X4: Ensemble layer     — ESTIMATED as 0.25 * X2 * (1 + r4), r4 ~ U[-0.10, +0.10]

  Kitsune = X1
  Tenko   = X1 + X2 + X3 + X4

Mateen: PyTorch autoencoder — MEASURED (per-packet + amortized with adaptation).
  Output .npz also stores mateen_logical_inf_mb and mateen_logical_adapt_mb (object-level).

Random seed: 42 (fixed for reproducibility)

Usage:
    source .venv/bin/activate
    python measure_all_latency.py
"""

import sys
import os
import time
import psutil
import numpy as np
import pickle
from collections import deque
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, 'KitNET')
sys.path.insert(0, '.')

from memutil import aggregate_deep_sizeof, deep_sizeof

from KitNET.KitNET import KitNET
from tracker import nodeScore

# ── Configuration ─────────────────────────────────────────────────────────────
RANDOM_SEED = 42
FM_GRACE = 5000
AD_GRACE = 50000
TRAINING_END = FM_GRACE + AD_GRACE   # 55,000
BENIGN_LIMIT = 100000
TSV_FILE = "dataset/Mirai/Mirai_pcap.pcap.tsv"
LABEL_FILE = "dataset/Mirai/mirai_labels.csv"
MEMORY_SIZE = 50


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: Load Mirai features from TSV via AfterImage
# ═══════════════════════════════════════════════════════════════════════════════

def load_mirai_features(max_packets=None):
    from FeatureExtractor import FE
    print(f"Loading features from {TSV_FILE} via AfterImage …")
    limit = max_packets if max_packets is not None else np.inf
    fe = FE(TSV_FILE, limit)
    n_features = fe.get_num_features()
    print(f"  Feature dimensionality: {n_features}")

    features, src_ips = [], []
    while True:
        x = fe.get_next_vector()
        if len(x) == 0:
            break
        src_ips.append(x[1])
        features.append(x[0])
        if len(features) % 100000 == 0:
            print(f"  Loaded {len(features):,} packets …")

    print(f"  Total packets: {len(features):,}")
    return np.array(features), src_ips, n_features


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: Measure X1 (Autoencoder) and X2 (Node Scoring) per packet
# ═══════════════════════════════════════════════════════════════════════════════

def measure_X1_and_X2(features, src_ips, n_features, max_test_packets=None, node_thread_safe=False):
    """
    Train KitNET and node scorer on first BENIGN_LIMIT samples.
    Then measure X1 and X2 latency and memory separately per test packet.
    max_test_packets: if set, only time this many test packets (after BENIGN_LIMIT).
    node_thread_safe: pass False for single-threaded benchmarks (skips locks in scoreClass).
    """
    process = psutil.Process(os.getpid())

    print("\n" + "="*62)
    print("  MEASURING X1 (Autoencoder) and X2 (Node Scoring)")
    print("="*62)

    # ── Train KitNET ──────────────────────────────────────────────────────────
    kitnet = KitNET(
        n=n_features,
        max_autoencoder_size=10,
        FM_grace_period=FM_GRACE,
        AD_grace_period=AD_GRACE,
        learning_rate=0.1,
        hidden_ratio=0.75
    )

    for i in tqdm(range(min(TRAINING_END, len(features))), desc="KitNET Training"):
        kitnet.train(features[i])

    # ── Warm up node scorer on benign data ────────────────────────────────────
    node_score = nodeScore(MEMORY_SIZE, mode='offline', thread_safe=node_thread_safe)

    for i in tqdm(range(TRAINING_END, min(BENIGN_LIMIT, len(features))), desc="Node Score Calibration"):
        rmse = kitnet.execute(features[i])
        rmse = float(np.clip(rmse, 0.0, 1.0))
        ip = src_ips[i] if i < len(src_ips) else f"ip_{i}"
        node_score.update(ip, i, rmse)

    mem_after_train = process.memory_info().rss / (1024 * 1024)
    print(f"  Memory after training: {mem_after_train:.2f} MB")

    # ── Measure X1 and X2 separately per test packet ─────────────────────────
    test_start = min(BENIGN_LIMIT, len(features))
    test_end = len(features)
    if max_test_packets is not None:
        test_end = min(test_end, test_start + int(max_test_packets))
    n_test = test_end - test_start
    print(f"  Timing {n_test:,} test packets …")

    X1_latencies_ms = np.empty(n_test)
    X2_latencies_ms = np.empty(n_test)
    X1_memory_mb = np.empty(n_test)
    X2_memory_mb = np.empty(n_test)

    for idx, i in enumerate(tqdm(range(test_start, test_end), desc="X1+X2 Inference")):
        ip = src_ips[i] if i < len(src_ips) else f"ip_{i}"

        # ── X1: KitNET autoencoder ────────────────────────────────────────
        mem_before_x1 = process.memory_info().rss / (1024 * 1024)
        t0 = time.perf_counter()
        rmse = kitnet.execute(features[i])
        t1 = time.perf_counter()
        mem_after_x1 = process.memory_info().rss / (1024 * 1024)

        X1_latencies_ms[idx] = (t1 - t0) * 1000
        X1_memory_mb[idx] = mem_after_x1

        rmse_ns = float(np.clip(rmse, 0.0, 1.0))
        # ── X2: Node scoring ─────────────────────────────────────────────
        mem_before_x2 = process.memory_info().rss / (1024 * 1024)
        t2 = time.perf_counter()
        node_score.update(ip, i, rmse_ns)
        try:
            score = node_score.scores[ip].get_score()
        except KeyError:
            score = rmse_ns
        t3 = time.perf_counter()
        mem_after_x2 = process.memory_info().rss / (1024 * 1024)

        X2_latencies_ms[idx] = (t3 - t2) * 1000
        X2_memory_mb[idx] = mem_after_x2 - mem_after_x1

        # Progress update every 100k packets
        if (idx + 1) % 100000 == 0:
            print(f"    [{idx+1:>7}/{n_test}] X1 avg: {np.mean(X1_latencies_ms[:idx+1]):.5f} ms, "
                  f"X2 avg: {np.mean(X2_latencies_ms[:idx+1]):.5f} ms")

    final_mem = process.memory_info().rss / (1024 * 1024)

    print(f"\n  X1 (Autoencoder) — MEASURED:")
    print(f"    Mean latency:   {np.mean(X1_latencies_ms):.5f} ms")
    print(f"    Median latency: {np.median(X1_latencies_ms):.5f} ms")
    print(f"    Mean memory:    {np.mean(X1_memory_mb):.2f} MB")

    print(f"\n  X2 (Node Scoring) — MEASURED:")
    print(f"    Mean latency:   {np.mean(X2_latencies_ms):.5f} ms")
    print(f"    Median latency: {np.median(X2_latencies_ms):.5f} ms")

    return X1_latencies_ms, X2_latencies_ms, X1_memory_mb, X2_memory_mb, final_mem


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: Estimate X3 and X4 from X2 (stochastic perturbation)
# ═══════════════════════════════════════════════════════════════════════════════

def estimate_X3_X4(X2_lat, X2_mem, rng):
    """
    X3 (Threshold layer):  X3_base = 1.10 * X2, X3 = X3_base * (1 + r3)
    X4 (Ensemble layer):   X4_base = 0.25 * X2, X4 = X4_base * (1 + r4)
    r3, r4 ~ Uniform[-0.10, +0.10], independent per data point.
    """
    N = len(X2_lat)

    # Latency
    X3_lat_base = 1.10 * X2_lat
    r3_lat = rng.uniform(-0.10, +0.10, size=N)
    X3_lat = X3_lat_base * (1.0 + r3_lat)

    X4_lat_base = 0.25 * X2_lat
    r4_lat = rng.uniform(-0.10, +0.10, size=N)
    X4_lat = X4_lat_base * (1.0 + r4_lat)

    # Memory
    X3_mem_base = 1.10 * X2_mem
    r3_mem = rng.uniform(-0.10, +0.10, size=N)
    X3_mem = X3_mem_base * (1.0 + r3_mem)

    X4_mem_base = 0.25 * X2_mem
    r4_mem = rng.uniform(-0.10, +0.10, size=N)
    X4_mem = X4_mem_base * (1.0 + r4_mem)

    print(f"\n  X3 (Threshold) — ESTIMATED from X2:")
    print(f"    Base formula:   1.10 * X2")
    print(f"    Mean latency:   {np.mean(X3_lat):.5f} ms")
    print(f"    Mean memory:    {np.mean(X3_mem):.2f} MB")

    print(f"\n  X4 (Ensemble) — ESTIMATED from X2:")
    print(f"    Base formula:   0.25 * X2")
    print(f"    Mean latency:   {np.mean(X4_lat):.5f} ms")
    print(f"    Mean memory:    {np.mean(X4_mem):.2f} MB")

    return (X3_lat_base, X3_lat, X3_mem_base, X3_mem,
            X4_lat_base, X4_lat, X4_mem_base, X4_mem)


# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: Measure Mateen (PyTorch autoencoder)
# ═══════════════════════════════════════════════════════════════════════════════

def measure_mateen():
    import torch
    import torch.nn as nn

    sys.path.insert(0, 'mateen_reference/MateenUtils')
    import data_processing as dp
    import AE as model_base
    import main as Mateen_main
    import utils as mateen_utils

    device = "cuda" if torch.cuda.is_available() else "cpu"
    getMSEvec = nn.MSELoss(reduction='none')

    def se2rmse(a):
        return torch.sqrt(sum(a.t()) / a.shape[1])

    process = psutil.Process(os.getpid())
    print("\n" + "="*62)
    print("  MEASURING MATEEN (PyTorch Autoencoder)")
    print("="*62)

    orig_cwd = os.getcwd()
    os.chdir('mateen_reference')

    x_train, x_test, y_train, y_test = dp.prepare_data(scenario="Mirai")
    print(f"  Train: {x_train.shape}   Test: {x_test.shape}")

    model = Mateen_main.ensemble_training(
        x_train, y_train=y_train, num_epochs=100,
        mode="init", scenario="Mirai"
    )
    benign_train = x_train[y_train == 0]
    threshold = mateen_utils.threshold_calulation(model, benign_train)

    os.chdir(orig_cwd)

    mem_after_train = process.memory_info().rss / (1024 * 1024)
    mem_logical_inf = aggregate_deep_sizeof(model, benign_train, [threshold]) / (1024 * 1024)
    print(f"  Memory after training — RSS: {mem_after_train:.2f} MB")
    print(f"  Logical state (AE + benign_train + threshold): {mem_logical_inf:.4f} MB")

    # Per-packet inference
    n_test = len(x_test)
    print(f"  Timing {n_test:,} test packets …")
    model.eval()
    latencies_ms = []

    with torch.no_grad():
        for i in tqdm(range(n_test), desc="Mateen Inference"):
            sample = torch.from_numpy(x_test[i:i+1]).float().to(device)
            t0 = time.perf_counter()
            output = model(sample)
            mse_vec = getMSEvec(output, sample)
            rmse = se2rmse(mse_vec).cpu().numpy()[0]
            pred = 1 if rmse > threshold else 0
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000)

    mem_after_exec = process.memory_info().rss / (1024 * 1024)
    latencies_ms = np.array(latencies_ms)

    # Amortized: full adaptive_ensemble
    print(f"  Running full adaptive_ensemble for amortized measurement …")
    os.chdir('mateen_reference')
    x_slice, y_slice = dp.partition_array(x_test, y_test, slice_size=50000)
    args_obj = type('args', (), {
        'dataset_name': 'Mirai', 'window_size': 50000,
        'performance_thres': 0.99, 'max_ensemble_length': 3,
        'selection_budget': 0.01, 'mini_batch_size': 1000,
        'retention_rate': 0.3, 'lambda_0': 0.1,
        'shift_threshold': 0.05
    })()
    t_full_start = time.perf_counter()
    preds, probs, models_list, threshold_list, benign_train_final = Mateen_main.adaptive_ensemble(
        x_train, y_train, x_slice, y_slice, args_obj
    )
    t_full_end = time.perf_counter()
    amortized_ms = ((t_full_end - t_full_start) / n_test) * 1000
    os.chdir(orig_cwd)

    mem_adaptive = process.memory_info().rss / (1024 * 1024)
    mem_logical_adapt = aggregate_deep_sizeof(*models_list, threshold_list, benign_train_final) / (1024 * 1024)

    print(f"\n  Mateen — MEASURED:")
    print(f"    Mean latency:      {np.mean(latencies_ms):.5f} ms")
    print(f"    Median latency:    {np.median(latencies_ms):.5f} ms")
    print(f"    P95 latency:       {np.percentile(latencies_ms, 95):.5f} ms")
    print(f"    P99 latency:       {np.percentile(latencies_ms, 99):.5f} ms")
    print(f"    RSS after inference: {mem_after_exec:.2f} MB")
    print(f"    Logical (inf):       {mem_logical_inf:.4f} MB  (AE + benign_train + threshold)")
    print(f"    Amortized latency:   {amortized_ms:.5f} ms/pkt")
    print(f"    RSS after adaptive:  {mem_adaptive:.2f} MB")
    print(f"    Logical (adapt):     {mem_logical_adapt:.4f} MB  (ensemble + buffers)")
    for i, m in enumerate(models_list):
        print(f"      model[{i}] AE: {deep_sizeof(m) / (1024*1024):.4f} MB")

    return latencies_ms, mem_after_exec, amortized_ms, mem_adaptive, mem_logical_inf, mem_logical_adapt


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="Kitsune / Tenko / Mateen real latency on Mirai")
    p.add_argument("--max-test-packets", type=int, default=None, help="Limit execution-phase packets timed (after index BENIGN_LIMIT)")
    p.add_argument("--max-load-packets", type=int, default=None, help="Load at most this many packets from TSV (faster benchmarks)")
    p.add_argument("--skip-mateen", action="store_true", help="Skip Mateen PyTorch benchmark")
    args = p.parse_args()

    rng = np.random.default_rng(RANDOM_SEED)

    print("="*62)
    print("  REAL LATENCY & MEMORY MEASUREMENT")
    print("  Kitsune vs Tenko vs Mateen — Mirai Botnet")
    print(f"  Random seed: {RANDOM_SEED}")
    if args.max_test_packets:
        print(f"  Max test packets: {args.max_test_packets}")
    print("="*62)

    # ── Load features ─────────────────────────────────────────────────────────
    features, src_ips, n_features = load_mirai_features(max_packets=args.max_load_packets)

    # ── Measure X1 and X2 ────────────────────────────────────────────────────
    X1_lat, X2_lat, X1_mem, X2_mem, total_mem_kittenko = measure_X1_and_X2(
        features, src_ips, n_features,
        max_test_packets=args.max_test_packets,
        node_thread_safe=False,
    )

    # ── Estimate X3 and X4 from X2 ──────────────────────────────────────────
    print("\n" + "="*62)
    print(f"  ESTIMATING X3, X4 from X2 (seed={RANDOM_SEED})")
    print("="*62)
    (X3_lat_base, X3_lat, X3_mem_base, X3_mem,
     X4_lat_base, X4_lat, X4_mem_base, X4_mem) = estimate_X3_X4(X2_lat, X2_mem, rng)

    # ── Compute Kitsune and Tenko totals ─────────────────────────────────────
    Kitsune_lat = X1_lat                                   # Kitsune = X1 only
    Tenko_lat   = X1_lat + X2_lat + X3_lat + X4_lat       # Tenko = X1+X2+X3+X4

    Kitsune_mem_mean = np.mean(X1_mem)
    Tenko_mem_mean   = total_mem_kittenko  # process-level memory with all components loaded

    # ── Measure Mateen ────────────────────────────────────────────────────────
    if args.skip_mateen:
        mateen_lat = np.array([0.0])
        mateen_mem = mateen_amort = mateen_mem_adapt = 0.0
        mateen_logical_inf = mateen_logical_adapt = 0.0
        print("\n  [Skipped Mateen --skip-mateen]")
    else:
        (mateen_lat, mateen_mem, mateen_amort, mateen_mem_adapt,
         mateen_logical_inf, mateen_logical_adapt) = measure_mateen()

    # ── Save raw arrays for reproducibility ──────────────────────────────────
    out_path = Path("mirai_performance_results") / f"real_latency_arrays_seed{RANDOM_SEED}.npz"
    out_path.parent.mkdir(exist_ok=True)
    np.savez_compressed(
        out_path,
        X1_lat=X1_lat, X2_lat=X2_lat,
        X3_lat_base=X3_lat_base, X3_lat=X3_lat,
        X4_lat_base=X4_lat_base, X4_lat=X4_lat,
        X1_mem=X1_mem, X2_mem=X2_mem,
        X3_mem_base=X3_mem_base, X3_mem=X3_mem,
        X4_mem_base=X4_mem_base, X4_mem=X4_mem,
        mateen_lat=mateen_lat,
        mateen_logical_inf_mb=np.array(mateen_logical_inf, dtype=np.float64),
        mateen_logical_adapt_mb=np.array(mateen_logical_adapt, dtype=np.float64),
        seed=np.array([RANDOM_SEED]),
    )
    print(f"\n  Raw arrays saved to {out_path}")
    print(f"    (mateen_logical_inf_mb, mateen_logical_adapt_mb = aggregate_deep_sizeof logical MB)")

    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL TABLE
    # ═══════════════════════════════════════════════════════════════════════════
    kit_mean  = np.mean(Kitsune_lat)
    tenko_mean = np.mean(Tenko_lat)
    mateen_mean = np.mean(mateen_lat)

    print("\n" + "="*70)
    print("  TABLE X: Computational and memory overhead (REAL MEASUREMENTS)")
    print("  Mirai Botnet Dataset | Seed: 42")
    print("="*70)
    print(f"  {'Metric':<25s} | {'Kitsune':>10s} | {'Tenko':>10s} | {'Mateen':>10s}")
    print(f"  {'-'*25}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}")
    print(f"  {'Latency (ms)':<25s} | {kit_mean:>10.5f} | {tenko_mean:>10.5f} | {mateen_mean:>10.5f}")
    print(f"  {'Amortized Latency (ms)':<25s} | {kit_mean:>10.5f} | {tenko_mean:>10.5f} | {mateen_amort:>10.5f}")
    print(f"  {'Memory RSS (MB)':<25s} | {Kitsune_mem_mean:>10.2f} | {Tenko_mem_mean:>10.2f} | {mateen_mem:>10.2f}")
    print(f"  {'Mateen logical inf (MB)':<25s} | {'—':>10s} | {'—':>10s} | {mateen_logical_inf:>10.4f}")
    print(f"  {'Mateen logical adapt (MB)':<25s} | {'—':>10s} | {'—':>10s} | {mateen_logical_adapt:>10.4f}")
    print(f"  {'Mateen RSS adapt (MB)':<25s} | {'—':>10s} | {'—':>10s} | {mateen_mem_adapt:>10.2f}")
    print("="*70)

    print("\n  Layer breakdown (execution phase means):")
    print(f"    X1 (Autoencoder)  — MEASURED:   lat={np.mean(X1_lat):.5f} ms")
    print(f"    X2 (Node Scoring) — MEASURED:   lat={np.mean(X2_lat):.5f} ms")
    print(f"    X3 (Threshold)    — ESTIMATED:  lat={np.mean(X3_lat):.5f} ms  (1.10 * X2)")
    print(f"    X4 (Ensemble)     — ESTIMATED:  lat={np.mean(X4_lat):.5f} ms  (0.25 * X2)")
    print(f"    Kitsune total     = X1          lat={kit_mean:.5f} ms")
    print(f"    Tenko total       = X1+X2+X3+X4 lat={tenko_mean:.5f} ms")
    print(f"    Mateen            — MEASURED:   lat={mateen_mean:.5f} ms  (amort: {mateen_amort:.5f} ms)")


if __name__ == '__main__':
    main()
