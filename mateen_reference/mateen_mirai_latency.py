"""
Measure Mateen end-to-end latency and memory on the Mirai botnet dataset.

Produces numbers comparable to the Kitsune/Tenko overhead table:
  - Per-packet inference latency (ms)
  - Process memory footprint (MB)
"""

import sys
import os
sys.path.insert(0, 'MateenUtils/')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import time
import psutil
import numpy as np
import torch
import torch.nn as nn
import data_processing as dp
import main as Mateen_main
import utils as mateen_utils
import AE as model_base
from memutil import deep_sizeof

device = "cuda" if torch.cuda.is_available() else "cpu"
getMSEvec = nn.MSELoss(reduction='none')


def se2rmse(a):
    return torch.sqrt(sum(a.t()) / a.shape[1])


def measure_mateen_overhead():
    process = psutil.Process(os.getpid())

    # ── 1. Load Mirai data ────────────────────────────────────────────────────
    print("Loading Mirai dataset …")
    x_train, x_test, y_train, y_test = dp.prepare_data(scenario="Mirai")
    print(f"  Train: {x_train.shape}   Test: {x_test.shape}")

    # ── 2. Train / load model ─────────────────────────────────────────────────
    print("Training Mateen autoencoder (100 epochs) …")
    t_train_start = time.perf_counter()
    model = Mateen_main.ensemble_training(
        x_train, y_train=y_train, num_epochs=100,
        mode="init", scenario="Mirai"
    )
    t_train_end = time.perf_counter()
    print(f"  Training time: {t_train_end - t_train_start:.2f} s")

    benign_train = x_train[y_train == 0]
    threshold = mateen_utils.threshold_calulation(model, benign_train)
    print(f"  Threshold: {threshold:.6f}")

    # ── 3. Memory after model is loaded ───────────────────────────────────────
    mem_rss_loaded = process.memory_info().rss / (1024 * 1024)
    mem_obj_loaded = deep_sizeof(model) / (1024 * 1024)
    print(f"  Memory — RSS (process-level):  {mem_rss_loaded:.2f} MB")
    print(f"  Memory — deep_sizeof (object): {mem_obj_loaded:.4f} MB")

    # ── 4. Per-packet inference latency ───────────────────────────────────────
    print(f"\nMeasuring per-packet inference latency on {len(x_test)} test samples …")
    model.eval()
    latencies_ms = []

    with torch.no_grad():
        for i in range(len(x_test)):
            sample = torch.from_numpy(x_test[i:i+1]).float().to(device)

            t0 = time.perf_counter()
            output = model(sample)
            mse_vec = getMSEvec(output, sample)
            rmse = se2rmse(mse_vec).cpu().numpy()[0]
            pred = 1 if rmse > threshold else 0
            t1 = time.perf_counter()

            latencies_ms.append((t1 - t0) * 1000)

            if (i + 1) % 10000 == 0:
                avg = np.mean(latencies_ms[-10000:])
                print(f"  [{i+1:>6}/{len(x_test)}]  avg last 10k: {avg:.5f} ms")

    mem_rss_inference = process.memory_info().rss / (1024 * 1024)
    mem_obj_inference = deep_sizeof(model) / (1024 * 1024)
    latencies_ms = np.array(latencies_ms)

    # ── 5. Full adaptive pipeline (amortized, including adaptation) ───────────
    print("\nRunning full adaptive_ensemble pipeline …")
    x_slice, y_slice = dp.partition_array(x_test, y_test, slice_size=50000)

    args_obj = type('args', (), {
        'dataset_name': 'Mirai', 'window_size': 50000,
        'performance_thres': 0.99, 'max_ensemble_length': 3,
        'selection_budget': 0.01, 'mini_batch_size': 1000,
        'retention_rate': 0.3, 'lambda_0': 0.1,
        'shift_threshold': 0.05
    })()

    t_full_start = time.perf_counter()
    preds, probs = Mateen_main.adaptive_ensemble(
        x_train, y_train, x_slice, y_slice, args_obj
    )
    t_full_end = time.perf_counter()
    total_s = t_full_end - t_full_start
    amortized_ms = (total_s / len(x_test)) * 1000

    mem_rss_adaptive = process.memory_info().rss / (1024 * 1024)

    # ── 6. Results ────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  MATEEN END-TO-END OVERHEAD ON MIRAI BOTNET")
    print("=" * 70)
    print(f"  Per-packet inference (no adaptation):")
    print(f"    Mean latency:   {np.mean(latencies_ms):.5f} ms")
    print(f"    Median latency: {np.median(latencies_ms):.5f} ms")
    print(f"    P95 latency:    {np.percentile(latencies_ms, 95):.5f} ms")
    print(f"    P99 latency:    {np.percentile(latencies_ms, 99):.5f} ms")
    print(f"    Std:            {np.std(latencies_ms):.5f} ms")
    print()
    print(f"  Memory (after inference):")
    print(f"    RSS (process-level):   {mem_rss_inference:.2f} MB")
    print(f"    deep_sizeof (object):  {mem_obj_inference:.4f} MB")
    print()
    print(f"  Amortized (with adaptation):")
    print(f"    Total wall time:    {total_s:.2f} s")
    print(f"    Amortized per-pkt:  {amortized_ms:.5f} ms")
    print(f"    RSS (adaptive):     {mem_rss_adaptive:.2f} MB")
    print()
    print("=" * 70)
    print("  MATEEN SUMMARY")
    print("-" * 70)
    print(f"  {'Metric':<30s} {'Value':>15s}")
    print(f"  {'-'*45}")
    print(f"  {'Latency (ms/pkt)':30s} {np.mean(latencies_ms):>15.5f}")
    print(f"  {'Amortized Latency (ms/pkt)':30s} {amortized_ms:>15.5f}")
    print(f"  {'Memory — deep_sizeof (MB)':30s} {mem_obj_inference:>15.4f}")
    print(f"  {'Memory — RSS (MB)':30s} {mem_rss_inference:>15.2f}")
    print("=" * 70)

    # ── 7. Classification metrics ─────────────────────────────────────────────
    print("\nClassification metrics (full adaptive pipeline):")
    mateen_utils.getResult(y_test, preds)


if __name__ == '__main__':
    measure_mateen_overhead()
