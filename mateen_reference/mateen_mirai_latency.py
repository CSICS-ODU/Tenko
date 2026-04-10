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
from memutil import deep_sizeof, aggregate_deep_sizeof

device = "cuda" if torch.cuda.is_available() else "cpu"
getMSEvec = nn.MSELoss(reduction='none')


def se2rmse(a):
    return torch.sqrt(sum(a.t()) / a.shape[1])


def _bytes_to_mb(b):
    return b / (1024 * 1024)


def _print_mateen_object_breakdown(label, model, benign_train, threshold_val):
    """Print AE weights, benign numpy buffer, thresholds, and aggregate logical size."""
    thr_container = threshold_val if isinstance(threshold_val, (list, tuple)) else [threshold_val]
    w = deep_sizeof(model)
    buf = deep_sizeof(benign_train)
    thr = deep_sizeof(thr_container)
    total = aggregate_deep_sizeof(model, benign_train, thr_container)
    print(f"  {label} (deep_sizeof, deduplicated):")
    print(f"    Autoencoder weights/buffers: {_bytes_to_mb(w):.4f} MB")
    print(f"    benign_train buffer (numpy): {_bytes_to_mb(buf):.4f} MB")
    print(f"    Threshold(s) (Python floats): {_bytes_to_mb(thr):.6f} MB")
    print(f"    Total logical state:         {_bytes_to_mb(total):.4f} MB")


def _print_ensemble_breakdown(models_list, threshold_list, benign_train):
    print("  Adaptive pipeline — object-level memory (after run):")
    for i, m in enumerate(models_list):
        print(f"    Ensemble model[{i}] (AE):    {_bytes_to_mb(deep_sizeof(m)):>12.4f} MB")
    thr_sz = deep_sizeof(threshold_list)
    buf_sz = deep_sizeof(benign_train)
    print(f"    threshold_list:                {_bytes_to_mb(thr_sz):>12.6f} MB")
    print(f"    benign_train (final, numpy): {_bytes_to_mb(buf_sz):>12.4f} MB")
    agg = aggregate_deep_sizeof(*models_list, threshold_list, benign_train)
    print(f"    Total (ensemble + buffers):    {_bytes_to_mb(agg):>12.4f} MB")
    print(f"    (n_models={len(models_list)})")


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

    # So adaptive_ensemble() does not train again from scratch (saves ~30+ min and RAM).
    os.makedirs("Models", exist_ok=True)
    ckpt = "Models/Mirai.pth"
    torch.save(model, ckpt)
    print(f"  Saved checkpoint → {ckpt} (adaptive_ensemble will load this, not retrain)")

    benign_train = x_train[y_train == 0]
    threshold = mateen_utils.threshold_calulation(model, benign_train)
    print(f"  Threshold: {threshold:.6f}")

    # ── 3. Memory after model is loaded ───────────────────────────────────────
    mem_rss_loaded = process.memory_info().rss / (1024 * 1024)
    print(f"  Memory — RSS (process-level):  {mem_rss_loaded:.2f} MB")
    _print_mateen_object_breakdown("After training (inference-ready detector)", model, benign_train, threshold)

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
    mem_obj_inference = aggregate_deep_sizeof(model, benign_train, [threshold]) / (1024 * 1024)
    latencies_ms = np.array(latencies_ms)

    # ── 5. Full adaptive pipeline (amortized, including adaptation) ───────────
    skip_adaptive = os.environ.get("MATEEN_SKIP_ADAPTIVE", "").strip().lower() in (
        "1", "true", "yes",
    )
    if skip_adaptive:
        print(
            "\nSkipping adaptive_ensemble (MATEEN_SKIP_ADAPTIVE=1). "
            "Use on Pi 1GB to avoid OOM; run without it on a larger machine for amortized + F1."
        )
        total_s = 0.0
        amortized_ms = float("nan")
        mem_rss_adaptive = process.memory_info().rss / (1024 * 1024)
        mem_obj_adaptive = mem_obj_inference
        models_list = [model]
        threshold_list = [threshold]
        benign_train_final = benign_train
        preds = None
    else:
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
        preds, probs, models_list, threshold_list, benign_train_final = Mateen_main.adaptive_ensemble(
            x_train, y_train, x_slice, y_slice, args_obj
        )
        t_full_end = time.perf_counter()
        total_s = t_full_end - t_full_start
        amortized_ms = (total_s / len(x_test)) * 1000

        mem_rss_adaptive = process.memory_info().rss / (1024 * 1024)
        mem_obj_adaptive = aggregate_deep_sizeof(*models_list, threshold_list, benign_train_final) / (1024 * 1024)

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
    print(f"  Memory (after per-packet inference, no adaptation):")
    print(f"    RSS (process-level):   {mem_rss_inference:.2f} MB")
    print(f"    Logical state (AE + benign_train + threshold): {mem_obj_inference:.4f} MB")
    print()
    print(f"  Amortized (with adaptation):")
    if skip_adaptive:
        print(f"    Total wall time:    (skipped)")
        print(f"    Amortized per-pkt:  (skipped)")
    else:
        print(f"    Total wall time:    {total_s:.2f} s")
        print(f"    Amortized per-pkt:  {amortized_ms:.5f} ms")
    print(f"    RSS (adaptive):     {mem_rss_adaptive:.2f} MB")
    print(f"    Logical state (full ensemble + buffers): {mem_obj_adaptive:.4f} MB")
    if not skip_adaptive:
        _print_ensemble_breakdown(models_list, threshold_list, benign_train_final)
    print()
    print("=" * 70)
    print("  MATEEN SUMMARY")
    print("-" * 70)
    print(f"  {'Metric':<30s} {'Value':>15s}")
    print(f"  {'-'*45}")
    print(f"  {'Latency (ms/pkt)':30s} {np.mean(latencies_ms):>15.5f}")
    amort_str = f"{amortized_ms:>15.5f}" if not np.isnan(amortized_ms) else f"{'skipped':>15s}"
    print(f"  {'Amortized Latency (ms/pkt)':30s} {amort_str}")
    print(f"  {'Memory — logical (inf) MB':30s} {mem_obj_inference:>15.4f}")
    print(f"  {'Memory — logical (adapt) MB':30s} {mem_obj_adaptive:>15.4f}")
    print(f"  {'Memory — RSS inf (MB)':30s} {mem_rss_inference:>15.2f}")
    print(f"  {'Memory — RSS adapt (MB)':30s} {mem_rss_adaptive:>15.2f}")
    print("=" * 70)

    # ── 7. Classification metrics ─────────────────────────────────────────────
    if preds is not None:
        print("\nClassification metrics (full adaptive pipeline):")
        mateen_utils.getResult(y_test, preds)


if __name__ == '__main__':
    measure_mateen_overhead()
