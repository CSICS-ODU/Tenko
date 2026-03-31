#!/usr/bin/env python3
"""
Real Latency & Memory Measurement: Kitsune vs Tenko vs Mateen — Mirai Botnet

Layer Definition (Tenko) — ALL LAYERS MEASURED (no estimation):
  X1: Autoencoder layer          — MEASURED (KitNET.execute)
  X2: Node-scoring layer         — MEASURED (nodeScore.update + get_score)
  X3: Centroid thresholding      — MEASURED (per-IP RMSE pattern vs global centroid)
  X4: Weighted ensemble decision — MEASURED (global-centroid flag * w + single-centroid flag * w)

  Kitsune = X1
  Tenko   = X1 + X2 + X3 + X4

Both TRAINING and EXECUTION phases are timed and memory-tracked.
Memory is reported as deep_sizeof (logical object graph, MB).

Mateen: PyTorch autoencoder — MEASURED (per-packet + amortized).

Random seed: 42 (fixed for reproducibility)

Usage:
    source .venv/bin/activate
    python setup_cython.py build_ext --inplace   # once, builds Cython X1
    python measure_all_latency.py [--skip-mateen] [--max-load-packets N]
                                  [--max-train-packets N] [--max-test-packets N]
                                  [--x3-window W] [--x3-segments S]
"""

import sys
import os
import time
import psutil
import numpy as np
from collections import deque
from pathlib import Path
from typing import Optional, Dict
from tqdm import tqdm

sys.path.insert(0, 'KitNET')
sys.path.insert(0, '.')

from memutil import aggregate_deep_sizeof, deep_sizeof
from KitNET.KitNET import KitNET
from tracker import nodeScore

# ── Configuration ─────────────────────────────────────────────────────────────
RANDOM_SEED    = 42
FM_GRACE       = 5000
AD_GRACE       = 50000
TRAINING_END   = FM_GRACE + AD_GRACE   # 55,000  — KitNET fully trained
BENIGN_LIMIT   = 100000                # X3/X4 centroid models warm up through here
TSV_FILE       = "dataset/Mirai/Mirai_pcap.pcap.tsv"
MEMORY_SIZE    = 50                    # nodeScore sliding-window size

# X3/X4 centroid defaults (tuned for <10 µs combined target)
DEFAULT_X3_WINDOW   = 20   # RMSE window length per IP
DEFAULT_X3_SEGMENTS = 5    # Segments used to build the pattern vector

# Weighted ensemble weights and threshold (X4)
W_GLOBAL            = 0.5
W_SINGLE            = 0.5
ENSEMBLE_THRESHOLD  = 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# Centroid-based pattern recognizer (inline — no import from results.py)
# ═══════════════════════════════════════════════════════════════════════════════

class _CentroidRecognizer:
    """
    Sliding-window RMSE centroid recognizer, optimised for sub-10-µs inference.

    Key optimisations vs the naive version:
    - Window stored as a plain list (ring buffer via head pointer) — no deque
      overhead, contiguous memory, fast numpy view.
    - Segment sums maintained incrementally: updating one slot costs O(1),
      rebuilding the segment-mean vector is O(segments) not O(window_size).
    - `is_known()` does one np.dot for the norm — no temporary array.
    """
    __slots__ = (
        'window_size', 'segments', 'seg_len', 'tol_factor',
        '_buf', '_head', '_full',
        '_seg_sums',          # running sum per segment [segments]
        'training_vecs', 'centroid', 'tol',
    )

    def __init__(self, window_size: int, segments: int, tol_factor: float = 1.1):
        self.window_size = window_size
        self.segments    = segments
        self.seg_len     = max(1, window_size // segments)
        self.tol_factor  = tol_factor
        self._buf        = np.zeros(window_size, dtype=np.float64)
        self._head       = 0
        self._full       = False
        self._seg_sums   = np.zeros(segments, dtype=np.float64)
        self.training_vecs: list = []
        self.centroid: Optional[np.ndarray] = None
        self.tol: Optional[float]           = None

    def update(self, value: float):
        old_val  = self._buf[self._head]
        seg_idx  = self._head // self.seg_len
        if seg_idx >= self.segments:          # guard for window_size % segments != 0
            seg_idx = self.segments - 1
        self._seg_sums[seg_idx] += value - old_val
        self._buf[self._head]    = value
        self._head               = (self._head + 1) % self.window_size
        if not self._full and self._head == 0:
            self._full = True

    def _vec(self) -> Optional[np.ndarray]:
        if not self._full:
            return None
        return self._seg_sums / self.seg_len   # shape (segments,)

    def learn_current(self):
        v = self._vec()
        if v is not None:
            self.training_vecs.append(v.copy())

    def finalize_training(self):
        if not self.training_vecs:
            return
        arr           = np.stack(self.training_vecs, axis=0)
        self.centroid = arr.mean(axis=0)
        diffs         = arr - self.centroid
        dists         = np.sqrt((diffs * diffs).sum(axis=1))
        self.tol      = float(dists.max()) * self.tol_factor if len(dists) > 0 else 0.0

    def is_known(self) -> bool:
        if self.centroid is None or self.tol is None:
            return True
        v = self._vec()
        if v is None:
            return True
        d = v - self.centroid
        return float(np.dot(d, d) ** 0.5) <= self.tol


# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: Load features from TSV
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
        if len(features) % 100_000 == 0:
            print(f"  Loaded {len(features):,} packets …")

    print(f"  Total packets: {len(features):,}")
    return np.array(features), src_ips, n_features


# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: Full pipeline — train and execute, all 4 layers timed + memory
# ═══════════════════════════════════════════════════════════════════════════════

def measure_all_layers(
    features, src_ips, n_features,
    max_train_packets=None,
    max_test_packets=None,
    node_thread_safe=False,
    x3_window=DEFAULT_X3_WINDOW,
    x3_segments=DEFAULT_X3_SEGMENTS,
    x3_tol_factor=1.1,
    w_global=W_GLOBAL,
    w_single=W_SINGLE,
    ensemble_threshold=ENSEMBLE_THRESHOLD,
):
    """
    Two phases, all 4 layers timed per-packet in each phase.

    TRAINING PHASE  (pkts TRAINING_END → BENIGN_LIMIT-1):
      X1 not timed (KitNET already done); X2, X3, X4 timed.

    EXECUTION PHASE (pkts BENIGN_LIMIT → end):
      X1, X2, X3, X4 all timed.

    Memory is reported as deep_sizeof (logical MB), sampled every 500 packets
    during training and every packet during execution.

    Returns a dict with 'train' and 'exec' sub-dicts each containing:
      lat_{x1..x4}_ms  : np.ndarray  per-packet latencies (ms)
      mem_{x1..x4}_mb  : np.ndarray  per-packet deep_sizeof delta (MB)
    and global scalars:
      rss_after_kitnet_train_mb
      rss_after_calib_mb
      rss_after_exec_mb
    """
    process = psutil.Process(os.getpid())

    print("\n" + "=" * 66)
    print("  MEASURING X1–X4 (Training + Execution)")
    print(f"  X3: window={x3_window}, segments={x3_segments}")
    print(f"  X4: w_global={w_global}, w_single={w_single}, threshold={ensemble_threshold}")
    print("=" * 66)

    # ── Phase 0: KitNET weight training (pkts 0 → TRAINING_END-1) ─────────────
    # Not timed; just builds the AE ensemble weights.
    kitnet = KitNET(
        n=n_features,
        max_autoencoder_size=10,
        FM_grace_period=FM_GRACE,
        AD_grace_period=AD_GRACE,
        learning_rate=0.1,
        hidden_ratio=0.75,
    )
    train_end = min(TRAINING_END, len(features))
    if max_train_packets is not None:
        train_end = min(train_end, int(max_train_packets))

    for i in tqdm(range(train_end), desc="KitNET Weight Training"):
        kitnet.train(features[i])

    rss_after_kitnet = process.memory_info().rss / (1024 * 1024)
    print(f"  RSS after KitNET weight training: {rss_after_kitnet:.2f} MB")

    # ── Initialise X2 / X3 / X4 models ───────────────────────────────────────
    node_score = nodeScore(MEMORY_SIZE, mode='offline', thread_safe=node_thread_safe)

    per_ip_recs: Dict[str, _CentroidRecognizer] = {}
    single_rec  = _CentroidRecognizer(x3_window, x3_segments, x3_tol_factor)

    global_centroid: Optional[np.ndarray] = None
    global_tol: Optional[float]           = None

    # ── Phase 1: Calibration training (pkts TRAINING_END → BENIGN_LIMIT-1) ───
    # X2, X3, X4 are TIMED here (X1 is frozen — execute() not timed in training
    # but we call it to get the RMSE that feeds X2/X3/X4).
    calib_start = min(TRAINING_END, len(features))
    calib_end   = min(BENIGN_LIMIT, len(features))
    n_calib     = calib_end - calib_start

    train_lat_x2 = np.empty(n_calib)
    train_lat_x3 = np.empty(n_calib)
    train_lat_x4 = np.empty(n_calib)

    # deep_sizeof memory samples — measured every MEM_SAMPLE_INTERVAL packets
    MEM_SAMPLE_INTERVAL = 500
    _last_ds_ns = aggregate_deep_sizeof(node_score, per_ip_recs, single_rec)
    train_mem_x2 = np.empty(n_calib)
    train_mem_x3 = np.empty(n_calib)
    train_mem_x4 = np.empty(n_calib)

    print(f"\n  Phase 1 — Calibration training ({n_calib:,} packets) …")
    for idx in tqdm(range(n_calib), desc="Calibration Training"):
        i  = calib_start + idx
        ip = src_ips[i] if i < len(src_ips) else f"ip_{i}"
        rmse_raw  = kitnet.execute(features[i])
        rmse_clip = float(np.clip(rmse_raw, 0.0, 1.0))

        # ── X2 training ──────────────────────────────────────────────────────
        t0 = time.perf_counter()
        node_score.update(ip, i, rmse_clip)
        try:
            score = node_score.scores[ip].get_score()
        except KeyError:
            score = rmse_clip
        t1 = time.perf_counter()
        train_lat_x2[idx] = (t1 - t0) * 1000.0

        # ── X3 training (per-IP centroid) ─────────────────────────────────────
        t2 = time.perf_counter()
        if ip not in per_ip_recs:
            per_ip_recs[ip] = _CentroidRecognizer(x3_window, x3_segments, x3_tol_factor)
        per_ip_recs[ip].update(score)
        per_ip_recs[ip].learn_current()
        t3 = time.perf_counter()
        train_lat_x3[idx] = (t3 - t2) * 1000.0

        # ── X4 training (single aggregate centroid) ───────────────────────────
        t4 = time.perf_counter()
        single_rec.update(score)
        single_rec.learn_current()
        t5 = time.perf_counter()
        train_lat_x4[idx] = (t5 - t4) * 1000.0

        # Memory (sampled periodically to avoid slow deep_sizeof on every pkt)
        if idx % MEM_SAMPLE_INTERVAL == 0:
            _last_ds_ns = aggregate_deep_sizeof(node_score, per_ip_recs, single_rec)
        _ds = _last_ds_ns / (1024 * 1024)
        train_mem_x2[idx] = _ds
        train_mem_x3[idx] = _ds   # shared object graph; reported together
        train_mem_x4[idx] = _ds

    # ── Finalise centroid models ───────────────────────────────────────────────
    print("  Finalising centroid models …")
    valid_cents, valid_tols = [], []
    for pr in per_ip_recs.values():
        pr.finalize_training()
        if pr.centroid is not None and pr.tol is not None:
            valid_cents.append(pr.centroid)
            valid_tols.append(pr.tol)

    if valid_cents:
        global_centroid = np.mean(np.stack(valid_cents, axis=0), axis=0)
        global_tol      = float(np.mean(valid_tols))
        print(f"  Global centroid ready — shape {global_centroid.shape}, tol {global_tol:.6f}")
    else:
        print("  [Warning] No valid per-IP centroids — X3 global model unavailable.")

    single_rec.finalize_training()
    if single_rec.centroid is not None:
        print(f"  Single-aggregate centroid ready — tol {single_rec.tol:.6f}")
    else:
        print("  [Warning] Single-aggregate centroid unavailable.")

    rss_after_calib = process.memory_info().rss / (1024 * 1024)
    ds_after_calib  = aggregate_deep_sizeof(kitnet, node_score, per_ip_recs, single_rec) / (1024 * 1024)
    print(f"  RSS after calibration: {rss_after_calib:.2f} MB  |  deep_sizeof: {ds_after_calib:.4f} MB")

    # ── Phase 2: Execution / inference (pkts BENIGN_LIMIT → end) ─────────────
    exec_start = min(BENIGN_LIMIT, len(features))
    exec_end   = len(features)
    if max_test_packets is not None:
        exec_end = min(exec_end, exec_start + int(max_test_packets))
    n_exec = exec_end - exec_start
    print(f"\n  Phase 2 — Execution ({n_exec:,} packets) …")

    exec_lat_x1 = np.empty(n_exec)
    exec_lat_x2 = np.empty(n_exec)
    exec_lat_x3 = np.empty(n_exec)
    exec_lat_x4 = np.empty(n_exec)

    exec_mem_x1 = np.empty(n_exec)
    exec_mem_x2 = np.empty(n_exec)
    exec_mem_x3 = np.empty(n_exec)
    exec_mem_x4 = np.empty(n_exec)

    _last_ds_exec = deep_sizeof(kitnet) / (1024 * 1024)

    for idx in tqdm(range(n_exec), desc="X1+X2+X3+X4 Inference"):
        i  = exec_start + idx
        ip = src_ips[i] if i < len(src_ips) else f"ip_{i}"

        # ── X1: KitNET autoencoder ────────────────────────────────────────────
        t0 = time.perf_counter()
        rmse_raw = kitnet.execute(features[i])
        t1 = time.perf_counter()
        exec_lat_x1[idx] = (t1 - t0) * 1000.0
        if idx % MEM_SAMPLE_INTERVAL == 0:
            _last_ds_exec = deep_sizeof(kitnet) / (1024 * 1024)
        exec_mem_x1[idx] = _last_ds_exec

        rmse_clip = float(np.clip(rmse_raw, 0.0, 1.0))

        # ── X2: Node scoring ──────────────────────────────────────────────────
        _last_ds_x2 = deep_sizeof(node_score) / (1024 * 1024)
        t2 = time.perf_counter()
        node_score.update(ip, i, rmse_clip)
        try:
            score = node_score.scores[ip].get_score()
        except KeyError:
            score = rmse_clip
        t3 = time.perf_counter()
        exec_lat_x2[idx] = (t3 - t2) * 1000.0
        exec_mem_x2[idx] = _last_ds_x2

        # ── X3: Per-IP centroid distance check ────────────────────────────────
        _last_ds_x3 = deep_sizeof(per_ip_recs) / (1024 * 1024)
        t4 = time.perf_counter()
        if ip not in per_ip_recs:
            per_ip_recs[ip] = _CentroidRecognizer(x3_window, x3_segments, x3_tol_factor)
            if global_centroid is not None:
                per_ip_recs[ip].centroid = global_centroid
                per_ip_recs[ip].tol      = global_tol
        pr = per_ip_recs[ip]
        pr.update(score)
        flag_global = (not pr.is_known()) if global_centroid is not None else False
        t5 = time.perf_counter()
        exec_lat_x3[idx] = (t5 - t4) * 1000.0
        exec_mem_x3[idx] = _last_ds_x3

        # ── X4: Weighted ensemble decision ────────────────────────────────────
        _last_ds_x4 = deep_sizeof(single_rec) / (1024 * 1024)
        t6 = time.perf_counter()
        single_rec.update(score)
        flag_single = (not single_rec.is_known())
        combined    = w_global * flag_global + w_single * flag_single
        _pred       = 1 if combined >= ensemble_threshold else 0  # noqa: F841
        t7 = time.perf_counter()
        exec_lat_x4[idx] = (t7 - t6) * 1000.0
        exec_mem_x4[idx] = _last_ds_x4

        if (idx + 1) % 100_000 == 0:
            print(
                f"    [{idx+1:>7}/{n_exec}] "
                f"X1 avg={np.mean(exec_lat_x1[:idx+1]):.5f} ms  "
                f"X2 avg={np.mean(exec_lat_x2[:idx+1]):.5f} ms  "
                f"X3 avg={np.mean(exec_lat_x3[:idx+1]):.5f} ms  "
                f"X4 avg={np.mean(exec_lat_x4[:idx+1]):.5f} ms"
            )

    rss_after_exec = process.memory_info().rss / (1024 * 1024)

    # ── Print execution-phase summary ─────────────────────────────────────────
    print(f"\n  X1 (Autoencoder) — MEASURED (execution):")
    print(f"    Mean latency:   {np.mean(exec_lat_x1):.5f} ms  |  Median: {np.median(exec_lat_x1):.5f} ms")
    print(f"    Mean deep_sizeof: {np.mean(exec_mem_x1):.4f} MB")

    print(f"\n  X2 (Node Scoring) — MEASURED (execution):")
    print(f"    Mean latency:   {np.mean(exec_lat_x2):.5f} ms  |  Median: {np.median(exec_lat_x2):.5f} ms")
    print(f"    Mean deep_sizeof: {np.mean(exec_mem_x2):.4f} MB")

    print(f"\n  X3 (Centroid Threshold) — MEASURED (execution):")
    print(f"    Mean latency:   {np.mean(exec_lat_x3):.5f} ms  |  Median: {np.median(exec_lat_x3):.5f} ms")
    print(f"    Mean deep_sizeof: {np.mean(exec_mem_x3):.4f} MB")
    x3x4_budget = np.mean(exec_lat_x3) + np.mean(exec_lat_x4)
    budget_met  = "✓ UNDER" if x3x4_budget < 0.01 else "✗ OVER"
    print(f"\n  X4 (Weighted Ensemble) — MEASURED (execution):")
    print(f"    Mean latency:   {np.mean(exec_lat_x4):.5f} ms  |  Median: {np.median(exec_lat_x4):.5f} ms")
    print(f"    Mean deep_sizeof: {np.mean(exec_mem_x4):.4f} MB")
    print(f"\n  X3+X4 combined mean: {x3x4_budget:.5f} ms  [{budget_met} 0.01 ms target]")

    return {
        "train": {
            "lat_x2": train_lat_x2,
            "lat_x3": train_lat_x3,
            "lat_x4": train_lat_x4,
            "mem_x2": train_mem_x2,
            "mem_x3": train_mem_x3,
            "mem_x4": train_mem_x4,
        },
        "exec": {
            "lat_x1": exec_lat_x1,
            "lat_x2": exec_lat_x2,
            "lat_x3": exec_lat_x3,
            "lat_x4": exec_lat_x4,
            "mem_x1": exec_mem_x1,
            "mem_x2": exec_mem_x2,
            "mem_x3": exec_mem_x3,
            "mem_x4": exec_mem_x4,
        },
        "rss_after_kitnet_train_mb": rss_after_kitnet,
        "rss_after_calib_mb":        rss_after_calib,
        "rss_after_exec_mb":         rss_after_exec,
        "ds_after_calib_mb":         ds_after_calib,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: Measure Mateen (PyTorch autoencoder)
# ═══════════════════════════════════════════════════════════════════════════════

def measure_mateen():
    import torch
    import torch.nn as nn

    sys.path.insert(0, 'mateen_reference/MateenUtils')
    import data_processing as dp
    import main as Mateen_main
    import utils as mateen_utils

    device      = "cuda" if torch.cuda.is_available() else "cpu"
    getMSEvec   = nn.MSELoss(reduction='none')

    def se2rmse(a):
        return torch.sqrt(sum(a.t()) / a.shape[1])

    process = psutil.Process(os.getpid())
    print("\n" + "=" * 62)
    print("  MEASURING MATEEN (PyTorch Autoencoder)")
    print("=" * 62)

    orig_cwd = os.getcwd()
    os.chdir('mateen_reference')

    x_train, x_test, y_train, y_test = dp.prepare_data(scenario="Mirai")
    print(f"  Train: {x_train.shape}   Test: {x_test.shape}")

    model = Mateen_main.ensemble_training(
        x_train, y_train=y_train, num_epochs=100,
        mode="init", scenario="Mirai",
    )
    benign_train = x_train[y_train == 0]
    threshold    = mateen_utils.threshold_calulation(model, benign_train)
    os.chdir(orig_cwd)

    mem_after_train   = process.memory_info().rss / (1024 * 1024)
    mem_logical_inf   = aggregate_deep_sizeof(model, benign_train, [threshold]) / (1024 * 1024)
    print(f"  RSS after training: {mem_after_train:.2f} MB  |  logical: {mem_logical_inf:.4f} MB")

    n_test      = len(x_test)
    latencies_ms = []
    model.eval()
    with torch.no_grad():
        for i in tqdm(range(n_test), desc="Mateen Inference"):
            sample = torch.from_numpy(x_test[i:i+1]).float().to(device)
            t0     = time.perf_counter()
            output = model(sample)
            rmse   = se2rmse(getMSEvec(output, sample)).cpu().numpy()[0]
            _pred  = 1 if rmse > threshold else 0  # noqa: F841
            t1     = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000)

    mem_after_exec = process.memory_info().rss / (1024 * 1024)
    latencies_ms   = np.array(latencies_ms)

    print("  Running adaptive_ensemble for amortized measurement …")
    os.chdir('mateen_reference')
    x_slice, y_slice = dp.partition_array(x_test, y_test, slice_size=50000)
    args_obj = type('args', (), {
        'dataset_name': 'Mirai', 'window_size': 50000,
        'performance_thres': 0.99, 'max_ensemble_length': 3,
        'selection_budget': 0.01, 'mini_batch_size': 1000,
        'retention_rate': 0.3, 'lambda_0': 0.1,
        'shift_threshold': 0.05,
    })()
    t_start = time.perf_counter()
    preds, probs, models_list, threshold_list, benign_final = Mateen_main.adaptive_ensemble(
        x_train, y_train, x_slice, y_slice, args_obj,
    )
    amortized_ms = ((time.perf_counter() - t_start) / n_test) * 1000
    os.chdir(orig_cwd)

    mem_adaptive      = process.memory_info().rss / (1024 * 1024)
    mem_logical_adapt = aggregate_deep_sizeof(*models_list, threshold_list, benign_final) / (1024 * 1024)

    print(f"\n  Mateen — MEASURED:")
    print(f"    Mean latency:      {np.mean(latencies_ms):.5f} ms")
    print(f"    Amortized latency: {amortized_ms:.5f} ms/pkt")
    print(f"    RSS (inference):   {mem_after_exec:.2f} MB  |  logical: {mem_logical_inf:.4f} MB")
    print(f"    RSS (adaptive):    {mem_adaptive:.2f} MB  |  logical: {mem_logical_adapt:.4f} MB")

    return latencies_ms, mem_after_exec, amortized_ms, mem_adaptive, mem_logical_inf, mem_logical_adapt


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Kitsune / Tenko / Mateen real latency on Mirai — all layers measured"
    )
    p.add_argument("--max-load-packets",  type=int, default=None)
    p.add_argument("--max-train-packets", type=int, default=None,
                   help="Limit KitNET weight-training packets (default: TRAINING_END=55000)")
    p.add_argument("--max-test-packets",  type=int, default=None,
                   help="Limit execution-phase packets timed (default: all after BENIGN_LIMIT)")
    p.add_argument("--skip-mateen",  action="store_true")
    p.add_argument("--x3-window",    type=int, default=DEFAULT_X3_WINDOW,
                   help=f"X3 centroid window size (default {DEFAULT_X3_WINDOW})")
    p.add_argument("--x3-segments",  type=int, default=DEFAULT_X3_SEGMENTS,
                   help=f"X3 centroid segments (default {DEFAULT_X3_SEGMENTS})")
    args = p.parse_args()

    print("=" * 66)
    print("  REAL LATENCY & MEMORY MEASUREMENT  (correct-latency branch)")
    print("  Kitsune vs Tenko vs Mateen — Mirai Botnet")
    print(f"  Seed: {RANDOM_SEED}  |  X3 window={args.x3_window}  segments={args.x3_segments}")
    print("=" * 66)

    features, src_ips, n_features = load_mirai_features(max_packets=args.max_load_packets)

    R = measure_all_layers(
        features, src_ips, n_features,
        max_train_packets=args.max_train_packets,
        max_test_packets=args.max_test_packets,
        node_thread_safe=False,
        x3_window=args.x3_window,
        x3_segments=args.x3_segments,
    )

    TR, EX = R["train"], R["exec"]

    if args.skip_mateen:
        mateen_lat = np.array([0.0])
        mateen_mem = mateen_amort = mateen_mem_adapt = 0.0
        mateen_logical_inf = mateen_logical_adapt = 0.0
        print("\n  [Skipped Mateen --skip-mateen]")
    else:
        (mateen_lat, mateen_mem, mateen_amort, mateen_mem_adapt,
         mateen_logical_inf, mateen_logical_adapt) = measure_mateen()

    # ── Compute layer totals ───────────────────────────────────────────────────
    # Training phase: X1 is frozen (not timed) so Tenko_train = X2+X3+X4
    # Execution phase: Tenko = X1+X2+X3+X4
    train_tenko = TR["lat_x2"] + TR["lat_x3"] + TR["lat_x4"]
    exec_kitsune = EX["lat_x1"]
    exec_tenko   = EX["lat_x1"] + EX["lat_x2"] + EX["lat_x3"] + EX["lat_x4"]

    x3x4_combined = np.mean(EX["lat_x3"]) + np.mean(EX["lat_x4"])
    budget_met    = "YES" if x3x4_combined < 0.01 else "NO"

    # ── Save .npz ─────────────────────────────────────────────────────────────
    out_path = Path("mirai_performance_results") / f"real_latency_arrays_seed{RANDOM_SEED}.npz"
    out_path.parent.mkdir(exist_ok=True)
    np.savez_compressed(
        out_path,
        # training phase
        train_lat_x2=TR["lat_x2"], train_lat_x3=TR["lat_x3"], train_lat_x4=TR["lat_x4"],
        train_mem_x2=TR["mem_x2"], train_mem_x3=TR["mem_x3"], train_mem_x4=TR["mem_x4"],
        # execution phase
        exec_lat_x1=EX["lat_x1"], exec_lat_x2=EX["lat_x2"],
        exec_lat_x3=EX["lat_x3"], exec_lat_x4=EX["lat_x4"],
        exec_mem_x1=EX["mem_x1"], exec_mem_x2=EX["mem_x2"],
        exec_mem_x3=EX["mem_x3"], exec_mem_x4=EX["mem_x4"],
        # mateen
        mateen_lat=mateen_lat,
        mateen_logical_inf_mb=np.array(mateen_logical_inf,  dtype=np.float64),
        mateen_logical_adapt_mb=np.array(mateen_logical_adapt, dtype=np.float64),
        seed=np.array([RANDOM_SEED]),
    )
    print(f"\n  Raw arrays saved → {out_path}")

    # ── Final table ───────────────────────────────────────────────────────────
    # Per-layer mean deep_sizeof memory (MB)
    x1_mem_mb   = float(np.mean(EX["mem_x1"]))
    x2_mem_mb   = float(np.mean(EX["mem_x2"]))
    x3_mem_mb   = float(np.mean(EX["mem_x3"]))
    x4_mem_mb   = float(np.mean(EX["mem_x4"]))

    kitsune_mem_mb = x1_mem_mb
    tenko_mem_mb   = x1_mem_mb + x2_mem_mb + x3_mem_mb + x4_mem_mb

    kit_exec  = float(np.mean(exec_kitsune))
    tenk_exec = float(np.mean(exec_tenko))
    tenk_train = float(np.mean(train_tenko))
    mateen_mean = float(np.mean(mateen_lat))

    print("\n" + "=" * 78)
    print("  TABLE X: Computational and Memory Overhead (REAL MEASUREMENTS)")
    print("  Mirai Botnet Dataset | Seed: 42 | X3/X4 MEASURED (centroid + ensemble)")
    print("=" * 78)
    print(f"  {'Metric':<30s} | {'Kitsune':>10s} | {'Tenko':>10s} | {'Mateen':>10s}")
    print(f"  {'-'*30}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}")
    print(f"  {'Exec latency (ms)':<30s} | {kit_exec:>10.5f} | {tenk_exec:>10.5f} | {mateen_mean:>10.5f}")
    print(f"  {'Train latency (ms)':<30s} | {'—':>10s} | {tenk_train:>10.5f} | {'—':>10s}")
    print(f"  {'Amortized latency (ms)':<30s} | {kit_exec:>10.5f} | {tenk_exec:>10.5f} | {mateen_amort:>10.5f}")
    print(f"  {'Memory deep_sizeof (MB)':<30s} | {kitsune_mem_mb:>10.4f} | {tenko_mem_mb:>10.4f} | {mateen_logical_inf:>10.4f}")
    print(f"  {'Memory RSS exec (MB)':<30s} | {R['rss_after_exec_mb']:>10.2f} | {R['rss_after_exec_mb']:>10.2f} | {mateen_mem:>10.2f}")
    print(f"  {'Mateen logical adapt (MB)':<30s} | {'—':>10s} | {'—':>10s} | {mateen_logical_adapt:>10.4f}")
    print("=" * 78)

    print("\n  Layer breakdown — EXECUTION phase (mean per packet):")
    print(f"  {'Layer':<28} {'Lat (ms)':>10} {'Mem deep_sizeof (MB)':>22}")
    print(f"  {'-'*60}")
    print(f"  {'X1 (Autoencoder)':<28} {np.mean(EX['lat_x1']):>10.5f} {x1_mem_mb:>22.4f}")
    print(f"  {'X2 (Node Scoring)':<28} {np.mean(EX['lat_x2']):>10.5f} {x2_mem_mb:>22.4f}")
    print(f"  {'X3 (Centroid Threshold)':<28} {np.mean(EX['lat_x3']):>10.5f} {x3_mem_mb:>22.4f}")
    print(f"  {'X4 (Weighted Ensemble)':<28} {np.mean(EX['lat_x4']):>10.5f} {x4_mem_mb:>22.4f}")
    print(f"  {'-'*60}")
    print(f"  {'Kitsune total (=X1)':<28} {kit_exec:>10.5f} {kitsune_mem_mb:>22.4f}")
    print(f"  {'Tenko total (X1+X2+X3+X4)':<28} {tenk_exec:>10.5f} {tenko_mem_mb:>22.4f}")

    print("\n  Layer breakdown — TRAINING phase (mean per calibration packet):")
    print(f"  {'Layer':<28} {'Lat (ms)':>10} {'Mem deep_sizeof (MB)':>22}")
    print(f"  {'-'*60}")
    print(f"  {'X1 (frozen — not timed)':<28} {'—':>10} {'—':>22}")
    print(f"  {'X2 (Node Scoring train)':<28} {np.mean(TR['lat_x2']):>10.5f} {np.mean(TR['mem_x2']):>22.4f}")
    print(f"  {'X3 (Centroid train)':<28} {np.mean(TR['lat_x3']):>10.5f} {np.mean(TR['mem_x3']):>22.4f}")
    print(f"  {'X4 (Single centroid train)':<28} {np.mean(TR['lat_x4']):>10.5f} {np.mean(TR['mem_x4']):>22.4f}")

    print(f"\n  X3+X4 combined exec mean: {x3x4_combined:.5f} ms  "
          f"[<0.01 ms target: {budget_met}]")
    print(f"  Mateen — MEASURED: lat={mateen_mean:.5f} ms  (amort: {mateen_amort:.5f} ms)")


if __name__ == '__main__':
    main()
