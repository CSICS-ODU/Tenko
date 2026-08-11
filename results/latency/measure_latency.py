#!/usr/bin/env python3
"""
OFFLINE-REPLAY latency / throughput / memory measurement — Tenko vs Kitsune.

Reviewer blocker B1 (empirical part). For the "real-time at gateway rates"
claim, Reviewer #3 asked for: hardware specs, packet rate, CPU%, and packet
drop. We CANNOT measure live-NIC packet drop on this machine (no gateway
deployment / no live capture), so this script produces the honest thing we
CAN measure here: OFFLINE-REPLAY per-packet processing latency, sustained
throughput (packets/sec), peak RSS, and CPU utilisation, by replaying a
committed mixed-attack packet stream through the detection models.

WHAT IS AND IS NOT MEASURED
  MEASURED (this script):
    * Kitsune X1      : KitNET autoencoder ensemble  (kitnet.execute)
    * Tenko (full)    : X1 + node scoring (tracker.nodeScore) + tolerance
                        (per-IP centroid + weighted-ensemble decision).
    * Feature extraction (parser + AfterImage) latency is captured during
      the load pass and reported separately so a full-stack estimate is
      possible, clearly labelled as offline replay.
  NOT MEASURED (explicitly out of scope / future work):
    * Live-NIC packet capture and packet-DROP under sustained load. That
      needs an actual inline/tap deployment with a traffic generator; it is
      NOT what an offline TSV replay can measure. Reported as future work.

The two systems are compared on the SAME trained KitNET and the SAME
measurement packets, so the Tenko-vs-Kitsune delta is purely the added
node-scoring + tolerance overhead (Tenko is expected to be somewhat slower;
we report that honestly rather than hiding it).

INPUT
  results/CICIoT2023/mixed/stream_mixed.pcap.tsv   (committed mixed stream)

OUTPUT
  results/latency/latency_throughput.csv
  (stdout summary; the .md is written by hand from these numbers)

Measurements reflect SINGLE-CORE online per-packet processing (BLAS/OMP
threads pinned to 1), which is the realistic model for an online, per-packet
gateway IDS. Seed fixed at 42.

Usage:
  .venv/bin/python results/latency/measure_latency.py \
      [--tsv PATH] [--fm-grace N] [--ad-grace N] [--calib-end N] \
      [--warmup N] [--measure N] [--out CSV]
"""

# Pin math libs to a single thread BEFORE importing numpy: online per-packet
# IDS processing is single-threaded, and this keeps per-packet latency stable.
import os
for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
           "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    os.environ.setdefault(_v, "1")

import sys
import csv
import time
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List

import numpy as np
import psutil

# repo root = two levels up from results/latency/
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "KitNET"))
sys.path.insert(0, str(REPO_ROOT))
os.chdir(REPO_ROOT)  # FeatureExtractor / KitNET use repo-relative paths

from KitNET.KitNET import KitNET          # noqa: E402
from tracker import nodeScore             # noqa: E402

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

DEFAULT_TSV = "results/CICIoT2023/mixed/stream_mixed.pcap.tsv"

# ── Tolerance layer (per-IP centroid + weighted ensemble) ──────────────────────
# Copied from measure_all_latency.py (correct-latency lineage) so this script is
# self-contained and does not depend on that harness being in the tree.
W_GLOBAL           = 0.5
W_SINGLE           = 0.5
ENSEMBLE_THRESHOLD = 0.5
MEMORY_SIZE        = 50     # nodeScore sliding-window size
DEFAULT_X3_WINDOW   = 20
DEFAULT_X3_SEGMENTS = 5


class _CentroidRecognizer:
    """Sliding-window RMSE centroid recognizer (Tenko tolerance layer)."""
    __slots__ = (
        'window_size', 'segments', 'seg_len', 'tol_factor',
        '_buf', '_head', '_full', '_seg_sums',
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
        old_val = self._buf[self._head]
        seg_idx = self._head // self.seg_len
        if seg_idx >= self.segments:
            seg_idx = self.segments - 1
        self._seg_sums[seg_idx] += value - old_val
        self._buf[self._head]    = value
        self._head               = (self._head + 1) % self.window_size
        if not self._full and self._head == 0:
            self._full = True

    def _vec(self) -> Optional[np.ndarray]:
        if not self._full:
            return None
        return self._seg_sums / self.seg_len

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


# ── Load features from TSV via AfterImage (records FE latency too) ─────────────
def load_features(tsv_path: str, max_packets: int):
    from FeatureExtractor import FE
    print(f"[load] Streaming {tsv_path} through AfterImage (limit={max_packets:,}) …")
    proc = psutil.Process(os.getpid())
    fe = FE(tsv_path, max_packets)
    n_features = fe.get_num_features()
    cap = int(fe.limit)
    print(f"[load] feature dim = {n_features}  |  packets to load = {cap:,}")

    features = np.empty((cap, n_features), dtype=np.float32, order="C")
    ip_ids   = np.empty(cap, dtype=np.uint32)
    ip_intern: Dict[Any, int] = {}
    next_id  = 0
    count    = 0
    peak_rss = proc.memory_info().rss

    fe_timings: Dict[str, List[float]] = {'parse': [], 'afterimage': []}
    while True:
        x = fe.get_next_vector(timings=fe_timings)
        if len(x) == 0:
            break
        vec = np.asarray(x[0], dtype=np.float32).ravel()
        if vec.size != n_features:
            raise ValueError(f"row len {vec.size} != n_features {n_features}")
        features[count] = vec
        key = x[1]
        if key not in ip_intern:
            ip_intern[key] = next_id
            next_id += 1
        ip_ids[count] = ip_intern[key]
        count += 1
        if count % 50_000 == 0:
            peak_rss = max(peak_rss, proc.memory_info().rss)
            print(f"[load]   {count:,} packets …")
        if count >= cap:
            break

    peak_rss = max(peak_rss, proc.memory_info().rss)
    features = features[:count]
    ip_ids   = ip_ids[:count]
    fe_parse = np.asarray(fe_timings['parse'][:count], dtype=np.float64)      # ms
    fe_ai    = np.asarray(fe_timings['afterimage'][:count], dtype=np.float64)  # ms
    print(f"[load] loaded {count:,} packets  |  unique node IDs = {next_id:,}  "
          f"|  load-phase peak RSS = {peak_rss/1e6:.1f} MB")
    return features, ip_ids, n_features, fe_parse, fe_ai, peak_rss


# ── Percentile helper (microseconds) ───────────────────────────────────────────
def _cpu_pct(ct0, ct1, wall_s: float) -> float:
    """Process CPU utilisation (%) over the interval, from cpu_times deltas.
    Avoids psutil.cpu_percent's cpu_count dependency (blocked in some sandboxes).
    Single-threaded work should read ~100%; multi-thread can exceed 100%."""
    if wall_s <= 0:
        return float('nan')
    busy = (ct1.user - ct0.user) + (ct1.system - ct0.system)
    return 100.0 * busy / wall_s


def _stats_us(lat_ms: np.ndarray) -> Dict[str, float]:
    us = lat_ms * 1000.0
    return {
        "mean_us":   float(np.mean(us)),
        "median_us": float(np.median(us)),
        "p95_us":    float(np.percentile(us, 95)),
        "p99_us":    float(np.percentile(us, 99)),
    }


def main():
    ap = argparse.ArgumentParser(description="Offline-replay latency: Tenko vs Kitsune")
    ap.add_argument("--tsv",       default=DEFAULT_TSV)
    ap.add_argument("--fm-grace",  type=int, default=5000)
    ap.add_argument("--ad-grace",  type=int, default=50000)
    ap.add_argument("--calib-end", type=int, default=100000,
                    help="packets [train_end, calib_end) warm up the tolerance layer")
    ap.add_argument("--warmup",    type=int, default=5000,
                    help="untimed warmup packets before the timed window")
    ap.add_argument("--measure",   type=int, default=100000,
                    help="timed measurement packets (fixed count)")
    ap.add_argument("--x3-window",   type=int, default=DEFAULT_X3_WINDOW)
    ap.add_argument("--x3-segments", type=int, default=DEFAULT_X3_SEGMENTS)
    ap.add_argument("--out", default="results/latency/latency_throughput.csv")
    args = ap.parse_args()

    train_end   = args.fm_grace + args.ad_grace
    calib_end   = args.calib_end
    warmup_n    = args.warmup
    measure_n   = args.measure
    measure_start = calib_end + warmup_n
    measure_end   = measure_start + measure_n
    max_load      = measure_end

    print("=" * 74)
    print("  OFFLINE-REPLAY LATENCY / THROUGHPUT — Tenko vs Kitsune")
    print(f"  seed={RANDOM_SEED}  threads=1(pinned)")
    print(f"  KitNET train pkts     : [0, {train_end:,})")
    print(f"  tolerance calib pkts  : [{train_end:,}, {calib_end:,})")
    print(f"  warmup (untimed) pkts : [{calib_end:,}, {measure_start:,})")
    print(f"  TIMED measure pkts    : [{measure_start:,}, {measure_end:,})  (N={measure_n:,})")
    print("=" * 74)

    features, ip_ids, n_features, fe_parse_ms, fe_ai_ms, load_peak_rss = load_features(
        args.tsv, max_load)

    if len(features) < measure_end:
        raise SystemExit(
            f"[fatal] loaded {len(features):,} packets < required {measure_end:,}. "
            f"Lower --measure/--warmup/--calib-end or use a longer stream.")

    proc = psutil.Process(os.getpid())

    # ── Train KitNET once (shared by both systems) ─────────────────────────────
    print(f"\n[train] KitNET on packets [0, {train_end:,}) …")
    kitnet = KitNET(n=n_features, max_autoencoder_size=10,
                    FM_grace_period=args.fm_grace, AD_grace_period=args.ad_grace,
                    learning_rate=0.1, hidden_ratio=0.75)
    for i in range(train_end):
        kitnet.train(features[i])
    rss_after_train = proc.memory_info().rss
    print(f"[train] done. RSS = {rss_after_train/1e6:.1f} MB")

    # ── Calibrate Tenko tolerance layer on [train_end, calib_end) ──────────────
    print(f"[calib] node-scoring + centroids on [{train_end:,}, {calib_end:,}) …")
    node_score = nodeScore(MEMORY_SIZE, mode='offline', thread_safe=False)
    per_ip_recs: Dict[int, _CentroidRecognizer] = {}
    single_rec  = _CentroidRecognizer(args.x3_window, args.x3_segments, 1.1)
    for i in range(train_end, calib_end):
        ip = int(ip_ids[i])
        rmse = float(np.clip(kitnet.execute(features[i]), 0.0, 1.0))
        node_score.update(ip, i, rmse)
        try:
            score = node_score.scores[ip].get_score()
        except KeyError:
            score = rmse
        if ip not in per_ip_recs:
            per_ip_recs[ip] = _CentroidRecognizer(args.x3_window, args.x3_segments, 1.1)
        per_ip_recs[ip].update(score)
        per_ip_recs[ip].learn_current()
        single_rec.update(score)
        single_rec.learn_current()

    valid_cents, valid_tols = [], []
    for pr in per_ip_recs.values():
        pr.finalize_training()
        if pr.centroid is not None and pr.tol is not None:
            valid_cents.append(pr.centroid)
            valid_tols.append(pr.tol)
    global_centroid = np.mean(np.stack(valid_cents, axis=0), axis=0) if valid_cents else None
    global_tol      = float(np.mean(valid_tols)) if valid_tols else None
    single_rec.finalize_training()
    print(f"[calib] centroids ready (per-IP={len(per_ip_recs):,}, "
          f"global_tol={global_tol})")

    # ═══════════════════════════════════════════════════════════════════════════
    # SYSTEM A — Kitsune X1 only (kitnet.execute)
    # KitNET.execute is pure inference (frozen weights) → deterministic & repeatable.
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[measure] System A: Kitsune X1 (autoencoder only) …")
    for i in range(calib_end, measure_start):        # untimed warmup
        kitnet.execute(features[i])

    kit_lat = np.empty(measure_n, dtype=np.float64)  # ms
    kit_peak_rss = proc.memory_info().rss
    _ct0 = proc.cpu_times()                           # CPU% via cpu_times (no cpu_count dep)
    t_wall0 = time.perf_counter()
    for idx in range(measure_n):
        i = measure_start + idx
        t0 = time.perf_counter()
        kitnet.execute(features[i])
        t1 = time.perf_counter()
        kit_lat[idx] = (t1 - t0) * 1000.0
        if (idx & 0x3FFF) == 0:
            kit_peak_rss = max(kit_peak_rss, proc.memory_info().rss)
    kit_wall = time.perf_counter() - t_wall0
    kit_cpu = _cpu_pct(_ct0, proc.cpu_times(), kit_wall)
    kit_peak_rss = max(kit_peak_rss, proc.memory_info().rss)
    kit_pps = measure_n / kit_wall

    # ═══════════════════════════════════════════════════════════════════════════
    # SYSTEM B — Full Tenko (X1 + node scoring + tolerance)
    # Fresh tolerance-layer STATE is required; but the centroids were calibrated
    # above. Re-seed continuity state by warming through [calib_end, measure_start).
    # ═══════════════════════════════════════════════════════════════════════════
    print("[measure] System B: Full Tenko (X1 + node-scoring + tolerance) …")

    def tenko_step(i: int):
        ip = int(ip_ids[i])
        rmse = float(np.clip(kitnet.execute(features[i]), 0.0, 1.0))
        node_score.update(ip, i, rmse)
        try:
            score = node_score.scores[ip].get_score()
        except KeyError:
            score = rmse
        if ip not in per_ip_recs:
            per_ip_recs[ip] = _CentroidRecognizer(args.x3_window, args.x3_segments, 1.1)
            if global_centroid is not None:
                per_ip_recs[ip].centroid = global_centroid
                per_ip_recs[ip].tol      = global_tol
        pr = per_ip_recs[ip]
        pr.update(score)
        flag_global = (not pr.is_known()) if global_centroid is not None else False
        single_rec.update(score)
        flag_single = (not single_rec.is_known())
        combined = W_GLOBAL * flag_global + W_SINGLE * flag_single
        return 1 if combined >= ENSEMBLE_THRESHOLD else 0

    for i in range(calib_end, measure_start):        # untimed warmup (continues state)
        tenko_step(i)

    ten_lat = np.empty(measure_n, dtype=np.float64)  # ms
    ten_peak_rss = proc.memory_info().rss
    _ct0 = proc.cpu_times()
    t_wall0 = time.perf_counter()
    for idx in range(measure_n):
        i = measure_start + idx
        t0 = time.perf_counter()
        tenko_step(i)
        t1 = time.perf_counter()
        ten_lat[idx] = (t1 - t0) * 1000.0
        if (idx & 0x3FFF) == 0:
            ten_peak_rss = max(ten_peak_rss, proc.memory_info().rss)
    ten_wall = time.perf_counter() - t_wall0
    ten_cpu = _cpu_pct(_ct0, proc.cpu_times(), ten_wall)
    ten_peak_rss = max(ten_peak_rss, proc.memory_info().rss)
    ten_pps = measure_n / ten_wall

    # ── Feature-extraction latency over the measurement window (already captured)─
    fe_win = (fe_parse_ms[measure_start:measure_end]
              + fe_ai_ms[measure_start:measure_end])     # ms per packet
    fe_stats = _stats_us(fe_win)
    fe_mean_ms = float(np.mean(fe_win))
    fe_pps = 1000.0 / fe_mean_ms if fe_mean_ms > 0 else float('nan')

    # ── Full-stack (FE + Tenko) per-packet estimate ────────────────────────────
    # FE and model are sequential in deployment; per-packet sum is an honest
    # offline estimate of combined cost (labelled ESTIMATE in the .md).
    full_win = fe_win + ten_lat
    full_stats = _stats_us(full_win)
    full_mean_ms = float(np.mean(full_win))
    full_pps = 1000.0 / full_mean_ms if full_mean_ms > 0 else float('nan')

    # ── Assemble rows ──────────────────────────────────────────────────────────
    kit_stats = _stats_us(kit_lat)
    ten_stats = _stats_us(ten_lat)

    rows = [
        {"system": "Kitsune_X1", "n_packets": measure_n, **kit_stats,
         "throughput_pps": kit_pps, "peak_rss_mb": kit_peak_rss / 1e6, "cpu_pct": kit_cpu},
        {"system": "Tenko_full", "n_packets": measure_n, **ten_stats,
         "throughput_pps": ten_pps, "peak_rss_mb": ten_peak_rss / 1e6, "cpu_pct": ten_cpu},
        # Extra honesty rows (not one of the two required systems):
        {"system": "FeatureExtraction_only", "n_packets": measure_n, **fe_stats,
         "throughput_pps": fe_pps, "peak_rss_mb": load_peak_rss / 1e6, "cpu_pct": float('nan')},
        {"system": "FullStack_FE+Tenko_est", "n_packets": measure_n, **full_stats,
         "throughput_pps": full_pps, "peak_rss_mb": ten_peak_rss / 1e6, "cpu_pct": ten_cpu},
    ]

    cols = ["system", "n_packets", "mean_us", "median_us", "p95_us", "p99_us",
            "throughput_pps", "peak_rss_mb", "cpu_pct"]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{r[k]:.4f}" if isinstance(r[k], float) else r[k]) for k in cols})

    # ── Console summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 74)
    print(f"  RESULTS (measured over N={measure_n:,} packets, single core)")
    print("=" * 74)
    hdr = f"  {'system':<24}{'mean_us':>9}{'med_us':>9}{'p95_us':>9}{'p99_us':>9}{'pps':>12}{'RSS_MB':>9}{'CPU%':>7}"
    print(hdr)
    for r in rows:
        print(f"  {r['system']:<24}{r['mean_us']:>9.2f}{r['median_us']:>9.2f}"
              f"{r['p95_us']:>9.2f}{r['p99_us']:>9.2f}{r['throughput_pps']:>12.0f}"
              f"{r['peak_rss_mb']:>9.1f}{r['cpu_pct']:>7.1f}")
    ovh = ten_stats['mean_us'] - kit_stats['mean_us']
    print("-" * 74)
    print(f"  Tenko per-packet overhead vs Kitsune (mean): +{ovh:.2f} us "
          f"({100.0*ovh/kit_stats['mean_us']:.1f}% over X1)")
    print(f"  Kitsune sustained: {kit_pps:,.0f} pps  |  Tenko sustained: {ten_pps:,.0f} pps")
    print(f"  CSV → {out_path}")
    print("=" * 74)


if __name__ == "__main__":
    main()
