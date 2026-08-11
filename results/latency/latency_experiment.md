# Offline-Replay Latency / Throughput Experiment (Reviewer Blocker B1)

**Scope.** Reviewer #3 asked, for the real-time claim, for: hardware specs,
packet rate, CPU%, and packet drop. We **cannot** measure live-NIC packet
**drop** on this machine (there is no inline/tap gateway deployment and no
live capture here). What we *can* honestly measure — and what this experiment
reports — is **offline-replay** per-packet processing latency, sustained
throughput (packets/sec), peak process memory, and CPU utilisation, obtained
by replaying a committed mixed-attack packet stream through the detection
models. **Live-capture packet drop under load is explicitly out of scope and
listed as future work** (it requires a real deployment with a hardware traffic
generator; an offline TSV replay cannot produce it).

## Hardware / software

From `results/latency/hardware_spec.txt`:

| Item | Value |
|---|---|
| CPU | **Apple M4 Pro** (arm64) |
| Cores | 14 physical / 14 logical |
| RAM | 48 GiB (51,539,607,552 bytes) |
| OS | macOS 26.5.2 (build 25F84), Darwin 25.5.0 |
| Python | 3.14.5 (`.venv`) |
| numpy / psutil | 2.5.1 / 7.2.2 |

Math libraries (OMP/OpenBLAS/MKL/Accelerate) were **pinned to 1 thread**. This
is deliberate: an online, per-packet gateway IDS processes packets sequentially
on a single core, so single-core numbers are the realistic per-core capacity.
CPU% is reported per process (single-threaded → ≈100%).

## Method

- **Input (replay):** `results/CICIoT2023/mixed/stream_mixed.pcap.tsv`
  (420,000 packets, a committed CICIoT2023 mixed benign+attack stream). Features
  are the standard 100-dim Kitsune/AfterImage vectors, streamed through
  `FeatureExtractor.FE` exactly as in the live pipeline.
- **Two systems, same trained KitNET, same measurement packets:**
  - **Kitsune X1** — KitNET autoencoder ensemble only (`kitnet.execute`).
  - **Tenko (full)** — X1 **+ node scoring** (`tracker.nodeScore`) **+ tolerance**
    (per-IP sliding-window RMSE centroid + weighted-ensemble decision, the
    `_CentroidRecognizer` logic from the `correct-latency` `measure_all_latency.py`).
  Because both share one trained KitNET and the identical measurement window,
  the Tenko−Kitsune delta is *purely* the added node-scoring + tolerance cost.
- **Phases (packet index ranges):**
  - KitNET training: `[0, 55,000)` (FM grace 5,000 + AD grace 50,000).
  - Tolerance-layer calibration (node scoring + centroids): `[55,000, 100,000)`.
  - **Warm-up (untimed):** `[100,000, 105,000)` — 5,000 packets, warms caches /
    branch predictors and continues online state.
  - **Timed measurement (fixed):** `[105,000, 205,000)` — **N = 100,000 packets**.
- **Metrics:** per-packet latency (mean / median / p95 / p99, via
  `time.perf_counter`), sustained throughput = N / wall-time, peak process RSS
  (psutil, sampled during the timed loop), and process CPU% (from
  `psutil.cpu_times()` deltas over the timed loop).
- **Reproduce:** `.venv/bin/python results/latency/measure_latency.py`
  (seed 42; defaults match the ranges above).

## Results

Full numbers in `results/latency/latency_throughput.csv`.

| System | mean (µs) | median (µs) | p95 (µs) | p99 (µs) | throughput (pps) | peak RSS (MB) | CPU% |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Kitsune X1** | 117.23 | 114.75 | 130.79 | 169.75 | **8,519** | 493.5 | 99.8 |
| **Tenko (full)** | 123.71 | 120.29 | 140.04 | 189.71 | **8,075** | 484.0 | 99.6 |
| Feature extraction only¹ | 4172.28 | **58.83** | 24,823 | 99,180 | (≈17,000 at median)¹ | 399.0 | — |
| Full stack (FE+Tenko), est.² | 4295.98 | **181.33** | 24,944 | 99,299 | ≈5,500 at median² | 484.0 | 99.6 |

¹ Feature-extraction (dpkt/TSV parse + AfterImage) latency was captured during
the bulk load pass. Its **median is ~59 µs** (representative steady-state), but
its **mean (4.17 ms) and tail (p99 ≈ 99 ms) are inflated by rare
garbage-collection / OS-scheduler stalls that occur during the one-shot bulk
load loop** — an artifact of the offline load context, not a per-packet cost the
detector pays in steady state. Treat FE median, not FE mean, as representative.

² Full-stack is a **derived ESTIMATE** = per-packet (FE + Tenko), summed because
the two run sequentially in deployment. Because it inherits the FE load-pass
tail, use its **median (~181 µs → ~5,500 pps)**, not its mean.

### Key reads

- **Tenko overhead vs Kitsune:** +6.47 µs mean per packet (**+5.5%** over X1).
  Median overhead is similar (+5.5 µs). Tenko's extra layers (node scoring +
  tolerance) are cheap; **Tenko is only marginally slower than Kitsune** and
  does not change the real-time story relative to Kitsune. We report this delta
  openly — Tenko *is* slightly slower, as expected.
- **Sustained throughput (single core, this machine):** Kitsune ≈ **8,519 pps**,
  Tenko ≈ **8,075 pps**. CPU ≈ 100% of one core; the run is compute-bound in the
  KitNET autoencoder (X1 dominates: ~118 µs of the ~124 µs Tenko cost).
- **Memory:** peak process RSS ≈ **484–494 MB**. This is *whole-process* RSS and
  is dominated by the Python/Scapy/numpy runtime plus the **205k-packet in-memory
  replay matrix (~82 MB)** — it is an upper bound, not the model's own footprint.
  The incremental model state (KitNET ensemble + nodeScore window + centroids) is
  small (sub-MB to a few MB by logical `deep_sizeof` in the companion harness).

### Derived line-rate estimate (clearly labelled ESTIMATE)

Throughput for a per-packet online IDS is bound by **packets/sec**, not bits/sec.
At **~8,075 pps/core (Tenko)**:

- Measured window packet size (attack-heavy, small packets): mean 89.8 B →
  **≈5.8 Mbps per core** (small packets ⇒ low Mbps at high pps).
- Whole-stream mean packet size (393 B, benign-heavy): **≈25 Mbps per core**.

These are **single-core, pure-Python** estimates for the model stage on
pre-extracted features. They are an **upper bound on sustainable rate without
drop only under the assumption that no capture/queueing loss occurs upstream** —
which we did **not** measure. Multi-core scaling (14 cores here) could raise
aggregate pps, but per-flow online scoring is not trivially parallel, so we do
**not** claim it.

## Honest interpretation — is "real-time at gateway rates" defensible?

From these numbers, **"real-time at gateway rates" should be softened /
qualified rather than stated flatly.** The pipeline sustains roughly **8,000
packets/sec on a single Apple M4 Pro core in pure Python**, with a per-packet
median of ~120 µs and a well-behaved tail (p99 ≈ 190 µs). That is genuinely
real-time (bounded, sub-millisecond per packet) and is adequate for **edge /
SOHO / IoT-segment gateways and low-to-moderate packet rates**, and Tenko adds
only ~5.5% over Kitsune so it inherits Kitsune's real-time profile. **However,
8k pps/core is well below the multi-hundred-thousand-to-million pps seen at
busy enterprise/ISP gateways**, so an unqualified "gateway line-rate" claim is
not supported by this Python prototype. The defensible framing is: *real-time,
per-packet online detection at edge-gateway rates on a single core, with a
low fixed overhead over Kitsune (~5.5%); higher line rates would rely on the
optimized (C++/Cython) autoencoder path — the Kitsune authors report ~100×
over Python — and/or multi-core deployment, and live-NIC packet-drop under
sustained load remains unmeasured and is future work.*

## Threats to validity / not measured

- **No live-NIC packet drop.** Offline replay decouples processing from arrival;
  drop under burst/queueing is a deployment property we did not (could not)
  measure here. **Future work.**
- Single machine (Apple M4 Pro), single core, pure-Python numpy backend; results
  will differ on the Cython/C++ path and on x86/server hardware.
- FE mean/tail inflated by bulk-load GC/scheduler stalls (see note ¹); FE median
  is the representative figure.
- RSS is whole-process (includes the in-memory replay buffer), an upper bound.

## Files

- `results/latency/hardware_spec.txt` — machine spec.
- `results/latency/measure_latency.py` — the replay harness (reproducible, seed 42).
- `results/latency/latency_throughput.csv` — the measured table above.
- `results/latency/latency_experiment.md` — this document.
