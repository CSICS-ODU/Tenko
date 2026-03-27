# Upstream Kitsune-py — Mirai latency (paper-style config)

## Repository

- **Clone:** [ymirsky/Kitsune-py](https://github.com/ymirsky/Kitsune-py) at `external/Kitsune-upstream/`
- **Measured commit (HEAD):** `7c8ea51e89268d9a20399dca4bf32d663e638eb4` (see JSON reports)

## Paper-style hyperparameters (upstream `example.py` / README)

| Parameter   | Value |
|------------|-------|
| `maxAE`    | 10    |
| `FMgrace`  | 5000  |
| `ADgrace`  | 50000 |

## Input data

- **File:** `dataset/Mirai/Mirai_pcap.pcap.tsv` (repo root, pre-parsed TSV)
- **Packets in file:** 764,137 data rows (+ header)

## What was timed

- **KitNET (`AnomDetector.process`)** — time inside `KitNET` only (same scope as instrumented `Kitsune.py` in this project).
- **Feature extraction (`get_next_vector`)** — reported separately; **mean** can be skewed by long tails; **median** is often more representative for FE.

## Measured run (representative)

**Host:** macOS, arm64 (Apple Silicon), Python 3.13.3  
**Execution-phase samples:** 50,000 (packets with index `i > 55000` in 1-based loop)

**KitNET — execution phase (50k samples)**

| Metric | Value |
|--------|--------|
| Mean | **~0.132 ms** |
| Median | **~0.129 ms** |
| Std | **~0.009 ms** |
| p99 | **~0.173 ms** |
| Implied single-thread pps (1/mean) | **~7,600 pps** |

Full JSON: [`mirai_latency_report_50k_exec.json`](mirai_latency_report_50k_exec.json)

**FE — execution phase (same 50k samples)**  
Median **~0.091 ms**; mean **~0.72 ms** (heavy-tailed — occasional slow reads/parsing).

## Caveats

1. **Paper vs Python:** The NDSS paper’s throughput figures are largely from **C++**; the upstream README states Python is **not** speed-optimal.
2. **Feature count:** This run reported **100 features → 16 autoencoders** after feature mapping. Your forked repo may show **115** dimensions depending on `FeatureExtractor` / dataset; compare mappings if you need bit-for-bit parity with internal experiments.
3. **Full-trace run:** To time **all** execution-phase packets (~709k after grace), run:

```bash
cd external/Kitsune-upstream
python3 run_mirai_latency.py --mirai-tsv ../../dataset/Mirai/Mirai_pcap.pcap.tsv
```

(no `--target-exec-samples`; may take on the order of **tens of minutes** for the full TSV)

## Scripts

- [`run_mirai_latency.py`](run_mirai_latency.py) — CLI for Mirai path, `--max-packets`, `--target-exec-samples`, JSON output.
- [`Kitsune.py`](Kitsune.py) — patched to set `_last_kitnet_time_s` and `_last_fe_time_s` each packet.
