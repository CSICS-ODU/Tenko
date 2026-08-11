# Tenko

Tenko is a streaming network intrusion detection system that builds on the Kitsune / KitNET per-packet autoencoder backbone and adds **per-source node scoring**, a **benign-calibrated tolerance layer**, and **weighted decision fusion**. The result is a stateful, device-aware anomaly detector that operates on packet streams without attack labels at train time.

This `public-release` branch packages the runnable code, committed score arrays, metric CSVs, and figure-data CSVs needed to regenerate the paper’s headline tables and figures.

---

## Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

- Tested with **Python 3.14** and the pins in `requirements.txt` (numpy 2.x, scikit-learn, scipy, pandas, matplotlib, scapy, …).
- Full transitive freeze: `requirements.lock.txt`.
- Optional Cython fast path for AfterImage / KitNET kernels: see `setup_cython.py` / `fastpath/`.

All commands below assume the repo root and:

```bash
PY=.venv/bin/python
```

---

## Repository layout

| Path | Role |
|---|---|
| `example.py`, `results.py`, `tracker.py`, `workflow.py` | Core Tenko pipeline (KitNET → node scores → pattern recognizers → decisions) |
| `KitNET/`, `AfterImage.py`, `FeatureExtractor.py`, `netStat.py` | Kitsune / KitNET feature extraction and autoencoder ensemble |
| `run_ciciot2023.py`, `recalibrate_ciciot2023.py` | CICIoT2023 drivers and recalibration |
| `scripts/` | Stream-building helpers (PCAP → TSV / labeled streams) |
| `results/CICIoT2023/` | Mixed-stream comparison, baselines, figures, seed study |
| `results/nbaiot/` | N-BaIoT Table V rebuild |
| `results/main9attack/` | Nine-attack Kitsune main-table rebuild |
| `results/latency/` | Latency / throughput measurements |
| `requirements.txt` | Curated runtime dependencies |

Large raw captures (`*.pcap` / `*.tsv`), vendored upstream trees under `external/`, and regenerable feature matrices are gitignored. Headline metrics regenerate from committed `.npy` / `.npz` / CSV artifacts without re-downloading PCAPs.

---

## Datasets and environment variables

| Dataset | Typical use | How to point the code |
|---|---|---|
| **CICIoT2023** | Mixed-stream binary comparison, per-class AUC/EER, baselines, t-SNE, seed study | Set `CIC_DATA_ROOT` (default `./data/ciciot2023/pilot`) and optionally `CIC_RESULTS_ROOT` (default `./results/CICIoT2023`). Obtain the dataset from the Canadian Institute for Cybersecurity (registration required). |
| **N-BaIoT** | Per-device / per-attack Table V | Pass `--dataset` to `results/nbaiot/run_nbaiot_tableV.py` (e.g. `~/dataset/N-BaIoT`). |
| **Kitsune (UCI)** | Nine-attack main table | Public UCI archive (id=516). Rebuild script downloads/uses data under `results/main9attack/data/` (gitignored). |

Feature / runtime flags used by the pipeline include `KITNET_USE_TORCH`, `KITNET_DISABLE_CYTHON_AI`, `FE_FORCE_SCAPY`, and `MPLBACKEND` (plotting).

---

## Method summary (unified pseudocode)

Derived from `results.py` (`get_adversarial_IPs_weighted_pattern`), `tracker.py`, and `example.py`. Defaults: η_global = 50, η_node = 20, `FMgrace=5000`, `ADgrace=50000`, fusion weights 0.5/0.5, decision threshold τ = 0.5.

```
Input : packet stream P = p_1..p_T with source IPs; benign lead length L
Params: FMgrace, ADgrace; η_global, η_node; weights w_g, w_s; threshold τ
Output: per-packet decisions and continuous scores (nd_g, nd_s, cont)

# X1 — KitNET per-packet anomaly score (Kitsune core)
for each packet p_i:
    f_i    = AfterImage.update_get_stats(p_i)
    rmse_i = KitNET.process(f_i)                 # train until FMgrace+ADgrace, else execute
    s_i    = tanh(rmse_i)

# X2 — per-source (node) aggregation
for each packet p_i with source IP n:
    nodeScore[n].update(s_i)
    S_i = nodeScore[n].get_score()

# X3 — benign-only pattern recognizers (global + single-aggregate)
# train on segment vectors of S for i in [FMgrace+ADgrace+1 .. L]
for each recognizer r:
    c_r   = mean(training segment vectors)
    tol_r = max_i ‖v_i − c_r‖ × η
benign_spread = tol / η

# X4 — test-time fusion
for each test packet p_i:
    nd_g = ‖v_g − c_global‖ / benign_spread_g
    nd_s = ‖v_s − c_single‖ / benign_spread_s
    flag_g = 1 if nd_g > η_global else 0
    flag_s = 1 if nd_s > η_node   else 0
    score_i    = w_g·flag_g + w_s·flag_s
    decision_i = 1 if score_i ≥ τ else 0
    cont_i     = w_g·nd_g + w_s·nd_s             # AUC / EER score
```

On CICIoT2023, the headline operating point uses **benign-calibrated** thresholds (η_g, η_s) chosen so the benign OR-flag rate matches a target FPR (orrule@2%: η_g=30.14, η_s=3.14), instead of the fixed 50/20 defaults.

**What Tenko adds beyond Kitsune.** Kitsune/KitNET supplies the per-packet RMSE backbone (X1). Tenko adds (X2) decaying per-source-IP state, (X3) benign-centroid tolerance envelopes on segmented pattern vectors, and (X4) global/node weighted fusion with a continuous η-normalized score for ROC analysis.

---

## Reproducibility manifest

Run from the repo root. Analytical scripts recompute metrics from committed score arrays and do not require raw PCAPs.

### Headline mixed-stream table (CICIoT2023)

| Item | Path |
|---|---|
| Script | `results/CICIoT2023/build_table_ix_mixed.py` |
| Inputs | `results/CICIoT2023/mixed/arr_{gold,ndg,nds,cont}_mixed.npy`, `mixed/kitsune_testscores_mixed.npy`, `baselines/{mateen,vaeesdd,iforest}/*_mixed.npz` |
| Output | `results/CICIoT2023/baselines/table_ix_mixed_with_iforest.csv` |

```bash
$PY results/CICIoT2023/build_table_ix_mixed.py --check   # verify == committed
$PY results/CICIoT2023/build_table_ix_mixed.py           # rewrite CSV
```

**Committed numbers (orrule@2% / shared labels):**

| Method | TPR | FPR | AUC |
|---|---:|---:|---:|
| **Tenko (orrule@2%)** | **0.9801** | **0.0200** | **0.9897** |
| Kitsune (med+MAD) | 0.9637 | 0.1971 | 0.9733 |
| Mateen | 0.9048 | 0.0488 | 0.9665 |
| VAE-ESDD (frozen) | 0.8251 | 0.0141 | 0.9540 |
| Isolation Forest (z-score) | 0.6115 | 0.0514 | 0.9347 |

### Other CICIoT2023 tables and figures

| Artifact | Script | Output |
|---|---|---|
| Per-class AUC/EER + η recalibration | `recalibrate_ciciot2023.py` | `results/CICIoT2023/ciciot2023_metrics_recalibrated.csv`, `ciciot2023_per_class_metrics.csv` |
| Out-of-sample η | `recalibrate_ciciot2023_oos.py` | `ciciot2023_metrics_recalibrated_oos.csv` |
| Baseline comparison @1% FPR | `results/CICIoT2023/baselines/build_comparison_table.py` | `baselines/comparison_metrics.csv` |
| Operating-point sweep | (committed CSV) | `mixed/ciciot2023_calibrated_operating_point_metrics.csv` |
| Figure data export | `results/CICIoT2023/export_figure_data.py` | `figs/data/*.csv` |
| RMSE timelines | `results/CICIoT2023/plot_cic_rmse.py` | `figs/` |
| ROC curves | `results/CICIoT2023/plot_cic_roc.py` | `figs/` |
| t-SNE (Fig-6) | `results/CICIoT2023/figs/plot_tsne.py` | `figs/tsne_mixed.{png,pdf}`, `figs/data/tsne_*.csv` |
| Seed robustness (6 seeds) | committed metrics | `seed_robustness/seed_robustness_metrics.csv` |

```bash
$PY recalibrate_ciciot2023.py
$PY results/CICIoT2023/export_figure_data.py
$PY results/CICIoT2023/figs/plot_tsne.py
```

**From-scratch CICIoT2023 rebuild** (needs external PCAP + `tshark`):

```bash
bash scripts/build_streams_ciciot2023.sh
$PY run_ciciot2023.py --attacks all
bash results/CICIoT2023/mixed/build_mixed_stream.sh
$PY results/CICIoT2023/mixed/run_mixed.py
```

Baseline runners (Mateen / VAE-ESDD / iForest) live under `results/CICIoT2023/baselines/`. Upstream source for Mateen/VAE-ESDD is expected under `external/` when re-running those baselines.

### N-BaIoT (Table V)

| Item | Path |
|---|---|
| Script | `results/nbaiot/run_nbaiot_tableV.py` |
| Output | `results/nbaiot/nbaiot_tableV_metrics.csv` (80 rows) |

```bash
$PY results/nbaiot/run_nbaiot_tableV.py --dataset ~/dataset/N-BaIoT \
    --output results/nbaiot/nbaiot_tableV_metrics.csv
```

### Nine-attack Kitsune table

| Item | Path |
|---|---|
| Script | `results/main9attack/run_kitsune_9attack.py` / `rebuild_8attacks.sh` |
| Output | `results/main9attack/kitsune_9attack_metrics.csv` |

Attacks: Mirai, OS Scan, SSL Renegotiation, Fuzzing, Active Wiretap, SYN DoS, Video Injection, ARP MitM, SSDP Flood.

```bash
bash results/main9attack/rebuild_8attacks.sh
$PY results/main9attack/verify_vs_paper.py
```

### Latency and throughput

| Item | Path |
|---|---|
| Script | `results/latency/measure_latency.py` |
| Hardware note | `results/latency/hardware_spec.txt` |
| Output | `results/latency/latency_throughput.csv` |

```bash
$PY results/latency/measure_latency.py --output results/latency/latency_throughput.csv
```

Committed snapshot (100k packets): Kitsune_X1 ≈ 117 µs mean / ~8.5k pps; Tenko_full ≈ 124 µs mean / ~8.1k pps.

### Quick verification

```bash
$PY results/CICIoT2023/build_table_ix_mixed.py --check
$PY recalibrate_ciciot2023.py | tail -2
$PY results/CICIoT2023/export_figure_data.py
```

---

## Related systems (context)

On the same CICIoT2023 mixed stream and gold labels, Tenko’s mixed-stream ROC-AUC (0.9897) sits above re-run baselines Kitsune (0.9733), Mateen (0.9665), VAE-ESDD (0.9540), and Isolation Forest (0.9347). Broader literature context includes recent unsupervised / streaming IDS work on CICIoT2023 and related IoT corpora (e.g. Adaptive NAD, AdaptiveAE-IDS, IMME, PGTAD, Mateen, VAE-ESDD). Tenko’s distinguishing design choice is **packet-level, per-source-IP state** with benign-only geometric calibration, rather than flow-batch or supervised multi-class training.

---

## License / citation

If you use this code or the committed result artifacts, please cite the Tenko paper and the upstream Kitsune / KitNET work as appropriate. Dataset providers (CICIoT2023, N-BaIoT, Kitsune UCI) require compliance with their own terms of use.
