# Tenko — Reproducibility Manifest

**Branch:** `public-release` (base: `correct-latency`).
**Purpose:** map every figure/table in the manuscript to the *script → input data → output CSV* that regenerates it, with exact commands, so a suspicious reviewer can reproduce the numbers from committed code + data.

> **Scope note.** This branch consolidates the **CICIoT2023 revision** (the new, headline recent-dataset work: mixed-stream binary comparison, per-class AUC/EER, baselines, operating-point and out-of-sample analyses, and the RMSE/ROC figures) **plus** the revision artifacts that answer the reviewer blockers: the **t-SNE separation figure** (§4), a measured **latency/throughput** table (§9), a **seed-robustness** study (§10), the **N-BaIoT Table V** rebuild (§11), and the **9-attack Kitsune** table (Mirai verified end-to-end; the other 8 attacks need public captures the maintainer must supply — §11). Data provenance and what still needs external data are documented in `results/DATA_LOCATION_REPORT.md`.

---

## 1. Environment

Two Python environments exist in the tree; the one that reproduces every number below is the repo `.venv`:

| | Interpreter | Key packages |
|---|---|---|
| **Actual working env** (`.venv/`) | Python **3.14.5** | numpy 2.5.1, scikit-learn 1.9.0, scipy 1.18.0, pandas 3.0.5, matplotlib 3.11.1 |
| `requirements.txt` (stale pins) | (pins Py3.9-era) | numpy 1.26.4, scikit-learn 1.6.1, torch <2.6 |

- The CICIoT2023 **analytical** scripts (metrics recomputed from cached `.npy`/`.npz`) only use core numpy / scikit-learn and reproduce identically under the `.venv`.
- Exact frozen versions of the working env: `results/CICIoT2023/environment_lock.txt`.
- `requirements.txt` is now the **curated top-level** dependency list for the `.venv` above (numpy 2.x / Python 3.14); `requirements.lock.txt` is the full transitive `pip freeze`. `requirements.public.txt` is the same curated list kept as a named copy.

All commands below assume you run from the repo root and use:

```bash
PY=.venv/bin/python
```

---

## 2. What is committed vs. excluded

**Committed (behind every CICIoT2023 number):**
- All analysis/driver/plotting **scripts** (`.py`, `.sh`).
- All **metric CSVs** and the figure-data CSVs (`results/CICIoT2023/**/*.csv`, `figs/data/*.csv`).
- Per-packet **score arrays** `arr_*.npy` (Tenko `nd_g`, `nd_s`, fused `cont`, node `S(n)`, Kitsune `tanh(RMSE)`, gold labels) and `rmse_raw_*.npy`.
- Baseline **score archives** `baselines/{mateen,vaeesdd,iforest}/*_mixed.npz` and per-attack `.npz`.
- Provenance/analysis **markdown** and JSON threshold dumps.

**Excluded via `.gitignore`** (large / raw / regenerable):
- Raw packet captures `*.pcap` / `*.pcapng` and their `*.pcap.tsv` conversions (multi-GB; derived from CICIoT2023, which requires registration).
- Per-packet feature matrices `baselines/features/X_*.npy` (~551 MB; regenerable from TSV via `extract_features.py`).
- The `mixed/rebal/` re-balance side-experiment bulk streams (not used by any headline table).
- Vendored upstream baseline source `external/` (see §6 for upstream URLs + attribution).
- Virtualenvs, `__pycache__`, `.DS_Store`, `*.pptx`.

**Consequence:** every CICIoT2023 **table and figure** below regenerates from committed `.npy`/`.npz` **without** the PCAP/TSV. Only a *from-scratch* rebuild (re-running KitNET/Tenko on packets) needs the excluded raw data + the external dataset.

---

## 3. CICIoT2023 tables — manifest

Run from repo root. "Verified" = re-run during this audit and matched the committed CSV / paper number.

| Table / metric | Script | Input data (committed) | Output CSV | Status |
|---|---|---|---|---|
| **Headline mixed-stream binary comparison** (Tenko/Kitsune/Mateen/VAEESDD/iForest; TPR/FPR/Precision/F1/MacroF1/Acc/AUC) | `results/CICIoT2023/build_table_ix_mixed.py` *(new)* | `mixed/arr_{gold,ndg,nds,cont}_mixed.npy`, `mixed/kitsune_testscores_mixed.npy`, `baselines/{mateen,vaeesdd,iforest}/*_mixed.npz` | `baselines/table_ix_mixed_with_iforest.csv` | **Verified** — `--check` PASS |
| Mixed operating-point sweep (committed η, cont@x%, **orrule@2%/5%**, Kitsune med+MAD/@x%) | *(internal calibration helper; not published)* | `mixed/arr_*_mixed.npy`, `mixed/kitsune_testscores_mixed.npy` | `mixed/ciciot2023_calibrated_operating_point_metrics.csv` *(committed)* | **Verified** — orrule@2% TPR 0.9801 / FPR 0.0200 / AUC 0.9897 |
| Per-class **AUC/EER + recalibrated η @1%/5%** (double-tanh) | `recalibrate_ciciot2023.py` | `arr_*_{double,single}.npy`, `ciciot2023_committedEta_double.csv`, `stream_counts.csv` | `ciciot2023_metrics_recalibrated.csv`, `ciciot2023_per_class_metrics.csv` | **Verified** — all F1 reconcile; matches roadmap |
| single-vs-double **tanh impact** | `recalibrate_ciciot2023.py` | `arr_*_{double,single}.npy` | `ciciot2023_tanh_impact.csv` | **Verified** |
| **Out-of-sample η** (held-out benign FPR non-transfer) | `recalibrate_ciciot2023_oos.py` | `arr_*_{double,single}.npy`, `stream_counts.csv` | `ciciot2023_metrics_recalibrated_oos.csv` | Regenerable |
| Baseline comparison @1% FPR + threshold-free | `results/CICIoT2023/baselines/build_comparison_table.py` | `mixed/arr_cont_mixed.npy`, `mixed/kitsune_testscores_mixed.npy`, `baselines/{mateen,vaeesdd,iforest}/*.npz` | `baselines/comparison_metrics.csv` | Regenerable |
| Individual-stream slices (contiguous/random benign) | *(internal helper; not published)* | `arr_*_<attack>_s60k.npy` | `ciciot2023_individual_streams_metrics.csv` *(committed)* | Committed CSV retained |
| Clean-split protocol | *(internal helper; not published)* | `arr_*_<attack>_s60k.npy` | `ciciot2023_cleansplit_metrics.csv` *(committed)* | Committed CSV retained |
| single-tanh η grid search (supervised upper-bound row) | *(internal helper; not published)* | `arr_*_<attack>_s60k.npy` | `ciciot2023_singletanh_gridsearch_metrics.csv` *(committed)* | Committed CSV retained |
| Per-source-device AUC/EER | `results/CICIoT2023/source_level_experiment.py` | `arr_kitsune_*`, `arr_cont_*_double.npy` **+ external pilot TSV** | `ciciot2023_source_level_metrics.csv` | Regenerable *(needs external TSV)* |
| Independent-stream robustness (distinct benign window per attack) | `results/CICIoT2023/indep/run_indep.py` | `indep/arr_*_indep.npy` (or rebuild from **raw PCAP**) | `indep/ciciot2023_independent_streams_metrics.csv` | Regenerable *(from cached arrays; from-scratch needs PCAP)* |

### Commands

```bash
PY=.venv/bin/python

# Headline mixed-stream table (Table IX/"X")
$PY results/CICIoT2023/build_table_ix_mixed.py --check      # verify == committed
$PY results/CICIoT2023/build_table_ix_mixed.py              # rewrite the CSV

# Per-class AUC/EER + recalibration + tanh impact
$PY recalibrate_ciciot2023.py
$PY recalibrate_ciciot2023_oos.py

# Baseline comparison
$PY results/CICIoT2023/baselines/build_comparison_table.py
```
(The mixed operating-point sweep CSV — `mixed/ciciot2023_calibrated_operating_point_metrics.csv` — is committed; the internal calibration helper that produced it is not part of the public branch.)

---

## 4. CICIoT2023 figures — manifest

Plotting scripts write PNG+PDF into `results/CICIoT2023/figs/`. The **underlying numbers** are exported to CSV by `export_figure_data.py` (new) into `results/CICIoT2023/figs/data/`.

| Figure | Plot script | Data CSV (new) | CSV producer | Status |
|---|---|---|---|---|
| RMSE timeline — Kitsune `tanh(RMSE)` (Fig-4 analogue) | `plot_cic_rmse.py` | `figs/data/rmse_timeline_<attack>.csv`, `figs/data/rmse_thresholds.csv` | `export_figure_data.py` | **Verified** |
| RMSE timeline — Tenko node score `S(n)` (Fig-5 analogue) | `plot_cic_rmse.py` | same | `export_figure_data.py` | **Verified** |
| Tenko-vs-Kitsune overlay / full-stream | `plot_cic_rmse.py --mode overlay|fullstream` | (timeline CSVs cover the scores) | `export_figure_data.py` | Regenerable |
| ROC — mixed + MITM "clear win" (Fig-7 analogue) | `plot_cic_roc.py` | `figs/data/roc_points_*.csv`, `figs/data/roc_summary.csv` | `export_figure_data.py` | **Verified** — AUCs match metric CSVs |
| Mixed-stream RMSE panels | `mixed/plot_mixed_rmse.py` | `mixed/arr_*_mixed.npy`, `mixed/attack_blocks.csv` | (plot reads arrays directly) | Regenerable |
| **t-SNE (Fig-6)** | `results/CICIoT2023/figs/plot_tsne.py` | `figs/data/tsne_mixed.csv`, `figs/data/tsne_separation_stats.csv` | `figs/tsne_mixed.{png,pdf}` | **Done** — see §4b + `results/CICIoT2023/tsne_analysis.md` |

### Commands

```bash
PY=.venv/bin/python

# Export the CSVs behind the figures
$PY results/CICIoT2023/export_figure_data.py

# Regenerate the figures themselves
$PY results/CICIoT2023/plot_cic_rmse.py --attacks DoS-SYN_Flood,MITM-ArpSpoofing --downsample 10
$PY results/CICIoT2023/plot_cic_rmse.py --mode fullstream --attacks DoS-SYN_Flood,MITM-ArpSpoofing
$PY results/CICIoT2023/plot_cic_roc.py                       # needs external MITM TSV for src-IP grouping
$PY results/CICIoT2023/mixed/plot_mixed_rmse.py
```

### 4b. t-SNE separation figure (Fig-6)

2-D t-SNE of the mixed-stream Tenko feature vectors (benign vs. the 6 attack classes), showing
class separability. The projected coordinates and the quantitative separation statistics
(silhouette / inter-vs-intra distance) are committed as CSV so the figure is reproducible
without re-running the (stochastic) embedding.

| Item | Path |
|---|---|
| Plot + embedding script | `results/CICIoT2023/figs/plot_tsne.py` |
| Projected coordinates | `results/CICIoT2023/figs/data/tsne_mixed.csv` |
| Separation statistics | `results/CICIoT2023/figs/data/tsne_separation_stats.csv` |
| Figure output | `results/CICIoT2023/figs/tsne_mixed.png` / `.pdf` |
| Analysis write-up | `results/CICIoT2023/tsne_analysis.md` |

```bash
PY=.venv/bin/python
$PY results/CICIoT2023/figs/plot_tsne.py     # writes tsne_mixed.{png,pdf} + figs/data/tsne_*.csv
```

---

## 5. Score-array dictionary (per-packet, committed `.npy`)

For a held-out per-attack test stream (`stream_counts.csv`): `[30k benign_test negatives] + [50k attack positives]`. For the mixed stream: `[60k benign] + [6 × 50k attack blocks] = 360k`.

| Array | Meaning |
|---|---|
| `arr_gold_<a>.npy` / `mixed/arr_gold_mixed.npy` | Binary label per test packet (0 benign / 1 attack) |
| `arr_kitsune_<a>.npy` / `mixed/kitsune_testscores_mixed.npy` | Kitsune X1 score `tanh(RMSE)` |
| `arr_node_<a>_double.npy` | Tenko X2 node-aggregated score `S(n)` |
| `arr_ndg_<a>_{double,single}.npy`, `mixed/arr_ndg_mixed.npy` | Tenko **global** normalized deviation `nd_g = ‖v−c_g‖ / benign_spread_g` |
| `arr_nds_<a>_{double,single}.npy`, `mixed/arr_nds_mixed.npy` | Tenko **node** normalized deviation `nd_s` |
| `arr_cont_<a>_{double,single}.npy`, `mixed/arr_cont_mixed.npy` | Fused score `0.5·nd_g + 0.5·nd_s` (AUC/EER input) |
| `rmse_raw_<a>.npy` | Raw KitNET RMSE over the full stream (pre-tanh) |
| `_double` | committed pipeline `tanh(tanh(raw))`; `_single` | single-tanh variant; `_s60k` | reduced split (`benignLimit=60000`); `_indep` | independent per-attack benign window |
| `baselines/{mateen,vaeesdd,iforest}/*_mixed.npz` | keys `scores`, `preds` (+ `threshold`/`protocol`/`preds_zscore`) for each baseline |

**From-scratch regeneration** (needs external CICIoT2023 PCAP + `tshark`):
```bash
bash scripts/build_streams_ciciot2023.sh          # PCAP -> streams + labels + TSV
.venv/bin/python run_ciciot2023.py --attacks all  # KitNET + Tenko + Kitsune -> arr_*.npy
bash results/CICIoT2023/mixed/build_mixed_stream.sh
.venv/bin/python results/CICIoT2023/mixed/run_mixed.py
```

---

## 6. Baselines (2025–2026 streaming IDS) — provenance

Vendored upstream source lives under `external/` (git-ignored on this branch). The committed baseline **score archives** (`.npz`) were produced by the `results/CICIoT2023/baselines/run_*_cic.py` runners from those upstreams:

| Baseline | Runner | Upstream |
|---|---|---|
| Mateen (adaptive ensemble) | `baselines/run_mateen_cic.py` | vendored `external/Mateen-upstream/` |
| VAE-ESDD (frozen, train-p95) | `baselines/run_vaeesdd_frozen_cic.py` | vendored `external/VAEESDD-upstream/` |
| Isolation Forest (z-score OP) | `baselines/run_iforest_cic.py` | scikit-learn |

To re-run a baseline you must restore `external/` (record the upstream repo + commit) and regenerate features: `baselines/extract_features.py` → `baselines/features/X_mixed.npy`.

---

## 7. Unified Tenko pseudocode (reviewer #5)

> **Derived directly from `results.py` `get_adversarial_IPs_weighted_pattern()` + `tracker.py` + `example.py`.** Symbol map: η_global = `global_pool_tol_factor` (default 50), η_node = `single_agg_tol_factor` (default 20); `FMgrace=5000`, `ADgrace=50000`, fusion weights 0.5/0.5, threshold 0.5.

```
Input : packet stream P = p_1..p_T with source IPs; benign lead length L (benignLimit)
Params: FMgrace, ADgrace; η_global, η_node; weights w_g,w_s; threshold τ; window/segments
Output: per-packet attack decision + continuous scores (nd_g, nd_s)

# ---- X1: KitNET autoencoder anomaly score (Kitsune core) ----
for each packet p_i:
    f_i   = AfterImage.update_get_stats(p_i)          # incremental damped features
    rmse_i = KitNET.process(f_i)                      # train while i<=FMgrace+ADgrace, else execute
    s_i   = tanh(rmse_i)                              # squash to [0,1]   (example.py:157)

# ---- X2: per-node score aggregation ----
for each packet p_i with source IP n:
    nodeScore[n].update(s_i)                          # numerator/denominator with decay (tracker.py)
    S_i = nodeScore[n].get_score()

# ---- Training (benign only, i in [FMgrace+ADgrace+1 .. L]) ----
build per-IP + global pooled + single-aggregate pattern recognizers on segment vectors of S
for each recognizer r:
    c_r   = mean(training segment vectors)            # benign centroid
    tol_r = max_i ‖v_i − c_r‖ × η                     # benign spread × tolerance factor
benign_spread_g = tol_global / η_global ; benign_spread_s = tol_single / η_node

# ---- Testing (i in [L+1 .. T]) ----
for each test packet p_i (source n):
    v_g = current global segment vector ; v_s = current single-aggregate vector
    nd_g = ‖v_g − c_global‖ / benign_spread_g         # η-normalized deviation
    nd_s = ‖v_s − c_single‖ / benign_spread_s
    flag_g = 1 if nd_g > η_global else 0              # equivalently ‖·‖ > tol_global
    flag_s = 1 if nd_s > η_node   else 0
    score_i = w_g·flag_g + w_s·flag_s                 # weighted ensemble (X4)
    decision_i = 1 if score_i ≥ τ else 0
    cont_i = w_g·nd_g + w_s·nd_s                       # threshold-free score for AUC/EER
```

For the CICIoT2023 operating point, `(flag_g, flag_s)` uses **benign-calibrated** thresholds `(η_g, η_s)` chosen so the benign OR-flag rate ≈ target FPR (see the committed `mixed/ciciot2023_calibrated_operating_point_metrics.csv`), instead of the fixed 50/20 defaults.

---

## 8. Quick end-to-end verification

```bash
PY=.venv/bin/python
$PY results/CICIoT2023/build_table_ix_mixed.py --check          # -> CHECK: PASS
$PY recalibrate_ciciot2023.py | tail -2                        # -> All F1 reconciled: 1
$PY results/CICIoT2023/export_figure_data.py                    # -> figs/data/*.csv
$PY results/CICIoT2023/figs/plot_tsne.py                        # -> figs/tsne_mixed.{png,pdf}
```

---

## 9. Latency & throughput (revision — measured)

Single-core, per-packet end-to-end latency and throughput of the Tenko pipeline, measured on
the machine in `results/latency/hardware_spec.txt`.

| Item | Path |
|---|---|
| Measurement driver | `results/latency/measure_latency.py` |
| Hardware spec | `results/latency/hardware_spec.txt` |
| Output table | `results/latency/latency_throughput.csv` |
| Write-up | `results/latency/latency_experiment.md` |

```bash
PY=.venv/bin/python
$PY results/latency/measure_latency.py --output results/latency/latency_throughput.csv
```

---

## 10. Seed-robustness study (revision — M4)

The headline mixed-stream comparison re-run across **6 random seeds** (1, 7, 42, 123, 1234, 2024;
1234 = the committed seed), reporting mean ± std of TPR/FPR/Precision/F1/AUC for Tenko vs. Kitsune
at several operating points. Confirms the result is not seed-cherry-picked.

| Item | Path |
|---|---|
| Aggregated per-seed metrics | `results/CICIoT2023/seed_robustness/seed_robustness_metrics.csv` |
| Write-up (mean ± std tables) | `results/CICIoT2023/seed_robustness/seed_robustness_experiment.md` |

> The per-seed run logs, raw `.npy` arrays, per-seed JSON, and the matplotlib font cache are
> **not** committed (bulk / regenerable); see the write-up for the exact per-seed commands.

---

## 11. Original main-paper tables — revision status

| Blocker | Table | Script | Output CSV | Status |
|---|---|---|---|---|
| **B3** | N-BaIoT per-device/per-attack (Table V) | `results/nbaiot/run_nbaiot_tableV.py` | `results/nbaiot/nbaiot_tableV_metrics.csv` | **Rebuilt from raw data** (80 rows). See `results/nbaiot/MEMO.md`; verification vs. recovered original in `nbaiot_verification_vs_recovered.csv`. |
| **B2** | 9-attack Kitsune main table | `results/main9attack/run_kitsune_9attack.py` | `results/main9attack/kitsune_9attack_metrics.csv` | **Mirai verified** end-to-end vs. paper (`mirai_verification_vs_paper.csv`); paper literals in `paper_literals_resultsNew.csv`. **Other 8 attacks pending** public Kitsune captures — see `results/DATA_LOCATION_REPORT.md`. |

### N-BaIoT provenance note (KitNET_improved)
The original published Table V was produced by an external driver importing `KitNET.KitNET_improved`,
which **no longer exists on disk**. The committed rebuild (`run_nbaiot_tableV.py`) uses the repo's
paper-style `KitNET/KitNET.py` with a fixed 12×10 feature map. It agrees with the recovered original
on **72/80** rows; the 8 divergences are all `gafgyt.tcp/udp` on devices 2/5/7/9, where the original
run collapsed to TPR≈0 while the rebuild detects them. The rebuilt CSV is the defensible,
fully-reproducible artifact; numbers were **run, not transcribed**.

### Commands
```bash
PY=.venv/bin/python
# N-BaIoT Table V (point --dataset at your local UCI N-BaIoT copy)
$PY results/nbaiot/run_nbaiot_tableV.py --dataset ~/dataset/N-BaIoT \
    --output results/nbaiot/nbaiot_tableV_metrics.csv

# 9-attack Kitsune — Mirai (needs the Mirai score stream / dataset; see DATA_LOCATION_REPORT.md)
$PY results/main9attack/run_kitsune_9attack.py --help
```
