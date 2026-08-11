# Tenko — Reproducibility Manifest

**Branch:** `public-release` (base: `correct-latency`).
**Purpose:** map every figure/table in the manuscript to the *script → input data → output CSV* that regenerates it, with exact commands, so a suspicious reviewer can reproduce the numbers from committed code + data. Read `AUDIT_REPORT.md` for the honest gap list (what is **not** yet reproducible and why).

> **Scope note.** This branch consolidates the **CICIoT2023 revision** (the new, headline recent-dataset work: mixed-stream binary comparison, per-class AUC/EER, baselines, operating-point and out-of-sample analyses, and the RMSE/ROC figures). The **original main-paper tables** (the 9-attack Kitsune-mixture per-attack table, the N-BaIoT/Hermes Table V, and the latency Table IX) are **NOT fully reproducible from this repo** — see `AUDIT_REPORT.md` §Blockers. Do not present them as regenerated here.

---

## 1. Environment

Two Python environments exist in the tree; the one that reproduces every number below is the repo `.venv`:

| | Interpreter | Key packages |
|---|---|---|
| **Actual working env** (`.venv/`) | Python **3.14.5** | numpy 2.5.1, scikit-learn 1.9.0, scipy 1.18.0, pandas 3.0.5, matplotlib 3.11.1 |
| `requirements.txt` (stale pins) | (pins Py3.9-era) | numpy 1.26.4, scikit-learn 1.6.1, torch <2.6 |

- The CICIoT2023 **analytical** scripts (metrics recomputed from cached `.npy`/`.npz`) only use core numpy / scikit-learn and reproduce identically under the `.venv`.
- Exact frozen versions of the working env: `results/CICIoT2023/environment_lock.txt`.
- `requirements.txt` is retained for the original pinned environment but is **out of date** relative to `.venv`; regenerate a fresh lock if you rebuild the env. (Flagged in `AUDIT_REPORT.md`.)

All commands below assume repo root `/Users/sbhola/Desktop/Tenko` and use:

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

**Excluded via `.gitignore`** (large / raw / regenerable — see `AUDIT_REPORT.md` §Data hosting):
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
| Mixed operating-point sweep (committed η, cont@x%, **orrule@2%/5%**, Kitsune med+MAD/@x%) | `results/CICIoT2023/mixed/_calibrated_operating_point.py` | `mixed/arr_*_mixed.npy`, `mixed/kitsune_testscores_mixed.npy` | `mixed/ciciot2023_calibrated_operating_point_metrics.csv` | **Verified** — orrule@2% TPR 0.9801 / FPR 0.0200 / AUC 0.9897 |
| Per-class **AUC/EER + recalibrated η @1%/5%** (double-tanh) | `recalibrate_ciciot2023.py` | `arr_*_{double,single}.npy`, `ciciot2023_committedEta_double.csv`, `stream_counts.csv` | `ciciot2023_metrics_recalibrated.csv`, `ciciot2023_per_class_metrics.csv` | **Verified** — all F1 reconcile; matches roadmap |
| single-vs-double **tanh impact** | `recalibrate_ciciot2023.py` | `arr_*_{double,single}.npy` | `ciciot2023_tanh_impact.csv` | **Verified** |
| **Out-of-sample η** (held-out benign FPR non-transfer) | `recalibrate_ciciot2023_oos.py` | `arr_*_{double,single}.npy`, `stream_counts.csv` | `ciciot2023_metrics_recalibrated_oos.csv` | Regenerable |
| Baseline comparison @1% FPR + threshold-free | `results/CICIoT2023/baselines/build_comparison_table.py` | `mixed/arr_cont_mixed.npy`, `mixed/kitsune_testscores_mixed.npy`, `baselines/{mateen,vaeesdd,iforest}/*.npz` | `baselines/comparison_metrics.csv` | Regenerable |
| Individual-stream slices (contiguous/random benign) | `results/CICIoT2023/_analyze_individual.py` | `arr_*_<attack>_s60k.npy` | `ciciot2023_individual_streams_metrics.csv` | Regenerable |
| Clean-split protocol | `results/CICIoT2023/_analyze_cleansplit.py` | `arr_*_<attack>_s60k.npy` | `ciciot2023_cleansplit_metrics.csv` | Regenerable |
| single-tanh η grid search (incl. oracle) | `results/CICIoT2023/_analyze_reduced.py` | `arr_*_<attack>_s60k.npy` | `ciciot2023_singletanh_gridsearch_metrics.csv` | Regenerable |
| Per-source-device AUC/EER | `results/CICIoT2023/source_level_experiment.py` | `arr_kitsune_*`, `arr_cont_*_double.npy` **+ external pilot TSV** | `ciciot2023_source_level_metrics.csv` | Regenerable *(needs external TSV)* |
| Independent-stream robustness (distinct benign window per attack) | `results/CICIoT2023/indep/run_indep.py` | `indep/arr_*_indep.npy` (or rebuild from **raw PCAP**) | `indep/ciciot2023_independent_streams_metrics.csv` | Regenerable *(from cached arrays; from-scratch needs PCAP)* |

### Commands

```bash
PY=.venv/bin/python

# Headline mixed-stream table (Table IX/"X")
$PY results/CICIoT2023/build_table_ix_mixed.py --check      # verify == committed
$PY results/CICIoT2023/build_table_ix_mixed.py              # rewrite the CSV

# Mixed operating points (orrule@2% etc.)
cd results/CICIoT2023/mixed && $PY _calibrated_operating_point.py && cd -

# Per-class AUC/EER + recalibration + tanh impact
$PY recalibrate_ciciot2023.py
$PY recalibrate_ciciot2023_oos.py

# Baseline comparison + macro-F1 verification
$PY results/CICIoT2023/baselines/build_comparison_table.py
$PY results/CICIoT2023/_verify_macro_f1_table_x.py
```

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
| **t-SNE (Fig-6)** | **NONE** | **NONE** | — | **MISSING — see `AUDIT_REPORT.md` blocker** |

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

For the CICIoT2023 operating point, `(flag_g, flag_s)` uses **benign-calibrated** thresholds `(η_g, η_s)` chosen so the benign OR-flag rate ≈ target FPR (`_calibrated_operating_point.py`), instead of the fixed 50/20 defaults.

---

## 8. Quick end-to-end verification

```bash
PY=.venv/bin/python
$PY results/CICIoT2023/build_table_ix_mixed.py --check          # -> CHECK: PASS
cd results/CICIoT2023/mixed && $PY _calibrated_operating_point.py | grep orrule@2%
# -> Tenko orrule@2% 0.9801 0.0200 ... 0.9897
cd - && $PY recalibrate_ciciot2023.py | tail -2                 # -> All F1 reconciled: 1
$PY results/CICIoT2023/export_figure_data.py                    # -> figs/data/*.csv
```
