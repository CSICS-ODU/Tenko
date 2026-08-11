# Tenko — Skeptical Reproducibility Audit

**Manuscript:** TCE-2026-04-1823.R1 — "Tenko: A Real-Time Intrusion Detection Framework with Context-Aware Anomaly Scoring" (IEEE TCE, minor revision).
**Audited branch base:** `correct-latency`; audit + fixes staged on **`public-release`**.
**Auditor stance:** assume nothing reproduces until the script + data are seen and the number is re-run. Findings are separated into **reproducibility gaps** (missing CSV/script) and **claim gaps** (over-reach / unsupported), then prioritized blocker → major → minor.

---

## 1. Repo / branch map — where the final code lives

| Component | Location | Notes |
|---|---|---|
| Core Tenko (KitNET X1, node scoring X2, tolerance layer, weighted ensemble) | `main` and `correct-latency`: `results.py`, `tracker.py`, `example.py`, `KitNET/`, `AfterImage.py`, `FeatureExtractor.py`, `netStat.py`, `workflow.py`, `Kitsune.py` | Node scoring = `tracker.nodeScore` keyed by source IP; tolerance = `global_pool_tol_factor`(η_global=50) / `single_agg_tol_factor`(η_node=20) computed from **benign-only** max intra-cluster distance (`results.py:696-705, 884-893`). |
| `results.py` additive extension (`benignLimit`, `return_scores`) | **uncommitted** working-tree change on `correct-latency` | Non-breaking; every CICIoT2023 driver depends on it. **Committed on `public-release`.** |
| Latency / memory harness | `correct-latency`: `measure_all_latency.py`, `memutil.py`, `mateen_reference/` | Real per-packet X1–X4 timing; **no committed result files**. |
| Main-paper 9-attack per-attack table (Mirai, Fuzzing, SSDP, Wiretap, SSL Reneg., Video Inj., ARP MITM, OS Scan, Syn DOS) | `Daksh-Mateen`: `resultsNew.py` lines ~142-190 | **Hard-coded numeric literals** (TPR/FPR/FNR/Precision arrays), no driver, no CSV, **no AUC/EER**. |
| N-BaIoT / Hermes per-device Table V | **not in any branch/history** | Pickaxe search (roadmap R7-A) found the class/device strings were never committed. |
| CICIoT2023 revision (mixed / indep / baselines / figures) | working tree on `correct-latency`, under `results/CICIoT2023/` | Was **entirely git-untracked** (`git ls-files` → 0). **Now committed on `public-release`** (minus large raw files). |

**Branch inventory:** `main`, `correct-latency` (branch of record), `cython-latency-measurement`, `Daksh-Mateen`, plus remote `daksh-latency`, `daksh-x1x4-fix`, `integrate-multichannel-working`, `latency-memory-experiment`, `zero-trust-implementation`.

---

## 2. Key-number reproduction (what I ran, pass/fail)

All re-run with `.venv/bin/python` (Python 3.14.5, numpy 2.5.1, sklearn 1.9.0) from committed `.npy`/`.npz` — **no PCAP/TSV, no model re-run.**

| Claim / number | Source of truth | Re-run result | Verdict |
|---|---|---|---|
| Mixed Table IX/"X": **Tenko orrule@2% TPR 0.9801 / FPR 0.0200 / AUC 0.9897** | `mixed/_calibrated_operating_point.py`; `build_table_ix_mixed.py` (new) | TPR 0.9801, FPR 0.0200, AUC 0.98968; η_g=30.14, η_s=3.14 | **PASS (exact)** |
| Mixed Table IX rows: Kitsune 0.9637/0.1971/0.9733; Mateen 0.9048/0.0488/0.9665; VAEESDD 0.8251/0.0140/0.9540; iForest 0.6115/0.0514/0.9347 | `table_ix_mixed_with_iforest.csv` | `build_table_ix_mixed.py --check` → **PASS** (≤1e-3; TPR/Acc differ ≤1.4e-4 from OR-rule grid granularity, both round to paper precision) | **PASS** |
| Macro-F1 definition (mean of 6 per-attack F1 vs shared benign, not sklearn macro) | `_verify_macro_f1_table_x.py` | Reproduced; `atkMac` == CSV `MacroF1` | **PASS** |
| Per-class recalibrated η @1%/5% (DoS-SYN 0.963 F1 0.966 AUC 0.988; MITM 0.824/0.889/0.949; DDoS 0.783/0.864/0.929; Mirai 0.712/0.817/0.937; Recon 0.115/0.200/0.796; Dict 0.031/0.058/0.697) | `recalibrate_ciciot2023.py` | Reproduced exactly; **"All F1 reconciled: 1"** | **PASS** |
| Committed η=50/20 is **degenerate under double-tanh** (TPR=FPR=0), non-degenerate for 4/6 under single-tanh | `recalibrate_ciciot2023.py` (Task 2) | Reproduced | **PASS** |
| Figure ROC AUCs (mixed Tenko 0.9897 / Kitsune 0.9733; MITM Tenko 0.949 / Kitsune 0.942) | `export_figure_data.py` (new) | Reproduced from `arr_cont`/`arr_kitsune` | **PASS** |

**No CICIoT2023 number failed to reproduce.** Nothing in the mixed/per-class results is hand-curated: every cell traces to a committed array. Numbers I could **not** reproduce are the ones with no committed code+data at all (main-paper 9-attack table, N-BaIoT Table V, latency table) — see blockers.

---

## 3. Claim audit (over-reach)

### 3a. "Real-Time" claim — **NOT SUPPORTED as written**
- `measure_all_latency.py` measures real per-packet **X1–X4 processing latency** on **offline sequential PCAP/TSV replay** with a single thread on pre-extracted features. Throughput is **derived** (`1000/mean_ms`), not a sustained load test.
- **No CPU-utilization %** anywhere (`psutil` is used only for RSS memory).
- **No packet-drop measurement / live capture** anywhere (no `AF_PACKET`, `pcap.open_live`, `sniff`, NIC ingest). "0 packet drops" in the roadmap is an *offline alignment* assertion, not a capture measurement.
- **No committed hardware spec** for Tenko latency runs; the only committed HW string is Apple-Silicon macOS in an **upstream Kitsune** JSON (`external/Kitsune-upstream/mirai_latency_report_50k_exec.json`), which times X1 only.
- **No committed Tenko latency/throughput/memory result file** — the harness would write `mirai_performance_results/real_latency_arrays_seed42.npz`; it is not in the repo.
- **Detection latency is an honest loss:** `_win_latency.py` shows Kitsune alarms in 7–28 packets vs Tenko in thousands (per `path_to_clear_win.md`).

→ The reviewer's E3/R1.3 bar (HW specs + packet rate + CPU% + drop rate) is **not met**. Must **soften to "streaming / real-time-capable under sequential PCAP replay"** everywhere (incl. title) **or** run and commit a live-capture experiment.

### 3b. Novelty beyond "Kitsune post-processing" — **defensible, is a distinct mechanism**
- The node-scoring + tolerance + ensemble layers are genuinely separate code from KitNET: `tracker.nodeScore` (per-source-IP aggregation), the benign-calibrated pattern recognizers (`results.py:696-714`), and the weighted global/single-aggregate fusion (`results.py:940-943`). These operate on top of X1 but are not Kitsune. The claim is code-supported; state it as a context-aware scoring layer over a KitNET backbone (do **not** claim a new detector core).

### 3c. η_global / η_node justification — **consistent and code-backed**
- Both are **benign-only** multipliers on the max benign intra-cluster distance (`tol = max‖v−c‖ × η`, `results.py:703-704`; `benign_spread = tol/η`, `:892-893`). Attack labels are **not** used to set them. The CICIoT2023 operating point recalibrates `(η_g, η_s)` from benign quantiles to a target benign FPR — still label-free. This directly answers Reviewer #4; make sure the manuscript states η is a **per-deployment benign-calibrated scale**, not a label-tuned operating point.

### 3d. Seed robustness — **NOT DONE**
- Only a **single fixed seed** exists (`RANDOM_SEED=42`, `KitNET/autoencoder.py:114 torch.manual_seed(42)`, `measure_all_latency.py:54`). There is **no multi-seed sweep, no variance/CI, no across-seed CSV** anywhere in the repo. Reviewer R1.8's "robustness across random seeds" is unaddressed.

### 3e. CICIoT2023 operating-point / FPR-transfer honesty — **must keep the caveat**
- The in-sample 1%/5%/2% benign FPR is **definitional**: `recalibrate_ciciot2023_oos.py` shows a fixed benign-calibrated η does **not** transfer out-of-sample (held-out benign FPR ≈ 0% one way, ≈30% the other) due to a benign CDN burst (non-stationarity, per `cic_config_audit.md`). **AUC/EER are the stable, honest headline numbers.** Do not present the low in-sample FPR as a generalization result — the repo's own OOS CSV contradicts that. The committed drafts already frame this correctly; keep it.

### 3f. Metric-integrity items still open (from roadmap §6, not re-verified here)
- Cross-table F1 reconciliation for the **main-paper** 9-attack tables (those are literals on `Daksh-Mateen`, not re-runnable — see blocker B2). Memory-overhead caption should state `deep_sizeof` (object graph), not RSS. Mateen "same platform" wording needs to match whether numbers were locally measured.

---

## 4. PRIORITIZED gap list

### BLOCKERS (reproducibility grounds or over-claim that invites rejection)

| # | Type | Gap | Fix | Status |
|---|---|---|---|---|
| **B1** | Claim | **"Real-time" unsupported** — no packet rate under load / CPU% / drop rate / committed HW specs. | Soften title + every "real-time" to "streaming / replay-capable under sequential PCAP replay," **or** run a live-capture drop-rate + CPU% experiment on stated hardware and commit results. No measurement script for drop/CPU exists to run. | **NEEDS USER / HARDWARE** (cannot fabricate) |
| **B2** | Repro | **Main-paper 9-attack per-attack table not reproducible** — numbers are hard-coded literals in `Daksh-Mateen:resultsNew.py`; no driver, no CSV, no AUC/EER; raw RMSE pickles + attack PCAPs not committed. | Write a committed 9-attack driver that regenerates TPR/FPR/F1/AUC/EER from `RMSEs_*.pkl` + `*_labels.csv`, then commit those inputs. | **NEEDS USER** (source data/pickles absent from repo) |
| **B3** | Repro | **N-BaIoT / Hermes Table V not in repo at all** — never committed (forensic pickaxe negative). | Locate the external workspace that produced it and commit code+CSV, or regenerate with a committed N-BaIoT loader + per-device eval, or drop reliance on Table V. | **NEEDS USER** |
| **B4** | Repro | **t-SNE (Fig 6) has no script/data/figure** for CICIoT2023 (Reviewer #5 wants it *deepened*). Only legacy N-BaIoT loaders contain dead `TSNE=False` code. | Add a committed t-SNE script over the committed feature/score arrays (e.g. `baselines/features/X_mixed.npy`), export the 2-D embedding CSV, and write the deepened discussion. | **NEEDS follow-up** (feature matrix is git-ignored/large; script must be written) |

### MAJOR

| # | Type | Gap | Fix | Status |
|---|---|---|---|---|
| **M1** | Repro | Headline mixed Table IX/"X" **had no builder script** (was assembled ad hoc); only the CSV existed. | Added `results/CICIoT2023/build_table_ix_mixed.py` regenerating the CSV from committed arrays; `--check` PASS. | **FIXED** |
| **M2** | Repro | Figures had **no committed CSV** of underlying numbers (only `.npy` + plot scripts) — Reviewer #7's exact question. | Added `results/CICIoT2023/export_figure_data.py` → `figs/data/rmse_timeline_*.csv`, `rmse_thresholds.csv`, `roc_points_*.csv`, `roc_summary.csv`. | **FIXED** |
| **M3** | Repro | Entire CICIoT2023 result tree was **git-untracked**. | Committed scripts + CSVs + score arrays + baseline `.npz` on `public-release`; large raw excluded via `.gitignore`. | **FIXED** |
| **M4** | Claim | **Seed robustness absent** (R1.8). | Run KitNET/Tenko for ≥3 seeds and report AUC mean±sd (needs re-run of the pipeline with varied seeds). No multi-seed harness exists yet. | **NEEDS re-run** |
| **M5** | Repro | `requirements.txt` is **stale** (pins numpy 1.26.4/py3.9; actual `.venv` is py3.14 + numpy 2.5.1) → a reviewer following it may not reproduce. | Committed `results/CICIoT2023/environment_lock.txt` (actual freeze); regenerate `requirements.txt` from the working env before release. | **PARTIAL** (lock committed; requirements.txt still needs refresh) |
| **M6** | Repro | Unified pseudocode (Reviewer #5) not consolidated in-repo. | Added faithful pseudocode derived from `results.py`/`tracker.py`/`example.py` in `REPRODUCIBILITY.md §7`. | **FIXED** |

### MINOR

| # | Type | Gap | Fix | Status |
|---|---|---|---|---|
| **m1** | Repro | Two differently-named "individual streams" experiments (`_analyze_individual.py` vs `indep/run_indep.py`) are easy to confuse. | Documented the distinction in `REPRODUCIBILITY.md §3`. | **FIXED (doc)** |
| **m2** | Claim | double-`tanh` (`tanh(tanh(raw))`) is undocumented in methods. | Provenance settled (predates paper numbers; AUC delta ≤0.011): add one methods sentence; do **not** change published numbers. | Documented; text edit **NEEDS USER** |
| **m3** | Repro | Source-level + independent-stream from-scratch rebuild needs external pilot TSV / raw PCAP (not committable). | Cached arrays committed so CSVs still regenerate; from-scratch path + dataset URL documented. | **FIXED (doc)** |
| **m4** | Claim | Decision-fusion / state-persistence / related-work wording over-reaches (roadmap §6). | Soften per roadmap checklist. | **NEEDS USER (text)** |

---

## 5. Reproducibility status summary

**Fully reproducible now from committed code + data (`public-release`, no PCAP/TSV):**
- Mixed-stream binary comparison table (Tenko/Kitsune/Mateen/VAEESDD/iForest) — `build_table_ix_mixed.py`.
- Mixed operating-point sweep incl. orrule@2%/5% — `mixed/_calibrated_operating_point.py`.
- Per-class AUC/EER + recalibrated η + tanh-impact — `recalibrate_ciciot2023.py`.
- Out-of-sample η / FPR-transfer table — `recalibrate_ciciot2023_oos.py`.
- Baseline @1%-FPR + threshold-free comparison — `baselines/build_comparison_table.py`.
- Individual-stream / clean-split / single-tanh grid tables — `_analyze_*.py`.
- RMSE-timeline and ROC figures **and their data CSVs** — `plot_cic_rmse.py`, `plot_cic_roc.py`, `export_figure_data.py`.

**Reproducible only with external data (documented):** per-source-device table and independent-stream from-scratch rebuild (need pilot TSV / raw CICIoT2023 PCAP).

**Not reproducible from this repo (blockers):** main-paper 9-attack per-attack table (B2), N-BaIoT Table V (B3), any latency/throughput/CPU/drop table (B1), t-SNE Fig 6 (B4).

---

## 6. Data hosting / large files

Excluded from git (host externally or regenerate; see `.gitignore`): `*.pcap`/`*.pcapng` and `*.pcap.tsv` (~2.1 GB, from registration-gated CICIoT2023), `baselines/features/X_*.npy` (~551 MB, regenerable via `extract_features.py`), `mixed/rebal/` bulk streams, and vendored `external/` upstream baselines. Committed data behind the numbers (score arrays + baseline `.npz` + CSVs) totals ~250 MB; largest single file 10 MB (no Git-LFS needed).

---

## 7. Reviewer-blocker call-outs (explicit)

- **Real-time / hardware / packet-drop (E3, R1.3):** **UNMET.** No live-capture, no CPU%, no drop-rate, no committed HW spec, no committed Tenko latency artifact. **Soften the claim or run+commit the experiment.** Cannot be fabricated.
- **Seed robustness (R1.8):** **UNMET.** Single fixed seed 42; no multi-seed study. Requires a pipeline re-run over multiple seeds.
