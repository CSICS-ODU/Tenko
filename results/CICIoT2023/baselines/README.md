# CICIoT2023 baseline comparison: Tenko vs Kitsune vs Mateen vs VAEESDD (+ iForest)

External baselines run on the same CICIoT2023 streams as Tenko so the methods
can be compared in one table.

- **Mateen** — ICL-ml4csec/Mateen (RAID 2024), adaptive AE ensemble. Cloned to
  `external/Mateen-upstream/`.
- **VAEESDD** — Jin000001/VAEESDD (Neurocomputing 2026). Cloned to
  `external/VAEESDD-upstream/`. The comparison table uses the **frozen-after-benign
  VAE** protocol (`run_vaeesdd_frozen_cic.py`): train on `[0:benignLimit]`, freeze,
  score the test region (same split as Tenko/Kitsune). The earlier unsupervised
  streaming `baseline` (which collapsed on attack-heavy traffic) is archived under
  `vaeesdd/streaming_baseline/`.
- **Isolation Forest** — detection recipe from Ramkumar et al. TSE 2025
  (`external/more-than-zero/`, sklearn `IsolationForest(random_state=42)` +
  Z-score OP). Runner: `run_iforest_cic.py`. Scores under `iforest/`.
  Extended metrics: `comparison_metrics_with_iforest.csv`. ASP abductive
  diagnosis from that paper is **not** applied to these streams (needs Clingo
  smart-home contextual encodings, not packet features).

## Feature representation
Each method's native representation for packet streams: the **100-dim
AfterImage/Kitsune feature vector** (the exact input Tenko's KitNET consumes).
Extracted once with Tenko's `FeatureExtractor`/`netStat` and shared by both
baselines. Mateen natively supports Kitsune features; VAEESDD consumes them as a
generic tabular VAE.

## Evaluation
Each baseline is run "as it runs" natively:
- **Mateen**: `adaptive_ensemble()` with repo-default hyperparameters. Initial
  AE pre-trained (100 epochs) on the benign train region, then windowed
  adaptation (`window_size=50000`) with its labeling budget.
- **VAEESDD**: `main_exp.run()` with `strategy='baseline', method='vae'`,
  streaming the whole stream (`win=2000`, `epochs=20`, `beta=1.0`,
  MinMax-scaled features, adaptive percentile threshold).

Split matches Tenko: train region = first `benignLimit=60000` (benign) packets;
metrics computed on the **same test region** `[60000:]` and the **same gold
labels** for every method, from each method's per-packet anomaly score:
- Tenko → `arr_cont_*`  · Kitsune → `arr_kitsune_*` / `kitsune_testscores_mixed`
- Mateen → AE RMSE (`mateen/*.npz`) · VAEESDD → VAE loss (`vaeesdd/*.npz`)

ROC-AUC / PR-AUC are threshold-free; `f1_best` is the best F1 over all
thresholds; `tpr_at_1fpr` fixes the threshold at 1% FPR on benign test scores.

## Reproduce
```bash
# 1. features (base env: numpy/sklearn/scapy)
.venv/bin/python results/CICIoT2023/baselines/extract_features.py
# 2. Mateen (torch env)
.venv_mateen/bin/python results/CICIoT2023/baselines/run_mateen_cic.py --all
# 3. VAEESDD frozen VAE (TF env; must run outside the tool sandbox)
.venv_vae/bin/python results/CICIoT2023/baselines/run_vaeesdd_frozen_cic.py --all
# optional: original streaming baseline (collapses on attack-heavy traffic)
# .venv_vae/bin/python results/CICIoT2023/baselines/run_vaeesdd_cic.py --all
# 4. one comparison table -> comparison_metrics.csv
.venv/bin/python results/CICIoT2023/baselines/build_comparison_table.py
```

## Notes
- VAEESDD's vendored copy ships without its `data/` loaders and had a
  single-sample `.predict()` per timestep (too slow) and a `torch`/mnist import
  at module top; these were patched in `external/VAEESDD-upstream/` (direct
  eager calls, optional imports). No detector math was changed.
- Frozen VAE = train on benign `[0:60000]`, threshold = 95th pct of train scores,
  no updates on the test region. Streaming baseline archived under
  `vaeesdd/streaming_baseline/` (mixed AUC 0.17 → frozen 0.95).
- Mateen loads a pre-trained checkpoint (`Models/{stream}.pth`); we train and
  save it first (their shipped workflow), then let `adaptive_ensemble` adapt it.
