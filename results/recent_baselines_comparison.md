# Recent IDS / anomaly-detection systems (2023–2026) vs. Tenko

**Purpose.** Answer Assoc. Editor E2 and Reviewers R1.4 / R1.6: a comprehensive table
comparing **≥8 recent systems** (methodology, supervision, streaming, datasets, reported
performance, resource footprint) and how Tenko differs — including **≥2 unsupervised *streaming*
IDS from 2025–2026**.

## Verification status
Every row was checked against a live web source (title/venue/year/DOI). All 11 systems below are
**real and findable**. Nothing here is a placeholder; the one item marked **[VERIFY]** is a
*numeric* caveat (a reported figure not independently reproduced by us), not a doubt about the
paper's existence. Where the manuscript's earlier working notes had an approximate author name or
title, the **corrected, verified** citation is used here (see "Corrections vs. repo notes" at the
end).

**Tenko numbers** are from committed CSVs (`results/CICIoT2023/ciciot2023_per_class_metrics.csv`,
`ciciot2023_source_level_metrics.csv`, `baselines/table_ix_mixed_with_iforest.csv`); baseline
numbers are **as reported** by each paper unless the row says "our run" (Mateen/VAE-ESDD/iForest
were re-run on our CICIoT2023 streams — see `results/CICIoT2023/baselines/README.md`).

---

## 1. Master comparison table (≥8 recent systems)

| # | System (year, venue) | Method | Supervision | Streaming / online? | Input domain | Dataset(s) | Reported performance | Resource footprint | How Tenko differs |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **Adaptive NAD** (2024/25, arXiv 2410.22967; code public) | Two-layer pseudo-label AD + online threshold update | **Unsupervised**, self-adaptive | **Yes** (online, self-updating) | Flow features | CIC-Darknet2020, NSL-KDD, Edge-IIoTset | Edge-IIoTset Acc 93.71%, F1 92.55%, **FAR 0.08%**; >3× faster online inference than SOTA | ">3× faster" latency claim; no per-device memory stated | Tenko keys state on **per-source IP** for device attribution; Adaptive NAD is flow-level with no node model. Best apples-to-apples *streaming unsupervised* baseline to cite. |
| 2 | **VAE-ESDD (VAE++ESDD)** (2026, Neurocomputing, DOI 10.1016/j.neucom.2026.133061; code public) | Two-level ensemble: VAEs + statistical drift detectors, incremental | **Unsupervised**, online | **Yes** (streaming, drift-adaptive) | Generic tabular streams | Real+synthetic streams (severe class imbalance) | Recall >0.75 & Specificity >0.65 across datasets; beats ARCUS/MemStream/METER/SEAD | Sliding-window ensemble; per-model overhead not itemized | We **re-ran** VAE-ESDD (frozen-benign protocol) on our CICIoT2023 mixed stream: ROC-AUC 0.9540 vs Tenko **0.9897** (`comparison_metrics_with_iforest.csv`). Tenko adds per-source context + packet-level operation. |
| 3 | **AdaptiveAE-IDS** (2026, Int. J. Intelligent Eng. & Systems, DOI 10.22266/ijies2026.0731.35) | Sparse AE + multi-head feature-attention gate + contrastive latent + MC-Dropout + **Page-Hinkley** drift threshold | **Unsupervised**, benign-only | **Yes** (online threshold recalibration, no retrain) | Flow features | **CICIoT2023** (33 attacks); cross-eval UNSW-NB15 | DR 79.26%, FAR 10.08%, **F1 86.80%, AUC-ROC 92.42%**; net-layer attacks 97–100% | **44K params, sub-ms inference**, fits commodity IoT gateway | Strongest **conceptual rival** (benign-only, CICIoT2023, edge, drift-adaptive). Tenko differs by operating on the **packet stream with per-source node aggregation** vs flow-level AE; and reports transfer-safe AUC/EER. |
| 4 | **IMME** (2026, IEEE QPAIN, DOI 10.1109/QPAIN69676.2026.11546448) | 5-detector ensemble: Adaptive Streaming Clustering + AE + Mahalanobis + iForest + O(1) sliding-window rarity kernel | **Unsupervised** (zero-day) | **Yes** (streaming, O(1) kernel) | Flow features | **CICIoT2023** | **ROC-AUC 0.9560**, UDR 47%, OSCR 47.5%, 100% precision (val-opt threshold) | **79,000 flows/sec** throughput | Tenko is a **single stateful per-source detector** (not a 5-way flow ensemble) and provides per-device attribution; comparable ROC-AUC band (Tenko mixed 0.9897, per-attack mean 0.883). |
| 5 | **PGTAD** (2025, IEEE Access, DOI 10.1109/access.2025.3610684) | Patch-Gate GRU-autoencoder, Mahalanobis on reconstruction error | **Unsupervised** | **Yes** (real-time MVTS) | Packet **and** flow | Edge-IIoTset, **CICIoT2023**, CICIoMT2024, CICIoV2024 | Avg F-score **0.92** | **>480K packets/sec on Jetson Orin Nano 8GB** (edge HW stated) | PGTAD models time-series windows globally; Tenko models **per-source-IP** behaviour and fuses global+node envelopes. Good recent *edge real-time* reference with explicit HW. |
| 6 | **Perf.–Efficiency Benchmark** (Lee & Zhang, 2025, ACSAC WAITI workshop) | Systematic benchmark of 10 AD architectures (IF, OC-SVM, GMM, AE, VAE, VQ-VAE, LSTM-AE, Deep SVDD, …) | **Unsupervised**, benign-only | Batch/offline eval | Flow features | **CICIoT2023** (benign-only train, 5 seeds) | LSTM-AE 99.58% ROC-AUC; AE 99.44%; **tree methods recall <45%** | **AMD Ryzen 9 / 20 GB "IoT-gateway" profile**; training time spans 4 orders of magnitude; model sizes (e.g. AE 36 KB) | Provides the **resource-footprint + multi-seed** framing reviewers want; Tenko adds per-source streaming detection the benchmark's static AEs lack. Cite for HW/efficiency context and seed methodology. |
| 7 | **Mateen** (2024, RAID; DOI 10.1145/3678890.3678901; code public) | Adaptive **ensemble of deep AEs** with drift detection, coreset sample selection, model merge/prune | **Unsupervised** core, **1% labeling budget** for updates | **Yes** (online, drift-adaptive) | Flow / Kitsune features | CICIDS2017, CSE-CIC-IDS2018, **Kitsune** (+2 variants) | +4.13% F1 (IDS17) … +72.6% F1 (Kitsune) over static DAE | Ensemble compaction to bound cost; needs periodic labeling | We **re-ran** Mateen on our CICIoT2023 mixed stream: ROC-AUC 0.9665 vs Tenko **0.9897** (`comparison_metrics_with_iforest.csv`). Tenko is **label-free** (no labeling budget) and per-source. |
| 8 | **ReCDA** (KDD 2024; ext. IEEE TDSC 2025, DOI 10.1109/TDSC.2025.3599321) | Self-supervised representation enhancement (drift-aware perturbation + alignment) + weakly-supervised tuning | **Weakly-supervised** (drift adaptation) | **Yes** (online + offline eval) | Flow features | Multiple NIDS benchmarks under drift | Superior adaptability/robustness vs SOTA under varying drift | Not itemized | Tenko is fully **benign-only / label-free** and adds per-device state; cite ReCDA as a recent drift-adaptation point (weakly-supervised, so not a strict unsupervised head-to-head). |
| 9 | **Sukanya & Daniel Madan Raja** (2025, ICTACT J. Comm. Tech., DOI 10.21917/ijct.2025.0546) | **VAE + Isolation Forest** hybrid, benign-only | **Unsupervised**, benign-only | Offline (flow batch) | Flow CSV (CICFlowMeter) | **CICIoT2023** (4 attacks: DDoS-HTTP, Browser-Hijack, Backdoor, SQLi) | Overall **ROC-AUC 0.8947, F1 0.55**; per-attack ROC-AUC 0.94–0.97 | Not stated | Same paradigm (unsup. benign-only) but **flow-level** — CSVs drop source IP, collapsing node aggregation. Ideal single-number unsupervised CICIoT2023 reference; Tenko mean ROC-AUC 0.883 sits in the same band **plus** packet-level per-source detection. |
| 10 | **Ramkumar et al.** (2025, IEEE TSE 51(11):3117-3137, DOI 10.1109/TSE.2025.3610540) | **Per-device iForest** + Answer-Set-Programming abductive diagnosis | **Unsupervised** (benign-trained) | Offline (flow batch) | Flow features | **CICIoT2023**, IoT-23 | **AUC-PR 0.91–0.9991** (mean ≈0.967), F1 0.62–0.97 (per device) [VERIFY numeric: AUC-PR ≠ ROC-AUC, not on the same axis] | Clingo/ASP reasoning layer (needs smart-home context encodings) | We **re-ran** the iForest detection recipe (z-score OP) on our streams (`baselines/`); Tenko keeps the **streaming per-packet** path and reports ROC-AUC/EER (do **not** compare directly to their AUC-PR). |
| 11 | **Ullah et al.** (2025, Scientific Reports 15:31072, DOI 10.1038/s41598-025-16553-w) | Ensemble CNN+BiLSTM+RF+LR, weighted soft-voting, SMOTE | **Supervised**, multi-class (34 classes) | Offline batch | Flow CSV | BOT-IoT, **CICIoT2023**, IoT-23 | CICIoT2023 **Acc 99.2%, F1 0.992, AUC 0.992** (k-fold, in-distribution) | ~12,320 s training (offline, heavy DL) | **Supervised upper bound**, not a head-to-head. Base-learner macro-F1 ≈0.62–0.68 reveals minority-class weakness. Tenko is **label-free / zero-day-capable / streaming**; cite as a supervised ceiling only. |

**Legend.** "our run" = the baseline was executed on our exact CICIoT2023 streams with shared
gold labels (`results/CICIoT2023/baselines/`). All other cells are **as reported** by the cited
paper.

---

## 2. Which rows satisfy each reviewer requirement

- **≥2 unsupervised *streaming* IDS from 2025–2026 (E2 / R1.6):** rows **1 (Adaptive NAD)**,
  **2 (VAE-ESDD, Neurocomputing 2026)**, **3 (AdaptiveAE-IDS, IJIES 2026)**, **4 (IMME, QPAIN
  2026)**, **5 (PGTAD, Access 2025)** — five, well above the minimum. Adaptive NAD and Mateen
  have public code; VAE-ESDD, Mateen and iForest were **actually re-run** on our data.
- **≥8 recent systems with resource footprint (R1.4):** all 11 rows are 2023–2026; footprint is
  itemized where the paper reports it (rows 3, 4, 5, 6, 11 give params/throughput/HW/training
  time). Rows 6 (ACSAC benchmark) and 5 (PGTAD) give explicit **hardware profiles and model
  sizes** — the exact "resource footprint" evidence the reviewer asked for.
- **Same-paradigm CICIoT2023 unsupervised references:** rows 3, 4, 9, 10 all evaluate on
  CICIoT2023 with benign-only/unsupervised training — the tightest comparators.

---

## 3. Head-to-head numbers we actually ran (CICIoT2023 mixed stream, shared labels)

From `results/CICIoT2023/baselines/comparison_metrics_with_iforest.csv` and
`baselines/table_ix_mixed_with_iforest.csv` (ROC-AUC, threshold-free; operating points from
`mixed/_calibrated_operating_point.py`):

| Method (mixed stream) | ROC-AUC | PR-AUC | Best F1 | TPR@1%FPR | Operating point |
|---|---|---|---|---|---|
| **Tenko (ours)** | **0.9897** | **0.9980** | **0.9813** | 0.8819 | orrule@2%: TPR 0.9801 / FPR 0.0200 (η_g=30.14, η_s=3.14) |
| Kitsune (X1 only) | 0.9733 | 0.9949 | 0.9639 | 0.8200 | med+MAD FPR≈0.197 |
| Mateen (our run) | 0.9665 | 0.9937 | 0.9600 | 0.8078 | — |
| VAE-ESDD (our run, frozen) | 0.9540 | 0.9914 | 0.9522 | 0.8126 | — |
| Isolation Forest (our run, z-score) | 0.9347 | 0.9802 | 0.9579 | 0.1113 | — |

This is a **real, same-data, same-label** comparison of Tenko against four baselines (two of
them recent streaming systems), which is stronger than a reported-numbers-only table.

---

## 4. Honest caveats to keep in the manuscript

- **Feature-domain mismatch.** Rows 3, 4, 6, 9, 10, 11 use **flow-level** features
  (CICFlowMeter/aggregates), which drop the per-packet source IP; Tenko operates on the **raw
  packet stream** precisely to retain node identity. Aggregate metrics are comparable; per-attack
  head-to-heads across feature domains are not.
- **Metric-type mismatch.** Ramkumar (row 10) reports **AUC-PR**, which runs higher than ROC-AUC
  under class imbalance — do **not** place it on Tenko's ROC-AUC axis. Flagged **[VERIFY]** as a
  numeric caveat.
- **Attack-subset mismatch.** No two CICIoT2023 papers use the same attack subset; only overall/
  representative aggregates should be compared.
- **Supervision mismatch.** Row 11 (Ullah) is supervised/in-distribution — a ceiling, not a rival.
- **Streaming vs. offline.** Rows 6, 9, 10, 11 evaluate offline/batch; Tenko's contribution is
  online per-packet operation, so cite them for method/accuracy context, not latency.

---

## Corrections vs. earlier repo working notes (so the citation is exactly right)

- **Sukanya & Raja 2025** → verified authors **N. S. Sukanya and S. Daniel Madan Raja**, title
  *"An Unsupervised Approach for Detection of Encrypted IoT Anomalies Using Variational
  Autoencoder and Isolation Forest Techniques,"* **ICTACT Journal on Communication Technology**,
  Vol. 16, Iss. 3, 2025 (DOI 10.21917/ijct.2025.0546). Numbers (F1 0.55, AUC 0.8947) confirmed.
- **Ramkumar et al. 2025** → verified full title *"Diagnosing Unknown Attacks in Smart Homes
  Using Abductive Reasoning,"* **IEEE Trans. Software Engineering** 51(11):3117-3137, Nov 2025
  (DOI 10.1109/TSE.2025.3610540; arXiv 2412.10738). iForest + ASP abduction, CICIoT2023 + IoT-23.
- **VAE-ESDD** → verified as **VAE++ESDD**, Li, Malialis, Panayiotou, Polycarpou,
  **Neurocomputing** 2026, DOI 10.1016/j.neucom.2026.133061 (arXiv 2602.12976); code
  `github.com/Jin000001/VAEESDD`.
- **AdaptiveAE-IDS (2026, IJIES)** and **IMME (2026, IEEE QPAIN)** → both **confirmed real** with
  DOIs above (they were candidates for fabrication but check out).

## Source key
- Tenko/baseline runs: `results/CICIoT2023/baselines/comparison_metrics_with_iforest.csv`,
  `baselines/table_ix_mixed_with_iforest.csv`, `baselines/README.md`,
  `mixed/ciciot2023_calibrated_operating_point_metrics.csv`,
  `ciciot2023_per_class_metrics.csv`, `ciciot2023_source_level_metrics.csv`.
- Prior positioning docs: `results/CICIoT2023/cic_baselines_comparison.md`,
  `baseline_comparison_ullah2025.md`.
- All external papers verified via web search (DOIs listed inline).
