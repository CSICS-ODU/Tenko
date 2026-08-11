# Novelty of Tenko beyond Kitsune — point-wise innovation table

**Purpose.** Answer Assoc. Editor E1 and Reviewer R1.1 ("what is the fundamental novelty
beyond Kitsune post-processing?") with a *mechanism-by-mechanism* comparison in which every
Tenko-only row points to the committed code that implements it. This document is evidence for
the `REVIEWER_RESPONSE.md` novelty answers.

**One-line thesis.** Kitsune (KitNET) is used **only as the per-packet feature/error backbone
(X1)**. Tenko's contribution is the four layers *on top of* X1 — per-source **node scoring
(X2)**, a **benign-calibrated tolerance layer (X3)**, and a **weighted decision fusion (X4)** —
which convert Kitsune's stateless per-packet reconstruction error into a *stateful, per-device,
context-aware* anomaly decision. These are separate code paths from KitNET, not a re-weighting
of Kitsune's output.

> **Honesty guardrail (from `AUDIT_REPORT.md §3b`).** Tenko is a *context-aware scoring layer
> over a KitNET backbone*, **not** a new detector core. We do not claim a novel autoencoder; we
> claim a novel per-source stateful scoring/decision layer and its benign-only calibration. On
> CICIoT2023 this layer is *competitive, not dominant* at packet level and *clearly wins at
> device (per-source) granularity* — see `results/CICIoT2023/manuscript_drafts.md` D.2 and
> `ciciot2023_source_level_metrics.csv`.

---

## 1. The point-wise table (Kitsune baseline → Tenko addition → code)

| # | Capability | Kitsune / KitNET (X1) baseline | Tenko addition | What it buys | Implementing code (committed) |
|---|---|---|---|---|---|
| 1 | **Per-packet anomaly signal** | KitNET autoencoder ensemble RMSE over AfterImage features; `s = tanh(RMSE)`. This is the *entire* Kitsune detector. | Reused **unchanged** as the X1 backbone (same AfterImage features, same `maxAE=10`, `FMgrace=5000`, `ADgrace=50000`). Tenko does **not** modify KitNET. | Keeps the strong per-packet detector as a feature; all novelty is layered above it. | `KitNET/`, `AfterImage.py`, `netStat.py`; squash `example.py:157` (`rmse = np.tanh(rmse)`). |
| 2 | **Per-source (node) state — X2** | **None.** KitNET is stateless per packet and has no notion of *which host* a packet came from; source IP is never used. | **Node scoring**: a decaying numerator/denominator anomaly accumulator **keyed on per-packet source IP**, updated in constant time per packet: `S(n) = num/den`, `num += s`, `den += 1`, with history decay. | Turns a per-packet score into a per-*device* behavioural trust estimate — the quantity an IoT gateway actually needs ("which device do I quarantine?"). | `tracker.py` — `scoreClass.update_anamoly/update_benign` (`tracker.py:27-42`), decay (`:53-69`), `nodeScore.update` keyed on `nodeId` (`tracker.py:114-144`); wired in `results.py:915-917`. Node key = src IP parsed from TSV col 4/17 (`results.py:748-749`). |
| 3 | **Temporal pattern representation** | Single scalar error per packet; no windowed pattern. | **Segmented pattern vector**: a sliding window of node scores (`pattern_window_size=100`) reduced to `pattern_segments=10` segment means — a low-dim temporal signature per recognizer. | Captures *sustained* behavioural deviation across packets, not just single-packet spikes — exactly the regime (MITM, Mirai) where Tenko beats Kitsune. | `RMSEPatternRecognizerDist._current_vector` (`results.py:717-725`); window `deque(maxlen=window_size)` (`results.py:682`). |
| 4 | **Benign-only tolerance envelope — X3** | Kitsune's operating threshold in the paper is a benign Median+MAD cut on the raw score; no per-cluster geometry. | **Tolerance layer**: for each recognizer, benign centroid `c = mean(training vectors)` and tolerance `tol = max‖v−c‖ × η` from **benign traffic only**. A packet is "unknown" iff `‖v−c‖ > tol`. Two recognizers: **global pooled** (η_global=50) and **single-aggregate** (η_node=20). | A per-deployment, label-free anomaly boundary shaped by the *geometry* of benign behaviour, with a single interpretable scale knob η per level. | `finalize_training` centroid+tol (`results.py:696-706`); `is_known` test (`results.py:708-715`); factors `global_pool_tol_factor=50`, `single_agg_tol_factor=20` (`results.py:776-777`). |
| 5 | **η = benign-quantile scale (not a label-tuned operating point)** | Threshold implicitly tuned to a target FPR (paper notes Kitsune's oracle "fixes FPR=0.001", requiring attack knowledge). | η multiplies the **max benign intra-cluster distance**; benign spread `= tol/η` (`benign_spread_g`, `benign_spread_s`). **No attack labels** are used to set η. On CICIoT2023 η is re-derived from benign score **percentiles** to a target benign FPR — still label-free. | Directly answers R4: η is a per-deployment benign-calibrated multiplier tied to benign-score distribution percentiles, not an attack-tuned knob. | `global_base = global_tol/η_global`, `single_base = single_tol/η_node` (`results.py:892-893`); benign-quantile recalibration `recalibrate_ciciot2023.py:72-92,131-151`. |
| 6 | **Two-recognizer decision fusion — X4** | Single detector, single score. | **Weighted ensemble** of the global-pooled flag and single-aggregate flag: `combined = w_g·flag_g + w_s·flag_s` (w=0.5/0.5), decision `1 if combined ≥ τ` (τ=0.5). Effectively an **OR at τ=0.5**: fire if *either* population-level or node-level pattern is out-of-envelope. | Population context catches coordinated/multi-source attacks; node context catches per-device sustained deviation; fusion covers both without labels. | Fusion `results.py:940-943`; weights/threshold `results.py:779-781`. |
| 7 | **Threshold-independent continuous score** | `tanh(RMSE)` is already continuous (ROC over it). | **η-normalized fused pattern distance** `nd = w_g·nd_g + w_s·nd_s`, where `nd_g = ‖v_g−c_g‖/benign_spread_g`, `nd_s = ‖v_s−c_s‖/benign_spread_s`. Additive returns `nd_g_list`/`nd_s_list` expose it for offline AUC/EER and η re-search **without re-running X1/X2**. | Lets us report the honest, transfer-safe headline (AUC/EER) independent of the operating point — the CICIoT2023 headline metric. | Continuous score `results.py:945-959`; additive `return_scores`/`benignLimit` params `results.py:782-789`. |
| 8 | **State persistence / attribution substrate** | None. | Optional per-node history backup/lookup (numerator/denominator per node) behind an offline/blocking/parallel mode switch; node identity is retained end-to-end for per-device attribution. | Enables per-device evaluation and quarantine decisions (the source-level win, `manuscript_drafts.md` D.2). | `nodeScore.backup_to_blockchain/lookup_from_blockchain` (`tracker.py:193-244`); `merge_history` (`tracker.py:44-51`). |

**Symbol map (for the reviewer).** η_global = `global_pool_tol_factor` (default 50);
η_node = `single_agg_tol_factor` (default 20); fusion weights `weight_global=weight_single=0.5`;
`ensemble_threshold τ=0.5`; `pattern_window_size=100`, `pattern_segments=10`; KitNET grace
`FMgrace=5000`, `ADgrace=50000`. All in the signature of
`get_adversarial_IPs_weighted_pattern()` (`results.py:766-785`).

---

## 2. Why this is *not* "just Kitsune post-processing" (the R1.1 rebuttal core)

1. **Different state model.** Kitsune/KitNET is memoryless per packet; rows 2–3 add
   **per-source-IP state** (`tracker.nodeScore`) that Kitsune has no representation for. A
   re-weighting or re-thresholding of Kitsune's output cannot recover per-device behaviour,
   because Kitsune's output does not carry node identity. Tenko's decision at packet *i*
   depends on the *history of packets from the same source*, not just packet *i*.
2. **Different decision geometry.** Kitsune thresholds a scalar; Tenko thresholds a **distance
   in a segmented-pattern vector space** against a benign centroid (rows 3–4). This is a
   distinct decision surface, implemented in separate classes
   (`RMSEPatternRecognizerDist`, `results.py:670-725`).
3. **Different calibration philosophy (row 5).** Kitsune's headline operating point in the
   paper uses an oracle FPR that "assumes prior knowledge of attack characteristics and is
   infeasible in streaming"; Tenko's η is a **benign-only** multiplier fixed before test-time
   with no attack labels (`AUDIT_REPORT.md §3c`; `manuscript_drafts.md` A.3).
4. **Empirical separation of the mechanism (faithfulness check).** Scoring devices by the raw
   node score `S(n)` alone does **not** win (per-device ROC-AUC 0.743 < Kitsune 0.759); the
   win appears only through the **tolerance-layer** distance `nd` (`arr_cont`), rising to 0.876
   (`manuscript_drafts.md` D.4; `source_level_faithfulness.md`). So the gain is specifically a
   property of the X3/X4 layers, not an artifact of aggregation.

---

## 3. Where the addition demonstrably changes the outcome (evidence, both directions)

| Regime | Kitsune (X1 only) | Tenko (X1+X2+X3+X4) | Source |
|---|---|---|---|
| Packet-level AUC, mean of 6 CICIoT2023 attacks | 0.893 | 0.883 (competitive, not dominant) | `ciciot2023_per_class_metrics.csv` |
| Packet-level AUC, **MITM-ARP** (sustained deviation) | 0.942 | **0.949** (Tenko wins) | `ciciot2023_per_class_metrics.csv:14,15` |
| Packet-level AUC, **Mirai-greeth** | 0.929 | **0.937** (Tenko wins) | `ciciot2023_per_class_metrics.csv:18,19` |
| **Source/device-level** ROC-AUC, mean of 6 | 0.759 | **0.876** (+0.118; wins 5/6, ties 1) | `ciciot2023_source_level_metrics.csv`; `manuscript_drafts.md` D.2 |
| Diffuse low-rate (Recon/Dict) device-level | 0.568 / 0.602 (near-chance) | **0.712 / 0.774** | `manuscript_drafts.md` D.2 |
| Mixed-stream binary, TPR@2%FPR (orrule) | 0.9637 / FPR 0.1971 | **0.9801 / FPR 0.0200**, AUC 0.9897 | `baselines/table_ix_mixed_with_iforest.csv`; `mixed/_calibrated_operating_point.py` |

**Honest framing.** The added layers help most where per-packet reconstruction has *headroom*
(sustained-deviation and diffuse attacks, and at device granularity) and are near-parity where
per-packet Kitsune is already near-ceiling (volumetric floods). This is exactly what a
context-aware layer *should* do, and we report it as such rather than as a uniform win
(`cic_config_audit.md`).

---

## Source key

- Core code: `results.py` (`get_adversarial_IPs_weighted_pattern`, `RMSEPatternRecognizerDist`),
  `tracker.py` (`scoreClass`, `nodeScore`), `example.py` (X1 squash), `KitNET/`, `AfterImage.py`,
  `netStat.py`, `FeatureExtractor.py`.
- Metrics: `results/CICIoT2023/ciciot2023_per_class_metrics.csv`,
  `ciciot2023_source_level_metrics.csv`,
  `baselines/table_ix_mixed_with_iforest.csv`,
  `mixed/ciciot2023_calibrated_operating_point_metrics.csv`.
- Provenance/discussion: `AUDIT_REPORT.md §3b–3c`, `REPRODUCIBILITY.md §7`,
  `results/CICIoT2023/manuscript_drafts.md` (D.2/D.4), `source_level_faithfulness.md`,
  `cic_config_audit.md`.
