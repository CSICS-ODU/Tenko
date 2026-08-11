# Tenko — R1 → R2 Revision Roadmap & Agent Work Plan

**Manuscript:** TCE-2026-04-1823.R1 — "Tenko: A Real-Time / Streaming Intrusion Detection Framework with Context-Aware Anomaly Scoring"
**Target venue:** IEEE Transactions on Consumer Electronics (TCE)
**Revision deadline:** 11-Aug-2026
**Branch of record:** `correct-latency` (latest real dev work; contains `measure_all_latency.py` real X1–X4 timing)
**Status:** Editor invited **minor revision**; two reviewers effectively accept (R2, R4); R1/R3/R5 raise addressable points.

> This file is the single source of truth for the R2 revision. It is written so background agents can pick up a numbered task, execute against **real file paths**, and hand back a verifiable artifact. **Do not fabricate metrics.** Every number in the manuscript must trace to an execution log or CSV committed to the repo.

### Locked decisions (2026-08-03)
1. **Headline recent dataset = CICIoT2023** (PCAP subset). Confirmed.
2. **Baselines:** reimplement/run **Adaptive NAD** (public code) for a real head-to-head on CICIoT2023; position AdaptiveAE-IDS / IMME from literature with an explicit "not reimplemented" note.
3. **Title/claim:** retitle to **"Streaming"** and qualify every "real-time" as "real-time-capable under sequential PCAP replay." No live packet-drop experiment required (E3/R1.3 answered by scoping).
4. **N-BaIoT / per-attack Kitsune code:** forensic search complete → **N-BaIoT Table V code + data are NOT in this repo/history** (never committed).
5. **N-BaIoT handling:** the **user will retrieve the external workspace/machine** that produced Table V and add the code + raw CSVs to the repo. No agent regeneration for now. (If retrieval fails, fall back to Task R7-A "regenerate.")
6. **Per-attack driver loop:** **DEFERRED until after the CICIoT2023 run.** For now, per-attack numbers remain the hard-coded literals in `resultsNew.py` on `Daksh-Mateen`; the committed nine-attack driver + AUC/EER regeneration is a later task.

---

## 0. Ground-truth findings that shape everything below

1. **The "IDS 2025" folder is CIC-IDS2018.** `~/Desktop/archive (1)` = CSE-CIC-IDS2018 flow CSVs (files literally named `*-2018.csv`), 80 CICFlowMeter features + `Label`, **no Source IP column**. It does **not** satisfy the reviewers' "recent traces" request and is **not** compatible with Tenko's packet pipeline (see §2). Do not present it as a 2025 dataset.
2. **Full Tenko (X1–X4 with node scoring) only runs on the PCAP path** via `workflow.py` → `example.py` (X1) + `results.py` (X2–X4). Node identity = **source IP** parsed from the TSV (`FeatureExtractor.py` cols 4/5 IPv4, 17/18 IPv6; MAC fallback). The CSV loaders (`task_1_loader.py`, `disNet_Loader.py`, `task_5*_loader.py`) are **KitNET-only, no node aggregation** — they cannot exercise Tenko's contribution.
3. **N-BaIoT code is NOT in this branch.** No loader, no preprocessing, no per-device metric routine. The manuscript's Hermes-vs-Tenko N-BaIoT table (Table V) and the per-attack Kitsune tables are **not reproducible from `correct-latency`**. Locate the branch/scripts that generated them, or they cannot be defended for Reviewer #7. **(Blocking risk — see Task R7-A.)**
4. **`results.py` computes a single binary label** (`gold = LABELS[benignLimit:]`), so **per-attack-class tables are not implemented**. Producing a CICIoT2023 per-class table (like the N-BaIoT per-device table) requires adding a per-class evaluation loop (Task D-3).
5. **Recent, Tenko-compatible dataset = CICIoT2023** (raw PCAP + source IP + real consumer IoT + benign + 7 attack classes). This is *literally* the dataset the reviewer meant by "CIC IDS 2023." Must be ingested from **PCAP**, because the popular CICIoT2023 **CSVs drop per-record source IP** and would collapse node aggregation.

---

## 1. Reviewer comment → work-item traceability matrix

Legend: **[EXP]** experiment, **[WRITE]** manuscript text, **[AUDIT]** verification, **[SUPP]** supplementary.

| # | Source | Comment (short) | Work item(s) | Type | Owner task |
|---|--------|-----------------|--------------|------|-----------|
| E1 | Editor | Point-wise novelty comparison | Sharpen §I-A novelty table; cite Tenko++ precursor | WRITE | Task N-1 |
| E2 | Editor | Compare ≥2 unsupervised streaming IDS from 2025–2026 | Add Adaptive NAD, AdaptiveAE-IDS (+IMME) | WRITE/EXP | Task B-1, B-2 |
| E3 | Editor | Real-time claim needs full HW specs + packet drop, else soften | Either measure live capture drop-rate OR soften to "replay-capable" everywhere | AUDIT/WRITE | Task RT-1 |
| R1.1 | Rev 1 | Fundamental novelty vs Kitsune post-processing | Novelty table + fusion-drives-gains argument | WRITE | Task N-1 |
| R1.2 | Rev 1 | Justify 8-yr-old datasets; run recent (CIC IDS 2023) | **Run CICIoT2023** (headline) | EXP | Task D-1..D-4 |
| R1.3 | Rev 1 | Live gateway? full env specs / drop rate | Same as E3 | AUDIT/WRITE | Task RT-1 |
| R1.4 | Rev 1 | Table comparing ≥8 recent systems | Extend Table II to ≥8 rows w/ resource footprint | WRITE | Task N-2 |
| R1.5 | Rev 1 | Unified pseudocode (IV-G) + runnable source | Alg. already added; verify + release code archive | WRITE/SUPP | Task R7-B |
| R1.6 | Rev 1 | Compare ≥2 unsupervised streaming IDS 2025–2026 | Same as E2 | WRITE/EXP | Task B-1, B-2 |
| R1.7 | Rev 1 | Were Figs 5/6/7 from logs or curated? Provide CSV/scripts | Export raw CSV + plotting scripts to supp | SUPP | Task R7-C |
| R1.8 | Rev 1 | Hyperparam selection, seed robustness, CE applicability | Supp Table III + seed note + CE paragraph | WRITE/SUPP | Task H-1 |
| R2 | Rev 2 | Accept | — | — | — |
| R3.1 | Rev 3 | Clarify network parameters | Table (network/model/eval params) — verify present | WRITE | Task H-2 |
| R3.2 | Rev 3 | Motivate old datasets (up to 2024) | Recency justification + CICIoT2023 run | WRITE/EXP | Task D-1, N-3 |
| R4 | Rev 4 | Minor: intuition for η_global, η_node | Expand η intuition tied to benign spread | WRITE | Task H-3 |
| R5.1 | Rev 5 | Deepen t-SNE analysis (drift, separability) | Rewrite t-SNE discussion; tie to per-class FPR | WRITE | Task T-1 |
| R5.2 | Rev 5 | Shorten overly long sentences | Readability pass | WRITE | Task W-1 |

---

## 2. Dataset decision (needs user confirm before heavy download)

**Primary (headline):** **CICIoT2023** — https://www.unb.ca/cic/datasets/iotdataset-2023.html
- Use the **`PCAP/` directory**, NOT the CSVs (CSVs drop per-record source IP → node aggregation collapses).
- 105 real IoT devices, benign + 33 attacks / 7 classes (DDoS, DoS, Recon, Web, Brute Force, Spoofing, Mirai). ~13 GB+.

**Secondary (recent, packet-level, IoT/edge):** **Edge-IIoTset (2022)** — http://ieee-dataport.org/8939 (per-attack PCAPs + benign; has src IP). Recency alt: **5G-NIDD (2023)** — https://netslab.ucd.ie/5g-nidd/ (pcapng; 5G/MEC framing).

**Do NOT use as "recent":** IoT-23 (2018–19), TON_IoT (2019–20). **Reject:** CICIoV2024 (CAN bus, no IP), NF-* NetFlow v2/v3 & BCCC-CIC reissues (CSV-only, repackaged 2015–2018 traffic).

**Rebuttal note to write (R1.2/R3.2):** state explicitly that "CIC IDS 2023" = **CICIoT2023** (there is no separate CIC-IDS2023), so the reviewer sees the request was met, not dodged.

---

## 3. HEADLINE TASK — Run Tenko on CICIoT2023 (PCAP)

> Goal: produce a per-attack-class results table for Tenko (and a Kitsune baseline) on a genuinely recent dataset, plus raw CSVs/plots for Reviewer #7, plus latency/memory on the same trace.

### Task D-1 — Acquire & stage data  ⚠️ USER-ACTION BLOCKER
Runbook produced by the acquisition worker; skeleton + scripts already created.
> **2026-08-03 note:** user first downloaded the CICIoT2023 **CSV package** (`~/Desktop/cic/CSV/`, `MERGED_CSV/`). Verified those CSVs are **39 aggregate features + Label with NO source IP / flow-id / timestamp** → full Tenko node aggregation is impossible on them (not even a pseudo-node). Decision: fetch the **raw PCAP pilot** instead (below). The CSVs may optionally serve a KitNET-only AE baseline, but do not exercise Tenko's contribution.
- **Raw PCAP corpus is ~548 GB** (only the CSVs are ~13 GB), split into ~10 MB `tcpdump` chunks per capture session. **Do NOT pull whole classes** (DDoS/DoS are multi-GB). Pilot = first-N chunks per class ≈ **100–150 MB total**.
- **BLOCKER 1 (user, one-time):** the CIC file server (`cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/`) returns an identical registration-form page for every path until you submit the short form in a browser (name/email/org/country — no password). Start at https://www.unb.ca/cic/datasets/iotdataset-2023.html → red **Download** button. This cannot and should not be scripted around.
- **BLOCKER 2 (env):** `tshark`, `mergecap`, `wget` (and `kaggle`) are NOT installed on this machine. Install Wireshark: `brew install wireshark` (provides tshark + mergecap).
- **Labels are file/folder-level** (class == capture session). There is **no attacker-IP or time-window mapping file**. Binary label = `0` if under `BenignTraffic/`, else `1`; per-class label = folder name. `scripts/build_ciciot2023_pilot.sh` emits `CICIoT2023_pilot.labels.csv` (`idx,binary,class`) aligned to packet order via `mergecap` (benign-first).
- Pilot file set (≥100k benign lead-in + 6 attack classes): 5 chunks `BenignTraffic/`, 1 chunk each of `DDoS-UDP_Flood/`, `DoS-SYN_Flood/`, `Recon-OSScan/`, `MITM-ArpSpoofing/`, `Mirai-greeth_flood/`, `DictionaryBruteForce/`.
- Staging: `dataset/CICIoT2023/raw/<Class>/` (created) mirroring `dataset/Mirai/` used by `measure_all_latency.py:59`.
- **Acceptance:** pilot PCAP chunks on disk; `wc -l` on the TSV confirms benign lead-in ≥ `benignLimit`; a `README` noting exact chunk filenames + `capinfos` counts.

### Task D-1.5 — tshark field order (verified)
`scripts/pcap2tsv_tenko.sh` emits the exact fields `FeatureExtractor.pcap2tsv_with_tshark()` expects (`FeatureExtractor.py:347`); TSV **src IP = col 4 (IPv4) / col 17 (IPv6)** confirmed against `FeatureExtractor.py:233-240`. Note: `FE` also has a **dpkt fast path** that reads `.pcap` directly (no tshark) for the FE-latency pass.

### Task D-2 — PCAP → TSV + aligned label CSV
- Convert each PCAP to the tshark TSV format `FeatureExtractor.py` expects (it auto-runs tshark in `FE.__prep__`; confirm the field order matches cols used for src IP: 4/5 IPv4, 17/18 IPv6).
- Build a **binary label CSV aligned 1:1 with packets** (0 benign / 1 attack) using CICIoT2023 ground truth (attacker/victim IPs + time windows). Also emit a **per-packet attack-class label** (0=benign, 1..K=class) for the per-class table in D-3.
- Respect the Kitsune protocol: **≥ the benign calibration window of benign packets must precede any attack packet** in stream order. If a single capture lacks enough benign lead-in, concatenate benign captures first.
- **Acceptance:** `CICIoT2023.tsv`, `CICIoT2023_labels.csv` (binary), `CICIoT2023_labels_multiclass.csv`; a sanity script prints class counts and confirms benign-lead-in length ≥ `benignLimit`.

### Task D-3 — Add per-attack-class evaluation (code change)
- `results.py` currently evaluates one binary label (`results.py:882`, `evaluate_and_print` `results.py:953-963`). Add a loop that, given the multiclass label vector, computes TPR/FPR/Precision/F1 **per attack class** (benign as negatives, one attack class as positives at a time) plus overall AUC/EER.
- Retune the hardcoded windows for the CICIoT2023 stream length: `FMgrace=5000`, `ADgrace=50000`, `benignLimit=100000`, test-start index `100000` (`results.py:793-794`, `:882`). If the benign lead-in differs, set these consistently and record the exact values used.
- Keep `tanh(RMSE)` normalization (`results.py:809`) and default fusion weights 0.5/0.5, threshold 0.5 (`results.py:779-781`).
- **Acceptance:** running the pipeline emits a per-class metrics CSV + overall AUC/EER, with the constants used printed to the log.

### Task D-4 — Execute Tenko + Kitsune baseline
- Tenko full stack:
  ```bash
  python workflow.py -i dataset/CICIoT2023/CICIoT2023.pcap \
      -ip dataset/CICIoT2023/CICIoT2023.tsv \
      -l  dataset/CICIoT2023/CICIoT2023_labels.csv -o
  ```
  (or reuse cached RMSE with `-r RMSEs.pkl`). Then run the per-class eval (D-3).
- Kitsune baseline on the same stream (raw per-packet RMSE + benign-derived threshold, e.g. Median+MAD as in Table II) for a fair same-regime comparison.
- **Acceptance:** committed logs + CSVs under `results/CICIoT2023/`; numbers flow into the Table template in §4. **No hand-editing of numbers.**

---

## 4. Results table template (fill from D-4 output — DO NOT invent values)

**Table X (new): Tenko vs Kitsune on CICIoT2023 (benign-only training, per attack class).**

| Attack class | TPR (Kitsune) | TPR (Tenko) | FPR (Kitsune) | FPR (Tenko) | Precision (Tenko) | F1 (Tenko) |
|--------------|:---:|:---:|:---:|:---:|:---:|:---:|
| DDoS         | TBD | TBD | TBD | TBD | TBD | TBD |
| DoS          | TBD | TBD | TBD | TBD | TBD | TBD |
| Recon        | TBD | TBD | TBD | TBD | TBD | TBD |
| Spoofing     | TBD | TBD | TBD | TBD | TBD | TBD |
| Web          | TBD | TBD | TBD | TBD | TBD | TBD |
| Brute Force  | TBD | TBD | TBD | TBD | TBD | TBD |
| Mirai        | TBD | TBD | TBD | TBD | TBD | TBD |

**Table Y (new): Threshold-independent discrimination on CICIoT2023.**

| Attack class | AUC (Kitsune) | AUC (Tenko) | EER (Kitsune) | EER (Tenko) |
|--------------|:---:|:---:|:---:|:---:|
| (per class)  | TBD | TBD | TBD | TBD |

**Rule:** every filled cell must be traceable to a row in `results/CICIoT2023/*.csv`. Re-verify F1 from Precision & Recall for each row before pasting into LaTeX (see §6).

### Pilot run findings (2026-08-03) — results/CICIoT2023/
Streams: 150k benign_lead + 30k benign_test (in-distribution held-out) + 50k attack = 230k pkts each; benignLimit=150000; 0 packet drops; alignment/determinism verified.
- **Kitsune (tanh(RMSE)+Median/MAD):** AUC 0.70–0.99, constant FPR≈0.323. Per-attack: DDoS-UDP 0.965, DoS-SYN 0.993, Recon-OSScan 0.827, MITM-ArpSpoofing 0.942, Mirai-greeth 0.929, DictionaryBruteForce 0.703.
- **Tenko @ committed η (50/20), fusion 0.5/0.5, T=0.5: DEGENERATE — flags nothing (TPR=FPR=0) on all 6 classes.** Pooled tolerance (~2.63) > max attack-window distance (~2.4) after the committed **double-`tanh`**. Not a harness bug; the committed constants simply don't transfer to CICIoT2023's benign spread.
- **Tenko threshold-independent (η-normalized pattern distance):** competitive; **node aggregation beats Kitsune on MITM-ArpSpoofing (AUC 0.949 vs 0.942, EER 0.131 vs 0.147) and Mirai-greeth_flood (0.937 vs 0.929, EER 0.140 vs 0.153)**; ties/slightly trails on pure floods (DDoS/DoS/Recon).
- **Latent issue flagged:** double-`tanh` (`example.py` stores tanh(raw) + `results.py:809` re-applies tanh) saturates scores into [0, 0.762]; may also affect main-paper Mirai numbers. **Under investigation.**
- Code: additive `return_scores`/`benignLimit` params in `results.py` + new `run_ciciot2023.py` driver + `scripts/build_streams_ciciot2023.sh`. Nothing committed. Fresh `.venv314` built (repo `.venv` was broken).

### Decisions (2026-08-03, second pass)
- **η handling:** recalibrate η on CICIoT2023 **benign-only** data (no attack labels) → report as Tenko's operating point; keep threshold-independent AUC/EER; document committed-default degeneracy in supplement as evidence η is a benign-calibrated per-deployment multiplier (answers Reviewer #4).
- **double-`tanh`:** investigate whether intended, whether main-paper Mirai path is affected, quantify single-vs-double impact, before any fix. Do NOT change main-paper numbers unilaterally.

### Recalibration + double-`tanh` results (2026-08-03)
**η recalibration (benign-only):** the culprit was **η_node** — committed 20, needed ~2.85 (η_global 50→~41). Benign-calibrated Tenko is no longer degenerate:

| Attack | Tenko TPR @FPR5% | F1 @FPR5% | AUC |
|---|---|---|---|
| DoS-SYN_Flood | 0.963 | 0.966 | 0.988 |
| MITM-ArpSpoofing | 0.824 | 0.889 | 0.949 |
| DDoS-UDP_Flood | 0.783 | 0.864 | 0.929 |
| Mirai-greeth_flood | 0.712 | 0.817 | 0.937 |
| Recon-OSScan | 0.115 | 0.200 | 0.796 |
| DictionaryBruteForce | 0.031 | 0.058 | 0.697 |

Recon/BruteForce stay weak (low AUC → genuinely poor separability, not a threshold issue). η values: 40.70/2.85 @1% FPR, 35.83/2.21 @5%. Files: `ciciot2023_metrics_recalibrated.csv`, `ciciot2023_per_class_metrics.csv` (4 row-groups).
- **⚠️ Integrity caveat:** η was fit on `benign_test` and FPR measured on the same slice → in-sample FPR is *definitional*. TPR/Precision/F1 on attacks are the real generalization numbers. **Fully out-of-sample recalibration pending** (split benign into calibrate/eval).

**double-`tanh` = confirmed latent BUG (not intended).**
- First tanh `example.py:157` (Soumya, 2025-01-17) — **necessary** (node scoring needs [0,1], `tracker.py:28`).
- Second tanh `results.py:805` (Daksh, **2026-03-23**), commented "Normalization" as if it receives raw RMSE — **redundant**; composes to `tanh(tanh(raw))`, squashing scores into [0, 0.762].
- **Impact on CICIoT2023:** AUC barely changes (single-tanh +0.002..+0.011, marginally better); but operating point is materially affected — under **single-tanh the committed η=50/20 becomes non-degenerate for 4/6 attacks** (DoS-SYN TPR 0.72). Files: `ciciot2023_tanh_impact.csv`, `ciciot2023_committedEta_{double,single}.csv`.
- **Main-paper exposure:** `dataset/Mirai/` is empty (can't quantify), but the Mirai path `workflow.py→example.py→results.py` routes through the SAME double-tanh, so any number from that path is affected. Second tanh added **2026-03-23** → provenance question: were the paper's Mirai/per-attack numbers generated before or after that date? (Per-attack literals live on `Daksh-Mateen`.) **Do NOT silently change main-paper numbers — coordinate with co-authors.**
- **Recommendation:** remove the redundant `results.py:805` tanh for new runs + always benign-calibrate η per dataset; document, regenerate affected tables deliberately.

**DECISIONS (2026-08-03, user):**
1. **CICIoT2023 authoritative pipeline = SINGLE-tanh** (redundant second tanh removed). Report the new dataset under the fixed normalization with benign-calibrated η.
2. **Main paper (Mirai/per-attack) = COORDINATE FIRST.** Do NOT touch any published number. Wait for the provenance verdict (were paper numbers generated before/after the 2026-03-23 second-tanh commit?), then coordinate with co-authors (Daksh/Soumya). If paper numbers predate the bug, main tables stand and only new runs use the fix.
3. **Mirai data:** not in scope now (`dataset/Mirai` empty) — focus is CICIoT2023.
4. **Pending (agent):** fully out-of-sample η recalibration → `ciciot2023_metrics_recalibrated_oos.csv` (report single-tanh variant); provenance timeline for main-paper numbers.

### OOS + provenance results (2026-08-03, agent 87fa6e77)
**OOS η (load-bearing finding):** a fixed benign-calibrated η is **NOT FPR-calibratable out-of-sample** on the CICIoT2023 benign trace — it's non-stationary (warm-up transient). Held-out benign FPR:

| target | calib=1st→eval=2nd | calib=2nd→eval=1st |
|---|---|---|
| 1% | ~0.0% | ~30.4% |
| 5% | ~0.0% | ~31.9% |

⇒ the in-sample 1%/5% FPR was **definitional, not predictive**. **AUC/EER are stable & honest** and are the numbers to report: DoS-SYN 0.994/0.024, MITM 0.985/0.065, DDoS 0.958/0.074, Mirai 0.980/0.071, Recon 0.884/0.137, Dict 0.805/0.200. single-tanh ≈ double-tanh OOS (±0.02 TPR) → **tanh choice is numerically irrelevant on this data**. File: `results/CICIoT2023/ciciot2023_metrics_recalibrated_oos.csv`.

**Provenance verdict = main-paper numbers carry the double-tanh.** `resultsNew.py` literals committed **2025-05-10** (`0089fa6`) & 2025-10-25 (`f097886`) on `Daksh-Mateen`; at 2025-05-10 BOTH tanhs were already live (`example.py:142`, `results.py:797`). The 2026-03-23 blame (`61e8be7`) only reorganized code — it did NOT introduce the second tanh. Pickaxe confirms the second tanh existed from the commit that introduced the numbers file. No RMSE `.pkl`/detection artifact tracked to pin generation date independently. ⇒ **published numbers reproduce from the committed double-tanh pipeline** (not fabricated, not new-runs-only).

**Implication for decisions:** since paper=double-tanh AND single≈double numerically, reporting CICIoT2023 under single-tanh would create a needless pipeline inconsistency across tables. Reconsider: report CICIoT2023 as AUC/EER (honest headline) + clearly-labeled in-sample operating point, under the SAME committed pipeline as the paper. **Next: audit manuscript's stated normalization + FPR/operating-point claims before finalizing.**

### Manuscript audit (2026-08-03, agent 87fa6e77)
**⚠️ Manuscript source is NOT on this machine** — no `.tex`/`.docx` on disk or in git (only a git-only DEV LOG `ShazamDoc.docx`@`f097886` 2025-10-25, which embeds a ChatGPT transcript + metric dumps, NOT the paper). Submitted paper = **TCE-2026-04-1823.R1**. **BUT the Overleaf LaTeX was pasted by the user into the parent chat transcript** → recoverable there; extraction delegated.
Verdicts (from dev log + roadmap, pending confirmation vs real manuscript text):
1. **Normalization mismatch: LIKELY YES.** Every authored artifact treats normalization as applied once ("single tanh") or "no tanh"; committed code does `tanh(tanh(raw))`. If the paper states a single squashing step, code contradicts spec → one-sentence fix.
2. **OOS vs FPR claims:** does NOT contradict the reported *in-sample* per-attack FPRs (still valid as reported), but DOES undermine any *FPR-generalization* narrative ("soft matching drastically cuts FPR"). Frame CICIoT2023 FPR as in-sample only.
3. **η/threshold calibration wording:** `tol_factor × max benign-training centroid distance`, benign-only, hand-tuned for tradeoff, **no target-FPR claim** → consistent with OOS finding (no explicit claim contradicted). Note: dev log explores tol_factor≈0.8–1.5 vs committed η=50/20 — gap driven by double-tanh squashing; reconcile in text.
4. **CICIoT2023 placement:** reviewers **R1.2 / R3.2** explicitly requested it. Add new Evaluation subsection: lead **Table Y (AUC/EER, honest headline)** + **Table X (per-class TPR/FPR, labeled in-sample)**.

### PLAN (2026-08-03)
- **Main-paper numbers: DO NOT regenerate** (reproducible from committed double-tanh; no Mirai data on disk; deadline 11-Aug). Keep as authoritative, describe pipeline accurately.
- **Normalization text:** if manuscript claims a single squash, add one clarifying sentence (describe the committed two-stage tanh as-implemented, note AUC impact ≤0.01) — no number changes.
- **CICIoT2023:** add Table Y (AUC/EER) headline + Table X (in-sample operating point, explicitly labeled) + honest FPR-non-transfer caveat. Answers R1.2/R3.2.
- **Deliverables:** paste-ready LaTeX (manuscript isn't editable locally — it's on Overleaf) + rebuttal snippet.

### Verdicts settled against REAL manuscript text (2026-08-03) — drafts in `results/CICIoT2023/manuscript_drafts.md`
Overleaf LaTeX recovered from parent transcript; verbatim quotes in the drafts file.
1. **Normalization: NO hard contradiction.** Paper never names the squash function — only asserts score ∈[0,1] and applies abstract `normalize(·)` once (Alg. tenko-pipeline). Committed `tanh(tanh(raw))` doesn't violate any written equation but is undocumented → **one-sentence methods clarification, NO number changes** (AUC delta ≤0.011). Main-paper numbers stand.
2. **FPR: NO contradiction.** Paper reports FPR as *achieved* at benign-derived thresholds, explicitly **rejects** target-FPR tuning ("infeasible in streaming"), **deletes** the "Tenko controls false alarms" claim, and already concedes "unavoidable false alarms" + drift can "inflate the FPR." OOS finding *confirms/sharpens* a conceded limitation.
3. **η: consistent.** Paper: "η … not a label-tuned operating point," "Attack labels are not used," "fixed from benign calibration before test-time." No target-FPR claim to contradict.
⇒ **Main paper is NOT contradicted by any finding.** Only additive work needed: CICIoT2023 tables + one normalization sentence + rebuttal.

**Table Y numbers (both protocols in drafts):**
- Full-trace (matches paper's existing AUC/EER table): Tenko>Kitsune on MITM (0.949 vs 0.942) & Mirai (0.937 vs 0.929); Kitsune wins DDoS/DoS-SYN/Recon/Dict. **Tenko competitive, small edge on sustained-deviation attacks — NOT dominant.**
- Held-out OOS: Kitsune stronger on floods (DDoS 0.986 vs 0.958, DoS-SYN 0.997 vs 0.994); Tenko wins MITM (0.985 vs 0.977); Mirai tie.

**DECISION (user, 2026-08-04): report BOTH** — full-trace = main-paper Table Y (`tab:ciciot2023_auc_eer`); held-out OOS = supplementary robustness table (`tab:ciciot2023_auc_eer_oos`). Drafts finalized with roles labeled + cross-refs wired in `results/CICIoT2023/manuscript_drafts.md`. **Paste-ready.**

### CIC config-vs-fundamental audit (2026-08-04, agent 87fa6e77) — `results/CICIoT2023/cic_config_audit.md`
**Verdict: competitive-not-dominant is GENUINE, mostly fundamental. Config is correct.** Tenko per-class AUC tracks `top1share` (attack-packet concentration on the busiest source IP = exactly what node aggregation needs): DoS-SYN top1=0.85→AUC0.988; MITM 0.53→0.949(+0.007); Mirai 0.43→0.937(+0.008); DDoS 0.22→0.929; Recon 0.16→0.796; Dict 0.11→0.697.
- **H1 node aggregation engaging: YES (not a bug).** Source IP parsed correctly (real IPv4, no MAC fallback, 0–5% empty ARP). Floods/botnet = rich per-node context; Recon/Dict intrinsically diffuse (230–411 sources) → fundamental.
- **H2 label contamination: REAL & FIXABLE.** Attack regions carry benign background (Recon positives even include the #1 benign host; 25–41% public/CDN on MITM/Mirai/Recon/Dict). Depresses Recon/Dict most. Fix = attacker-IP labeling → maybe several AUC points on the 2 weak classes (but also cleans baseline gold).
- **H3 benign non-stationarity: a CDN burst (AWS CloudFront dl at pkts ~155–160k), PARTLY FIXABLE.** Not warm-up. Caused the 0%/30% OOS-FPR asymmetry. Striped/random benign sampling fixes FPR-transfer; AUC gain ≤0.01.
- **H4 config deltas: NONE.** maxAE=10/FMgrace=5000/ADgrace=50000/memory=60/pattern100-10 byte-for-byte identical to `example.py`/`workflow.py`. RMSEs healthy.
- **H5 attack character: dominant cause (fundamental).** 4/6 CIC classes are volumetric floods where per-packet Kitsune is near-ceiling (no headroom); Kitsune-dataset mix left headroom → 9/9 there.
**Recommendation:** report as-is; OPTIONAL targeted robustness re-run = H2 attacker-IP relabel (Recon/Dict) + H3 striped benign sampling — won't flip to dominance (relabel helps both detectors; floods have no headroom).

---

## 5. New 2025–2026 baselines (E2 / R1.6)

Add at least two, cite + compare in Table II and the evaluation:
1. **Adaptive NAD** (2025, arXiv 2410.22967) — online unsupervised, **public code** (github.com/MyLearnCodeSpace/Adaptive-NAD), uses Edge-IIoTset. Best apples-to-apples streaming baseline.
2. **AdaptiveAE-IDS** (2026, IJIES) — benign-only sparse AE + Page-Hinkley online threshold + **CICIoT2023** + edge. Strongest conceptual rival; cite and compare directly.
3. **IMME** (2026, IEEE QPAIN) — unsupervised streaming ensemble on CICIoT2023 (third, for ensemble coverage).
- Cite w/ caveat: ReCDA (TDSC 2025, weakly-supervised), SEAD (PMLR 2025, general streaming AD).
- **Decision needed:** full reimplementation vs literature-positioning. Recommended: reimplement/obtain **Adaptive NAD** (public code) for a real head-to-head on CICIoT2023; position the others by reported results with an explicit "not reimplemented" disclosure (consistent with the Mateen framing).

---

## 6. Metric-integrity audit checklist (AUDIT — do before resubmission)

These are the exact issues flagged across prior review rounds. Lock every one down:

- [ ] **Cross-table consistency (IV vs VII vs VIII "Full History" vs XII "Ensemble").** For each attack, TPR/FPR/F1 must match across tables OR the differing protocol must be stated in the caption. Known past mismatches: OS Scan, SSDP Flood, ARP MiTM F1; Table XII Ensemble FPR ≠ Table IV FPR.
- [ ] **Recompute F1 from Precision & Recall** for every row (e.g., ARP MiTM P=0.654, R=0.953 → F1=0.776). Fix any that don't reconcile.
- [ ] **Define "memory overhead" precisely.** Per `memutil.py`, the paper's number is **`deep_sizeof` object-graph size**, not RSS. State this in the table caption; `measure_all_latency.py` also logs `psutil` RSS separately (`:367`, `:569`).
- [ ] **Mateen "on the same platform" wording.** `measure_all_latency.py` *does* have a real Mateen timing path (`mateen_reference/mateen_mirai_latency.py`); confirm whether the Table IX Mateen numbers were locally measured. If yes, say so explicitly; if reproduced from prior work, change wording to "reported by prior work, not re-measured."
- [ ] **Runtime regime reconciliation.** Older drafts showed Tenko 0.716 ms vs current 1.168 ms. State which config/platform is authoritative; delete stale numbers.
- [ ] **Naming consistency:** "SSDP Flood" vs "SSDP", "ARP MiTM" vs "ARP MITM" — unify everywhere.
- [ ] **Decision-fusion claim (Layer IV).** Soften to "conservative rule that does not uniformly dominate intermediate configurations" — matches the ablation.
- [ ] **State-persistence claim (Table VIII).** Change "consistently recovers" → "partially restores, attack-dependent."
- [ ] **Related-work claim** that adaptive methods "underperform under standard conditions" → soften to "may exhibit weaker baseline behavior under the reported stationary setting."
- [ ] **Real-time claim (E3/R1.3).** Either add live-capture packet-drop numbers, or ensure EVERY "real-time" is qualified as "streaming / real-time-capable under sequential PCAP replay." Title still says "Real-Time" — confirm this is defensible or retitle to "Streaming."
- [ ] **Fix `[?]` unresolved citation** reported in an earlier draft's related-work.

---

## 7. Reproducibility & supplementary (R1.5 / R1.7)

- **Task R7-A (BLOCKING — forensic result below):**
  - **N-BaIoT / Hermes per-device table (Table V): NOT REPRODUCIBLE from this repo.** A pickaxe search across all 16 refs + stash + full history found the strings (`gafgyt`, `Danmini`, `Ecobee`, `Hermes`, `n-baiot`, ...) were **never committed**, and no JSON/CSV artifact holds those per-device numbers. The table must have come from an external/uncommitted workspace. **Action:** the user must locate that external workspace/machine; if unrecoverable, the N-BaIoT results must be **regenerated with committed code** (new N-BaIoT loader + per-device eval), or the reliance on Table V reconsidered. This is the top Reviewer #7 risk.
  - **Per-attack Kitsune/Tenko tables: reproducible in principle, but no committed driver.** `results.py` computes TPR/FPR/AUC/EER (`results.py:975-980`) but `main()` is hard-wired to ONE attack (`results.py:1038-1039`); the nine-attack numbers were produced by manually editing paths and re-running 9×. The finished per-attack TPR/FPR/FNR/Precision matrix survives only as **hard-coded literals in `resultsNew.py` on branch `Daksh-Mateen` (lines 142-190)** — with **no AUC/EER preserved** there, and the file is absent/empty on `correct-latency`/`main`. **Action:** write a committed nine-attack driver loop that regenerates the full per-attack table (incl. AUC/EER) from `RMSEs_*.pkl` + `*_labels.csv` inputs, so the numbers are defensible and match the manuscript.
- **Task R7-B:** Prepare a clean, runnable source archive (the paper cites github.com/CSICS-ODU/Tenko). Verify the pinned commit reproduces the headline numbers; include `requirements.txt`, seed (`RANDOM_SEED=42`), and run commands.
- **Task R7-C:** For Figs 5/6/7 (Kitsune RMSE, Tenko OS-Scan, memory-constraint plot), export the underlying serialized arrays (`RMSEs.pkl`, per-packet logs) to CSV and commit the plotting scripts (`plot.py`, `visualizer.py`). State in caption that figures are generated programmatically from execution outputs.

---

## 8. Writing / minor (R4, R5, H-tasks)

- **H-1/H-3:** Expand η_global (=50), η_node (=20) intuition: η multiplies benign deviation magnitude (not a label-tuned operating point); separate factors because node vs population benign spreads differ. Point to Supp Table III (hyperparameter selection).
- **H-2 (R3.1):** Ensure the network/model/eval parameter table (features, splits, AE size, window/segments, k, damping, tolerance factors, seed, platforms) is complete and referenced.
- **T-1 (R5.1):** Deepen t-SNE discussion — tie cluster separability to per-class FPR (Mirai/SSDP separable → low FPR; Fuzzing/Active Wiretap overlap → high FPR); frame as feature-space diagnostic, not node-state trajectories; discuss what it implies about concept drift vs static overlap.
- **W-1 (R5.2):** Split overly long sentences across abstract, intro, methodology.

---

## 9. Suggested agent decomposition (parallelizable)

| Agent | Scope | Depends on | Output |
|-------|-------|-----------|--------|
| **Data agent** | D-1, D-2 (acquire + TSV/labels) | user confirms dataset | staged PCAP/TSV/labels |
| **Pipeline agent** | D-3 (per-class eval code), D-4 (run Tenko+Kitsune) | Data agent | results CSVs + logs |
| **Baseline agent** | B-1/B-2 (Adaptive NAD run or positioning) | Data agent (for CICIoT2023) | baseline metrics |
| **Audit agent** | §6 checklist across the LaTeX + tables | current manuscript | corrected tables + change log |
| **Repro agent** | R7-A/B/C (find N-BaIoT scripts, code archive, fig CSVs) | — | supp package |
| **Writing agent** | N-1/N-2, H-1/2/3, T-1, W-1 | audit + experiments | revised LaTeX sections + rebuttal answers |

**Ordering:** Data → Pipeline/Baseline (parallel) → Audit + Writing. Repro agent runs in parallel from the start (it's independent). The Audit agent must run last on any table it did not itself produce.

---

## 10. Open decisions for the user (before agents start heavy work)

1. **Confirm CICIoT2023 as the headline dataset** and that you can allocate disk/time for the PCAP subset (13 GB+). If not, fall back to Edge-IIoTset (smaller, 2022).
2. **Baselines:** reimplement Adaptive NAD (public code, real head-to-head) vs literature-position only? Recommended: reimplement at least one.
3. **Title:** keep "Real-Time" (requires packet-drop evidence per E3) or change to "Streaming"?
4. **N-BaIoT scripts:** do you know which branch/machine produced Table V and the per-attack Kitsune tables? This unblocks R7-A.
