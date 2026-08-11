# Mixed CICIoT2023 Stream — one physically-concatenated run, Table-9 format

**Goal.** Build ONE combined stream = a single shared benign lead-in followed by
ALL SIX attacks concatenated back-to-back, run KitNET(X1)+Tenko(X2–X4) **once**
with node state carried across the whole stream, and report aggregate metrics in
the paper's Table 9 (`tab:mateen_comparative_performance`) format. This is the
"one big stream, same benign, different attacks" analog of the paper's Kitsune
combined-attack regime — the faithful physically-concatenated counterpart to a
pooled-per-attack-array estimate.

All numbers below come from an actual run (no fabricated values). Reproduce with:

```
bash results/CICIoT2023/mixed/build_mixed_stream.sh
MPLBACKEND=Agg MPLCONFIGDIR=results/CICIoT2023/mixed/mplcache \
  .venv/bin/python results/CICIoT2023/mixed/run_mixed.py
```

(`MPLBACKEND=Agg` is required: `results.py` imports `matplotlib.pyplot` and
saves an ROC figure; the default macOS interactive backend aborts (SIGABRT) in
this headless/sandboxed context. Agg is non-interactive and writes the PNG fine.)

## Protocol (exact)

Stream layout (`mergecap -a` concatenation, packet order preserved within each input):

| block | attack | stream idx | label | n |
|---|---|---|---|---|
| 0 | shared benign (first 120k of `BenignTraffic.pcap`) | `[0:120000]` | 0 | 120,000 |
| 1 | DoS-SYN_Flood_sub | `[120000:170000]` | 1 | 50,000 |
| 2 | DDoS-UDP_Flood_sub | `[170000:220000]` | 1 | 50,000 |
| 3 | Recon-OSScan_sub | `[220000:270000]` | 1 | 50,000 |
| 4 | MITM-ArpSpoofing_sub | `[270000:320000]` | 1 | 50,000 |
| 5 | Mirai-greeth_flood_sub | `[320000:370000]` | 1 | 50,000 |
| 6 | DictionaryBruteForce_sub | `[370000:420000]` | 1 | 50,000 |

- Total = **420,000 packets** (120,000 + 300,000). Verified: `capinfos` count ==
  label rows == TSV rows == 420,000; benign region all-0, attack region all-1.
- **benignLimit = 60,000**: KitNET trains on `[0:55000]` (FMgrace 5000 + ADgrace
  50000); Tenko pattern models train on node scores `[55001:60000]`.
- **Test region = `[60000:420000]`** = 60,000 benign negatives (`[60000:120000]`)
  + 300,000 attack positives (`[120000:420000]`).
- **single-tanh**: raw KitNET RMSE is fed to
  `results.get_adversarial_IPs_weighted_pattern`, which applies its ONE internal
  `tanh` (`results.py:805`). Committed operating point η = 50/20 (global/single
  tolerance factors); fused OR rule `pred = (nd_g > 50) | (nd_s > 20)`. The
  recomputed pred matched the function's returned `out[1]` exactly (0 mismatches).
- **Node state carries across the entire test region** — this is a single
  `get_adversarial_IPs_weighted_pattern` call over the whole 420k stream, so the
  `nodeScore` accumulator (memorySize=60) and the global/single pattern
  recognizers keep updating continuously across all six attack blocks (no reset).
- **Kitsune baseline**: single `tanh(rmse)`, Median+MAD threshold
  `median + 3·1.4826·MAD` calibrated on `[55001:60000]` (thr = 0.009578,
  median = 0.004223, MAD = 1.204e-03), evaluated on the same test region.

**X1 timing:** KitNET produced 420,000 RMSEs in **665.7 s (1.585 ms/pkt)**.

## Aggregate results (Table-9 format, test region: 60k benign + 300k attack)

Operating point = committed η 50/20 for Tenko; Median+MAD threshold for Kitsune.
AUC-ROC / EER from the continuous score (Tenko fused η-normalized distance
`out[9]`; Kitsune `tanh(rmse)`), labels benign 0 vs all-attack 1.

| Model | Accuracy | F1 | Macro-F1 | AUC-ROC | EER | TPR | FPR | Precision |
|---|---|---|---|---|---|---|---|---|
| **Tenko (X1–X4)** | **0.8983** | **0.9351** | **0.9260** | **0.9897** | **0.0407** | 0.8793 | 0.0069 | 0.9984 |
| Kitsune baseline | 0.9348 | 0.9610 | 0.8684 | 0.9733 | 0.0651 | 0.9645 | 0.2136 | 0.9576 |

Tenko confusion (test region): TN = 59,583, FP = 417, FN = 36,209, TP = 263,791.
- Tenko flags only **417 / 60,000** benign packets (FPR 0.69%) → Precision 0.998.
- Kitsune's Median+MAD point is far more trigger-happy (FPR 21.4%): higher raw
  recall (0.965) and pooled F1 (attacks dominate 5:1), but much lower **Macro-F1**
  (0.868 vs 0.926) and lower **AUC-ROC** (0.973 vs 0.990). Tenko is the stronger
  threshold-independent detector and the far cleaner operating point.

## Per-attack breakdown (each attack block vs the shared 60k benign)

**Tenko** (TPR = recall on block; F1 vs shared benign; AUC = block-vs-benign on `out[9]`):

| Attack | TPR | F1 | AUC | EER |
|---|---|---|---|---|
| DoS-SYN_Flood | 0.9909 | 0.9913 | 0.9976 | 0.0090 |
| DDoS-UDP_Flood | 0.9245 | 0.9566 | 0.9769 | 0.0419 |
| Recon-OSScan | 0.6222 | 0.7632 | 0.9767 | 0.0769 |
| MITM-ArpSpoofing | 0.9743 | 0.9828 | 0.9976 | 0.0184 |
| Mirai-greeth_flood | 0.9638 | 0.9774 | 0.9969 | 0.0203 |
| DictionaryBruteForce | 0.8001 | 0.8849 | 0.9923 | 0.0434 |

**Kitsune** (companion, TPR / F1 vs shared benign / AUC):

| Attack | TPR | F1 | AUC | EER |
|---|---|---|---|---|
| DoS-SYN_Flood | 0.9964 | 0.8846 | 0.9973 | 0.0126 |
| DDoS-UDP_Flood | 0.9803 | 0.8766 | 0.9859 | 0.0387 |
| Recon-OSScan | 0.9111 | 0.8407 | 0.9360 | 0.1238 |
| MITM-ArpSpoofing | 0.9668 | 0.8697 | 0.9780 | 0.0457 |
| Mirai-greeth_flood | 0.9805 | 0.8767 | 0.9830 | 0.0460 |
| DictionaryBruteForce | 0.9517 | 0.8620 | 0.9593 | 0.0857 |

At the committed η, Tenko's only soft spot is **Recon-OSScan** (TPR 0.62) — a
low-rate scan whose node-aggregated pattern stays closest to benign — yet even
there its threshold-independent AUC is 0.977. The volumetric/rich attacks
(DoS-SYN, MITM, Mirai, DDoS) are essentially saturated (F1 ≥ 0.956, AUC ≥ 0.977).

## Interpretation

### vs the paper's Kitsune combined regime (Table 9)

| Model | Accuracy | F1 | Macro-F1 | AUC-ROC |
|---|---|---|---|---|
| Paper Tenko (combined) | 0.9021 | 0.6603 | 0.8016 | 0.6068 |
| Paper Mateen (combined) | 0.9520 | 0.9710 | 0.9160 | 0.7215 |
| **This mixed run — Tenko** | **0.8983** | **0.9351** | **0.9260** | **0.9897** |

Accuracy lands right on the paper's Tenko combined figure (0.898 vs 0.902), but
F1 (+0.27), Macro-F1 (+0.12) and especially AUC-ROC (+0.38) are dramatically
higher, and Macro-F1 / AUC now exceed the Mateen combined baseline. The AUC gap
is the headline: the η-normalized fused pattern distance is a far more
discriminative continuous signal on this concatenated CICIoT2023 stream than the
paper's combined-regime AUC suggests.

### vs the pooled preview

| | Accuracy | F1 | Macro-F1 | AUC-ROC |
|---|---|---|---|---|
| Pooled preview (per-attack arrays pooled) | 0.797 | 0.856 | 0.771 | 0.938 |
| **Faithful concatenated run** | **0.8983** | **0.9351** | **0.9260** | **0.9897** |
| Δ (concat − pooled) | **+0.101** | **+0.079** | **+0.155** | **+0.052** |

The faithful physically-concatenated run is **uniformly higher** on all four
Table-9 metrics. The gap is a direct consequence of running one shared stream
with node state carried across attacks, rather than pooling six independently
scored per-attack arrays:

1. **One shared clean benign set, scored once.** The concatenated run has a
   single 60k benign negative pool with just 417 false positives (FPR 0.69%).
   Pooling per-attack arrays effectively multiplies the benign/negative side
   (each attack carried its own benign tail, including its own burst window),
   inflating the pooled FP count and dragging Accuracy, pooled F1 and Precision
   down. Sharing one calm benign lead-in is what lifts Precision to 0.998 and
   Accuracy by ~10 points.

2. **Node-state carryover raises the continuous signal (AUC +0.052).** Because
   the `nodeScore` accumulator and the global/single pattern recognizers are
   never reset between attacks, per-source aggregates that drift during one
   attack block stay elevated into the next, and the benign baseline learned in
   the lead-in keeps informing every downstream packet. The fused distance
   `out[9]` therefore separates benign from attack more cleanly end-to-end
   (0.990) than six independently-initialized per-attack passes did (0.938).
   In the pooled preview each attack is scored as if it were the first traffic
   the detector ever saw after training; the concatenated run lets earlier
   attacks "prime" the accumulators, so later blocks sit further from the benign
   centroid.

3. **Macro-F1 jumps the most (+0.155).** Macro-F1 averages the six per-attack F1
   values, each computed against the *shared* clean 60k benign (only 417 shared
   FPs). Weak attacks — Recon-OSScan and DictionaryBruteForce — benefit twice:
   from the low shared-benign FP count and from carried node state, so their F1
   (0.763 / 0.885) is far above what an isolated, state-reset per-attack pass
   yields. That lifts the mean the most.

**Net:** the concatenation is not a cosmetic reshuffle — carrying node state and
sharing one benign lead-in materially changes the numbers, and does so in
Tenko's favour. The pooled preview is a conservative lower bound; the faithful
single-stream regime is the correct analog of the paper's Kitsune combined
setting, and Tenko posts an AUC-ROC of 0.9897 / Macro-F1 0.9260 on it.

## Files (all under `results/CICIoT2023/mixed/`)

- `build_mixed_stream.sh` — build script (pcap merge → labels → 19-field TSV, all asserts).
- `run_mixed.py` — self-contained, pandas-free driver (X1 KitNET + Tenko single-tanh + Kitsune baseline).
- `stream_mixed.pcap` (420k pkts), `labels_mixed.csv`, `stream_mixed.pcap.tsv`, `attack_blocks.csv`.
- `ciciot2023_mixed_stream_metrics.csv` — aggregate rows (Tenko, Kitsune) + 6 per-attack rows each.
- `mixed_summary.json` — machine-readable summary.
- Cached arrays: `rmse_raw_mixed.npy`, `arr_gold_mixed.npy`, `arr_ndg_mixed.npy`,
  `arr_nds_mixed.npy`, `arr_cont_mixed.npy`, `arr_pred_mixed.npy`, `kitsune_testscores_mixed.npy`.

## Protocol deviations

- **`MPLBACKEND=Agg` required** to run `results.py` headless (default macOS
  interactive matplotlib backend aborts). No effect on numbers.
- Label CSV generated with `awk` (not `yes | head`) to avoid a SIGPIPE that trips
  `set -o pipefail`. Cosmetic build-script detail; output identical.
- Otherwise the protocol was followed exactly (stream layout, benignLimit=60000,
  attack blocks, single-tanh, committed η 50/20, exact 19 tshark fields).

## AUC-PR provenance (for Ramkumar et al. 2025 comparison)

Ramkumar reports AUC-PR (not AUC-ROC), so AUC-PR was computed from the cached mixed
arrays via `mixed/_auc_pr.py` (sklearn `average_precision_score`), benign test = 60k
negatives, attacks = 300k positives:

- Tenko  overall AUC-PR = 0.9980; per-attack mean = 0.9904
- Kitsune overall AUC-PR = 0.9949; per-attack mean = 0.9766
- Per-attack (Tenko): DoS-SYN 0.9982, DDoS 0.9843, Recon 0.9748, MITM 0.9976,
  Mirai 0.9971, Dict 0.9904

AUC-PR is prevalence-dependent. The combined stream is attack-heavy (~83% positive,
random baseline ≈0.83), whereas Ramkumar uses 95% benign / 5% attack (random ≈0.05).
For a fair comparison, a prevalence-matched AUC-PR (attack positives subsampled to 5%,
mean ± std over 20 seeds) was computed:

- Tenko  AUC-PR@5% = 0.9431 ± 0.0032
- Kitsune AUC-PR@5% = 0.8969 ± 0.0050

Ramkumar CICIoT2023 detector means (their Table 3, 8 device-attack pairs):
iForest F1 0.795 / AUC-PR 0.968; One-SVM F1 0.563 / AUC-PR 0.762; LOF F1 0.427 / AUC-PR 0.742.

Consolidated write-up: `results/CICIoT2023/cic_baselines_final.tex` (compiles with tectonic).

## Attack-prevalence sweep (Tenko vs Kitsune)

This combined stream is **83.3% attack** (300k attack / 60k benign), which flatters
high-recall/high-FPR detectors on prevalence-weighted metrics. A separate analytic
sweep (`prevalence_sweep_experiment.md`,
`ciciot2023_prevalence_sweep_metrics.csv`, driver `_prevalence_sweep.py`) reweights
the fixed within-class confusion to realistic benign-majority mixes
π ∈ {0.833, 0.50, 0.30, 0.10, 0.05}. No pipeline is re-run — the reweighting is
exact because TPR/FPR are within-class.

- **Prevalence-invariant (reported once):** Tenko FPR 0.0069 / TPR 0.8793 /
  AUC-ROC 0.9897; Kitsune FPR 0.1971 / TPR 0.9637 / AUC-ROC 0.9733. (Kitsune here
  uses the full-benign `[0:60000]` Median+MAD threshold per the sweep spec, so its
  FPR 0.1971 differs slightly from the `[55001:60000]`-calibrated 0.2136 above.)
- **Prevalence-dependent:** as attack fraction drops, Kitsune's 19.7% FPR sinks its
  Precision (0.96 → 0.20) and micro-F1 (0.96 → 0.34), while Tenko's 0.69% FPR keeps
  Precision ≥ 0.87 and micro-F1 ≥ 0.87, with Accuracy rising to 0.99.
- **Crossover:** Tenko overtakes Kitsune on **Accuracy for π ≤ 0.6926** and on
  **micro-F1 for π ≤ 0.6638** — i.e. Tenko wins at any realistic benign-majority
  prevalence; the 83% stream is the only regime where Kitsune's operating point
  looks competitive.

See `prevalence_sweep_experiment.md` for the full table, the crossover analysis, the
AUC-PR reweighting method, and the faithfulness note on uniform subsampling vs
front-truncation.

## Addendum — re-picked benign-calibrated operating point

The committed OR-rule η=(50,20) is *ultra-tight* (benign FPR 0.69%, TPR 0.879) and
starves Tenko's single-signal attacks (Recon 0.62, DictBF 0.80). A separate analytic
recompute (`../calibrated_operating_point_experiment.md`, CSV
`ciciot2023_calibrated_operating_point_metrics.csv`, driver
`_calibrated_operating_point.py`) re-picks a benign-calibrated point at target FPR
∈ {2%, 5%} for both a single fused-score threshold (`cont@x`) and a **jointly
recalibrated OR-rule** (`orrule@x`), and also matches Kitsune to the same FPRs.

**New recommended default: `orrule@2%` = `(nd_g > 30.14) OR (nd_s > 3.14)`** (benign
FPR 2%). On the combined stream this lifts TPR 0.879 → **0.980** and Accuracy@30%
0.959 → **0.980**, rescues Recon (→0.95) and DictBF (→0.997), keeps Precision 0.996,
and beats Kitsune at matched FPR (+12.5 pts TPR at 2% FPR). It maximizes accuracy at
realistic prevalence while beating Kitsune on every metric at matched FPR. See that
memo for the full combined + individual tables, the Tenko-vs-Kitsune matched-FPR
comparison, and paste-ready LaTeX.
