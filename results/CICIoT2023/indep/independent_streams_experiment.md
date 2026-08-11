# CICIoT2023 — Independent Per-Attack Benign Windows

*Repo:* `/Users/sbhola/Desktop/Tenko` (branch `correct-latency`). Every number below comes
from an actual run of the pipeline in this directory (no fabricated values). Reproduce with
`results/CICIoT2023/indep/build_indep_streams.sh` (build) and
`results/CICIoT2023/indep/run_indep.py` (run). All outputs live under
`results/CICIoT2023/indep/`.

## 0. Motivation

In the committed CICIoT2023 setup **all 6 attack streams share the SAME benign traffic**
(the first 180k packets of one `BenignTraffic.pcap`), so the benign false-positive rate is
**byte-identical across attacks** — the shared-benign clean split reports a constant
**FPR = 0.081312 (8.13%)** for every attack (`results/CICIoT2023/ciciot2023_cleansplit_metrics.csv`,
`committed_50_20`). A per-attack FPR column that is a repeated constant looks suspicious.

In Mirsky's Kitsune dataset each attack is a **separate capture with its own benign
traffic**, so per-attack FPR legitimately differs. This experiment reproduces that
methodology on CICIoT2023: each attack gets its **own, distinct 120,000-packet benign
window** (a distinct temporal slice / file of the benign corpus), the streams are rebuilt,
and KitNET(X1)+Tenko(X2–X4) are re-run per stream.

**Honesty caveat up front:** the CICIoT2023 benign corpus is essentially **one long
recording chunked into 4 files** (`BenignTraffic{,1,2,3}.pcap`). Our 6 windows are disjoint
slices of that recording. The resulting per-attack FPR variation therefore reflects
**benign-window difficulty** (how bursty/noisy each temporal slice is), which is the direct
analogue of Mirsky's separate captures having different benign difficulty — it is **not**
caused by attack type.

## 1. Protocol

Per-attack **independent** stream = `[distinct 120,000-pkt benign window] + [that attack's
50,000-pkt _sub.pcap]` = **170,000** packets (packet order preserved). 0-based stream index
map (identical for all 6 attacks):

| Region | Index range | Size | Role |
|---|---|---|---|
| KitNET training (FM 5k + AD 50k) | `[0 : 55000]` | 55,000 | frozen at 55,001 |
| Tenko pattern-model training | `[55001 : 60000]` | 4,999 | `benignLimit = 60000` |
| **benign_test (FPR negatives)** | `[60000 : 120000]` | 60,000 | headline FPR |
| **attack (TPR positives)** | `[120000 : 170000]` | 50,000 | class-1 |

- `benignLimit = 60000` (KitNET trains on the first 55,000; Tenko pattern model on
  `[55001:60000]`). This reuses the reduced-split rationale from
  `singletanh_gridsearch_experiment.md` §2 (small ~5k pattern-training window inflates the
  normalized-distance scale ~10×, placing the committed η=50/20 at a usable operating point).
- **Single-tanh** reporting: the RAW KitNET RMSE is fed into
  `results.get_adversarial_IPs_weighted_pattern`, so its internal `tanh` (`results.py:805`)
  is the only normalization (matches the CIC reporting decision).
- Fixed Tenko params: `memorySize=60`, `blockchainMode="offline"`,
  `pattern_window_size=100`, `pattern_segments=10`, `global_pool_tol_factor=50`,
  `single_agg_tol_factor=20`, `weight_global=weight_single=0.5`, `ensemble_threshold=0.5`.
- Committed operating point (η_global=50, η_node=20): fused OR rule
  `pred = (nd_g > 50) | (nd_s > 20)`. Verified byte-identical to the function's own binary
  prediction `out[1]` (assert in `run_indep.py`).
- Continuous fused score for AUC/EER = `out[9] = 0.5·nd_g + 0.5·nd_s` (η-free).
- Kitsune baseline: `tanh(rmse)` with a benign Median+MAD threshold
  `median + 3·1.4826·MAD` calibrated on `[55001:60000]`, evaluated on the TEST region.

All count/alignment assertions pass: each stream = 170,000 packets = 170,000 label rows =
170,000 TSV rows; label layout = 120,000 zeros + 50,000 ones; per-attack cached arrays are
110,000-long with benign(60k)=0 / attack(50k)=1.

### Metrics
On the TEST region (benign_test `[60000:120000]` negatives, attack `[120000:170000]`
positives):
- **Committed η=50/20**: TPR/FPR/Precision/F1/Accuracy on full benign_test + attack.
- **Threshold-independent AUC/EER** from the fused continuous score.
- **Benign-only calibrated OP**: split benign_test into calib half `[60000:90000]` and eval
  half `[90000:120000]`; pick η by benign quantile targeting 1% / 5% FPR on the calib half;
  report on eval half (30k) + attack.
- **Kitsune baseline**: TPR/FPR/Precision/F1/AUC/EER.

Formulas: Accuracy=(TP+TN)/all; Precision=TP/(TP+FP); F1=2TP/(2TP+FP+FN); FPR=FP/(FP+TN);
TPR=TP/(TP+FN); divide-by-zero → nan.

## 2. Benign-window provenance (6 disjoint windows)

Each window is a distinct temporal slice; distinctness verified by differing md5 and
differing first-packet timestamps (monotonically increasing across the corpus, i.e. genuinely
different sessions). Window = source packets `[offset_start : offset_end]` (1-based).

| Attack | Benign source | Packet range (1-based) | Window size |
|---|---|---|---|
| DDoS-UDP_Flood | `BenignTraffic.pcap` | 1 – 120000 | 120,000 |
| DoS-SYN_Flood | `BenignTraffic.pcap` | 600001 – 720000 | 120,000 |
| Recon-OSScan | `BenignTraffic1.pcap` | 1 – 120000 | 120,000 |
| MITM-ArpSpoofing | `BenignTraffic1.pcap` | 600001 – 720000 | 120,000 |
| Mirai-greeth_flood | `BenignTraffic2.pcap` | 1 – 120000 | 120,000 |
| DictionaryBruteForce | `BenignTraffic3.pcap` | 1 – 120000 | 120,000 |

(Machine-readable copy: `benign_window_provenance.csv`.)

## 3. Results — committed η=50/20 (headline)

Negatives = benign_test 60,000; positives = attack 50,000.

| Attack | benign window | TPR | **FPR** | Precision | F1 | Accuracy | AUC | EER |
|---|---|---|---|---|---|---|---|---|
| DDoS-UDP_Flood | BenignTraffic [1:120k] | 0.9220 | **0.0069** | 0.9910 | 0.9553 | 0.9608 | 0.9722 | 0.0468 |
| DoS-SYN_Flood | BenignTraffic [600k:720k] | 0.9948 | **0.1466** | 0.8498 | 0.9166 | 0.9177 | 0.9953 | 0.0283 |
| Recon-OSScan | BenignTraffic1 [1:120k] | 0.4057 | **0.0000** | 1.0000 | 0.5772 | 0.7299 | 0.9714 | 0.0547 |
| MITM-ArpSpoofing | BenignTraffic1 [600k:720k] | 0.0095 | **0.0300** | 0.2096 | 0.0182 | 0.5334 | 0.3421 | 0.5959 |
| Mirai-greeth_flood | BenignTraffic2 [1:120k] | 0.9219 | **0.0000** | 1.0000 | 0.9594 | 0.9645 | 0.9940 | 0.0129 |
| DictionaryBruteForce | BenignTraffic3 [1:120k] | 0.1580 | **0.0000** | 1.0000 | 0.2729 | 0.6173 | 0.7914 | 0.3226 |
| **mean** | — | **0.5687** | **0.0306** | 0.8417 | 0.6166 | 0.7873 | 0.8444 | 0.1769 |

**KEY RESULT — per-attack committed FPR now VARIES:** min = **0.0000**, max = **0.1466**,
**spread = 0.1466 (14.66 percentage points)**, mean 0.0306, population stdev 0.0529 — versus
the shared-benign setup's **constant 0.0813** for every attack.

## 4. Results — other operating points (means over 6 attacks)

Full per-attack rows: `ciciot2023_independent_streams_metrics.csv` (24 rows = 6 × 4 methods).

| Method | mean TPR | mean FPR | mean Prec | mean F1 | mean Acc | mean AUC | mean EER |
|---|---|---|---|---|---|---|---|
| Tenko committed η=50/20 (fixed, benign-only) | 0.5687 | **0.0306** | 0.8417 | 0.6166 | 0.7873 | 0.8444 | 0.1769 |
| Tenko benign_calib @1% (quantile on calib half) | 0.8214 | 0.2459 | 0.8177 | 0.8185 | 0.7962 | 0.8444 | 0.1769 |
| Tenko benign_calib @5% | 0.8399 | 0.3243 | 0.7814 | 0.8079 | 0.7783 | 0.8444 | 0.1769 |
| Kitsune (Median+MAD) | 0.7580 | 0.2704 | 0.7662 | 0.7095 | 0.7425 | 0.7225 | 0.2960 |

(Tenko AUC/EER are identical across the three Tenko methods because they are
threshold-independent — the η only moves the operating point, not the ranking.)

Per-attack **benign_calib** and **Kitsune** FPR also vary widely across windows (e.g. Tenko
@1% eval-half FPR ranges 0.0092 for Mirai → 0.9965 for MITM; Kitsune FPR ranges 0.0089 for
Mirai → 0.9686 for MITM), reinforcing that the driver of FPR variation is the benign window.

## 5. Interpretation (honest)

**(a) Does per-attack FPR now vary, and by how much?**
Yes. The committed η=50/20 FPR spans **0.0000 → 0.1466** (spread 14.66 pp) across the six
windows, replacing the shared-benign **constant 0.0813**. The two windows drawn at offset
600k (DoS-SYN 14.66%, MITM 3.00%) are markedly harder than the four early/offset-0 windows
(0.00–0.69%). Every operating point (benign-quantile, Kitsune) shows the same qualitative
spread.

**(b) The variation reflects benign-window difficulty, NOT attack type.**
The FPR is measured **only on benign packets**, so by construction it cannot depend on the
attack; it depends entirely on which benign window sits next to that attack. The clear
pattern — offset-600k windows (which contain benign bursts, cf. the documented non-stationary
CICIoT2023 benign trace and "CDN burst" in `singletanh_gridsearch_experiment.md` §4) produce
high FPR, while quiet early windows produce ~0 — is a **benign-window** effect. Because the
corpus is one long recording chunked into 4 files, this is the CICIoT2023 analogue of
Mirsky's separate captures differing in benign difficulty; it should not be read as "attack X
is easier to keep clean than attack Y."

**(c) Comparison to the shared-benign result.**
Shared-benign clean split (`ciciot2023_cleansplit_metrics.csv`): committed η=50/20 FPR =
**0.081312 for all six attacks** (a repeated constant, because the benign test set is
identical). Independent windows: FPR **0.0000–0.1466** (genuinely per-attack). TPRs move too,
because the committed η interacts with each window's nd-scale (the pattern-training window
`[55001:60000]` now lives inside a different benign slice, so the normalization base differs).
The most striking case is **MITM-ArpSpoofing**, whose TPR collapses from 0.9714 (shared) to
0.0095 (independent) with AUC 0.3421 (< 0.5): in its noisy offset-600k window the benign
burst is *more* anomalous than the ARP-spoofing packets (ARP frames carry no IP, so KitNET
sees little signal), so the fixed η flags the wrong class. This is an honest, expected
consequence of pairing a hard attack with a hard benign window — and exactly the kind of
per-capture behaviour the independent-benign methodology is meant to surface.

**(d) Threshold-independent AUC/EER.**
AUC/EER do **not** depend on the η operating point (identical across all three Tenko η
settings above), which is the sense in which they are "stable regardless" of the FPR
calibration. They are **not** constant across attacks, however: they still legitimately vary
(committed AUC 0.3421 → 0.9953, EER 0.0129 → 0.5959) because they measure raw attack-vs-benign
separability, which depends on both the attack and its paired benign window. Four attacks
(DoS-SYN, DDoS, Recon, Mirai) retain strong separability (AUC 0.971–0.995); MITM (0.342) and
DictionaryBruteForce (0.791) are the hard cases in their assigned windows. Kitsune AUC is
lower on average (0.7225) and collapses on MITM (0.165).

## 6. Deviations from the protocol brief
- **`pip install` was required, not optional.** `results.py` imports `pandas` (and
  `psutil`, `tqdm`, `matplotlib`, `requests`, `cython`, `scapy`) at module load, so `import
  results` fails without them; these were installed into `.venv`. The driver itself is
  pandas-free (labels read with the `csv` module) as suggested, but importing the module is
  unavoidable.
- **`MPLBACKEND=Agg` is required.** `results.get_adversarial_IPs_weighted_pattern` builds a
  matplotlib ROC figure; the default macOS GUI backend aborts (SIGABRT) in a headless run.
  Forcing the Agg backend fixes it and changes no numbers.
- No deviation in windows/offsets/sizes: the suggested provenance mapping was used verbatim;
  all 6 windows are disjoint 120,000-packet slices.

## 7. Timing
X1 (KitNET) dominates and is expected to be slow. Per-stream X1 wall time this run:
DDoS-UDP_Flood ≈ 135 s (first pass; then cached), DoS-SYN_Flood ≈ 1693 s (its TCP-SYN-heavy
benign window stresses the feature extractor), Recon ≈ 64 s, MITM ≈ 36 s, Mirai ≈ 45 s,
Dictionary ≈ 52 s. Tenko X2–X4 ≈ 15–20 s per stream. RMSEs are cached to
`rmse_raw_<attack>.npy`, so re-running metrics is fast (`--use-cached-rmse`).

## 8. Files (all under `results/CICIoT2023/indep/`)
- `build_indep_streams.sh` — builds the 6 independent streams (benign windows, merge, labels,
  TSV) with count/alignment assertions.
- `run_indep.py` — self-contained driver (X1 KitNET, Tenko X2–X4 single-tanh, Kitsune
  baseline, all metrics).
- `ciciot2023_independent_streams_metrics.csv` — 24 rows (6 attacks × 4 methods) with metrics
  + benign-window provenance.
- `benign_window_provenance.csv` — window source/offset per attack.
- `stream_<attack>.pcap`, `stream_<attack>.pcap.tsv`, `labels_<attack>.csv`,
  `benign_<attack>.pcap` — intermediates.
- `rmse_raw_<attack>.npy`, `arr_{gold,ndg,nds,cont}_<attack>_indep.npy`,
  `arr_kitsune_<attack>_indep.npy` — cached arrays.
- `build.log`, `run_full.log` — run logs.
