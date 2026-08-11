# The CICIoT2023 Tenko Evaluation — End-to-End Experiment Story

*Repo:* `/Users/sbhola/Desktop/Tenko` (branch `correct-latency`). *Read-only reconstruction.*
Every number below is traceable to a file that was read; `file:line` or `csv:row/col`
citations are given inline. No figure is invented.

---

## 1. The dataset — what CICIoT2023 is, and why we used it

**Source.** CIC IoT Dataset 2023 (University of New Brunswick / CIC), used from its **raw
PCAP** release rather than the pre-computed CSVs. The roadmap fixes this as the headline
recent dataset for the R2 revision (`TENKO_R2_REVISION_ROADMAP.md:12`, `:59-61`), and states
"105 real IoT devices, benign + 33 attacks / 7 classes (DDoS, DoS, Recon, Web, Brute Force,
Spoofing, Mirai)" (`TENKO_R2_REVISION_ROADMAP.md:61`).

**Why PCAP, not the CSVs (the load-bearing decision).** Tenko's contribution is *node-level*
aggregation, and a node is identified by the **per-packet source IP**. The popular CICIoT2023
CSVs drop that column, which "would collapse node aggregation" (`TENKO_R2_REVISION_ROADMAP.md:27`).
The team verified the downloaded CSV package was "39 aggregate features + Label with NO source
IP / flow-id / timestamp → full Tenko node aggregation is impossible on them"
(`TENKO_R2_REVISION_ROADMAP.md:77`). The same reason ruled out the earlier "IDS 2025" folder,
which turned out to be **CSE-CIC-IDS2018** flow CSVs — "80 CICFlowMeter features + `Label`, **no
Source IP column**" — "not compatible with Tenko's packet pipeline"
(`TENKO_R2_REVISION_ROADMAP.md:23`). So CICIoT2023 PCAP was chosen precisely because it exposes
*ordered packet streams, a benign reference window, and per-packet source identity* — the three
properties Tenko's node state requires (`manuscript_drafts.md:233-235`).

**Which attack classes.** CICIoT2023 ships 7 attack families; we used **6 classes**, one PCAP
per class (`run_ciciot2023.py:43-50`, `scripts/build_streams_ciciot2023.sh:32-39`):

| Class used | Source PCAP | Raw size on disk |
|---|---|---|
| DDoS-UDP_Flood | `DDoS-UDP_Flood.pcap` | 2.048 GB |
| DoS-SYN_Flood | `DoS-SYN_Flood.pcap` | 2.048 GB |
| Recon-OSScan | `Recon-OSScan.pcap` | 324 MB |
| MITM-ArpSpoofing | `MITM-ArpSpoofing.pcap` | 2.046 GB |
| Mirai-greeth_flood | `Mirai-greeth_flood.pcap` | 2.048 GB |
| DictionaryBruteForce | `DictionaryBruteForce.pcap` | 39 MB |

Raw class sizes are from the on-disk listing of `/Users/sbhola/Desktop/cic/dataset/CICIoT2023/raw`.
Benign traffic is 4 chunks (`BenignTraffic.pcap`, `BenignTraffic1/2/3.pcap`, ≈ 7 GB total) from the
same directory. The order-of-classes is benign-first, defined in
`scripts/build_ciciot2023_pilot.sh:22-30`.

**Approx. raw vs pilot size.** The full CICIoT2023 raw PCAP corpus is "~548 GB"
(`TENKO_R2_REVISION_ROADMAP.md:78`); only the CSVs are ~13 GB. We downloaded ~30–35 GB of raw
PCAP (per-class chunks) and then carved a **pilot** of ~1.4 GB of stream PCAP/TSV
(`/Users/sbhola/Desktop/cic/pilot` listing: six `stream_*.pcap` ≈ 47–98 MB each plus their TSVs).
The roadmap describes the pilot as "first-N chunks per class ≈ 100–150 MB total"
(`TENKO_R2_REVISION_ROADMAP.md:78`).

**Ground-truth labels.** CICIoT2023 has **no per-packet ground-truth file**; the class *is* the
capture-session identity, i.e. the PCAP a packet came from
(`scripts/build_ciciot2023_pilot.sh:4-5`, `TENKO_R2_REVISION_ROADMAP.md:81`). Binary label = 0 if
from `BenignTraffic`, else 1.

---

## 2. What we took out of it (extraction / subsampling)

### 2a. PCAP → Tenko TSV (tshark field order)

Every PCAP is converted with tshark to the exact 19-column field order Tenko's
`FeatureExtractor` expects (`scripts/pcap2tsv_tenko.sh:16-22`,
`scripts/build_streams_ciciot2023.sh:107-113`):

```
col0 frame.time_epoch  col1 frame.len  col2 eth.src  col3 eth.dst
col4 ip.src  col5 ip.dst  col6 tcp.srcport col7 tcp.dstport
col8 udp.srcport col9 udp.dstport col10 icmp.type col11 icmp.code
col12 arp.opcode col13 arp.src.hw_mac col14 arp.src.proto_ipv4
col15 arp.dst.hw_mac col16 arp.dst.proto_ipv4  col17 ipv6.src col18 ipv6.dst
```

The **source IP** — the node key for Tenko's aggregation — is **col 4 (IPv4) or col 17 (IPv6)**;
the script comments warn "Do NOT reorder" (`scripts/pcap2tsv_tenko.sh:9`), and the field order was
verified against `FeatureExtractor.pcap2tsv_with_tshark()` (`TENKO_R2_REVISION_ROADMAP.md:86-87`).

### 2b. Pilot subset + subsample rates

Extraction is "first-N packets" per source, done with `tshark -c N -w` so it stops early instead of
scanning the whole multi-GB file (`scripts/build_streams_ciciot2023.sh:11-13, 43-66`). The window
sizes are fixed constants (`scripts/build_streams_ciciot2023.sh:21-23`):

- `N_LEAD = 150000` benign lead-in packets,
- `N_TEST = 30000` benign test packets,
- `N_ATK = 50000` attack packets per class.

**Benign lead / benign_test come from the *same* benign trace** (`BenignTraffic.pcap`) to follow
the standard Kitsune protocol (train + test benign from one trace) and avoid cross-session shift that
would inflate FPR (`scripts/build_streams_ciciot2023.sh:26-30`). Specifically:

- **benign_lead** = first 150,000 packets of `BenignTraffic.pcap`.
- **benign_test** = packets **150,001 … 180,000** of the same file (extract first 180,000, then
  `editcap` deletes 1–150,000, leaving the 30k tail) (`scripts/build_streams_ciciot2023.sh:47-53`).
- **attack** = first 50,000 packets of each attack PCAP (`scripts/build_streams_ciciot2023.sh:60-66`).

### 2c. Resulting stream layout (exact sizes)

Each per-attack stream is concatenated **[benign_lead] + [benign_test] + [attack]** with packet
order preserved (`scripts/build_streams_ciciot2023.sh:4-9, 71-74`). The recorded counts are
identical for all six classes (`stream_counts.csv:2-7`):

| Region | Label | Index range (0-based) | Size |
|---|---|---|---|
| benign_lead (KitNET train + pattern calibration) | 0 | 0 … 149,999 | **150,000** |
| benign_test (FPR negatives) | 0 | 150,000 … 179,999 | **30,000** |
| attack (TPR positives) | 1 | 180,000 … 229,999 | **50,000** |
| **total per stream** | — | — | **230,000** |

`benignLimit` = length of benign_lead = **150,000** (`stream_counts.csv` col `benignLimit`;
`run_ciciot2023.py:141-148`). Within KitNET, the first `FMGRACE=5000` + `ADGRACE=50000` packets are
grace/training, so benign *calibration* for thresholds starts at index
`TRAIN_START_IDX = 55001` (`run_ciciot2023.py:34-37`). The driver asserts label boundaries hold
exactly — benign region all-0, attack region all-1 (`run_ciciot2023.py:149-153`). The roadmap
summary matches: "150k benign_lead + 30k benign_test (in-distribution held-out) + 50k attack = 230k
pkts each; benignLimit=150000; 0 packet drops" (`TENKO_R2_REVISION_ROADMAP.md:137`).

### 2d. What the driver runs and persists

For each stream, `run_ciciot2023.py`:
1. Streams the TSV through **KitNET (X1)** producing one raw RMSE per packet, guaranteeing 1:1
   RMSE↔packet↔label alignment (a parse error yields a neutral 0.0 instead of truncating)
   (`run_ciciot2023.py:53-80`).
2. Runs the **Kitsune baseline** = `tanh(RMSE)` with a benign Median+MAD threshold
   (`thr = median + 3.0·1.4826·MAD`) calibrated on `[55001 : 150000]` and evaluated on the test
   region (`run_ciciot2023.py:34-38, 108-125`).
3. Runs **Tenko X2–X4** via `R.get_adversarial_IPs_weighted_pattern(...)` with `benignLimit=150000`,
   `memorySize=60`, `pattern_window_size=100`, `pattern_segments=10`, weights 0.5/0.5, threshold 0.5
   (`run_ciciot2023.py:179-186`).
4. Persists per-test-packet arrays: `arr_gold_*`, `arr_ndg_*_<tag>`, `arr_nds_*_<tag>`,
   `arr_cont_*_<tag>`, `arr_node_*_<tag>`, `arr_kitsune_*` (`run_ciciot2023.py:194-199`), enabling
   offline η recalibration and single/double comparison **without re-running X1/X2**.

---

## 3. What we changed vs the committed Tenko pipeline

### 3a. Benign-only η recalibration (the main fix)

**Symptom.** With the committed operating point `η_global=50, η_node=20`, fusion 0.5/0.5,
threshold 0.5, Tenko was **degenerate on all 6 classes — it flagged nothing** (TPR = FPR = 0)
(`ciciot2023_committedEta_double.csv:3,5,7,9,11,13`; `ciciot2023_tenko_signal_breakdown.csv` col
`tenko_op_degenerate` = 1 for every class, rows 2–7). Root cause: the fused rule flags when the
**normalized** pattern distance `nd > η`, where `nd = distance / (max benign training spread)`
(`results.py:884-893, 946-956`). After the committed squashing the benign-normalized attack
distances top out around ~2.4, far below η_node=20 / η_global=50, so nothing ever fires
(`TENKO_R2_REVISION_ROADMAP.md:139`). The diagnosis: "the culprit was **η_node** — committed 20,
needed ~2.85 (η_global 50→~41)" (`TENKO_R2_REVISION_ROADMAP.md:149`).

**Method (benign-quantile search).** `recalibrate_ciciot2023.py` uses **no attack labels**. It scans
a shared benign quantile `q` over `[0.50 … 0.99999]`, sets `η_global = Q(benign_ndg, q)` and
`η_node = Q(benign_nds, q)`, and picks the `q` whose fused benign-only FPR is closest to (from below)
the target (`recalibrate_ciciot2023.py:72-92, 131-151`). Recalibrated values (identical across
classes because the benign_test spread is shared) (`ciciot2023_metrics_recalibrated.csv:2-3`):

| Target benign FPR | η_global | η_node | shared q |
|---|---|---|---|
| committed | 50.0 | 20.0 | — (`recalibrate_ciciot2023.py:33-34`) |
| 1% | **40.699** | **2.854** | 0.994768 |
| 5% | **35.834** | **2.207** | 0.968434 |

So the fix is overwhelmingly on **η_node (20 → ~2.2–2.85)**: it was mis-scaled, producing the
degeneracy. Once corrected, Tenko is no longer degenerate (see §4).

### 3b. The double-`tanh` discovery

**Where.** The committed pipeline applies `tanh` **twice**: once in `example.py:157`
(`rmse = np.tanh(rmse)`, needed because node scoring requires `[0,1]`) and again in `results.py:805`
under a "# --- Normalization ---" comment (`RMSEs_norm = np.tanh(np.array(RMSEs))`). Composed, the
released code computes `tanh(tanh(raw))`, squashing scores into ~`[0, 0.762]`
(`run_ciciot2023.py:15-18`, `manuscript_drafts.md:46-52`, `TENKO_R2_REVISION_ROADMAP.md:163-166`).
The second tanh is **redundant** — it receives an already-squashed score.

**The `--tanh {double,single}` switch.** `run_ciciot2023.py` reproduces both: `double` feeds
`tanh(raw)` into the Tenko function (which tanhs again = committed `tanh(tanh(raw))`); `single` feeds
raw RMSE so `results.py`'s tanh is the only normalization (`tanh(raw)`)
(`run_ciciot2023.py:164-169, 244-245`).

**Impact — small on AUC.** Single vs double pattern-distance AUC (`ciciot2023_tanh_impact.csv:2-7`):

| Attack | double AUC | single AUC | Δ(single−double) |
|---|---|---|---|
| DDoS-UDP_Flood | 0.928822 | 0.930948 | +0.002126 |
| DoS-SYN_Flood | 0.987792 | 0.988392 | +0.000600 |
| Recon-OSScan | 0.795871 | 0.796219 | +0.000348 |
| MITM-ArpSpoofing | 0.949187 | 0.951141 | +0.001954 |
| Mirai-greeth_flood | 0.936728 | 0.936996 | +0.000268 |
| DictionaryBruteForce | 0.696816 | 0.707727 | +0.010911 |

Max AUC change is **+0.010911** (Dictionary), median well under 0.002 — i.e. **AUC ≤ 0.011**, the
number cited in the methods clarification (`manuscript_drafts.md:255-262, 299`).

**Impact — larger on the *operating point*.** Under **single**-tanh the committed η=50/20 stops
being uniformly degenerate: it fires for 4/6 attacks (e.g. DoS-SYN TPR 0.71518, DDoS TPR 0.05964),
while it stays degenerate under double (`ciciot2023_committedEta_single.csv:3,5`;
`ciciot2023_tanh_impact.csv` cols `single_committedEta_*` vs `double_committedEta_*`, rows 2–7;
`TENKO_R2_REVISION_ROADMAP.md:166`).

**Reporting decision.** CICIoT2023 is reported under a **fixed single-tanh** normalization
(redundant second tanh removed for this dataset), while noting it is numerically ~equivalent to
double (AUC ≤ 0.011) (`TENKO_R2_REVISION_ROADMAP.md:170-171`; `manuscript_drafts.md:255-262`). The
provenance check found the **main-paper** numbers were themselves generated under the double-tanh
pipeline, so those tables stand and are described accurately rather than silently changed
(`TENKO_R2_REVISION_ROADMAP.md:186-188`).

### 3c. New code artifacts

- `run_ciciot2023.py` — the per-attack driver (X1 + Kitsune + Tenko X2–X4, array persistence,
  `--tanh` switch).
- `recalibrate_ciciot2023.py` — benign-only in-sample η recalibration (TASK 1) + single/double
  impact (TASK 2).
- `recalibrate_ciciot2023_oos.py` — out-of-sample η recalibration (TASK 3).
- **Additive returns in `results.py`**: `benignLimit` and `return_scores` params
  (`results.py:783-784`) plus new returns `nd_g_list` / `nd_s_list` — the per-test-packet global and
  single-aggregate **normalized** pattern distances (`results.py:890-891, 946-962, 1060-1062`).
  These are the threshold-independent signals that make offline η re-search possible. Defaults
  preserve original behavior (`results.py:787-789`). Roadmap: "additive `return_scores`/`benignLimit`
  params in `results.py` + new `run_ciciot2023.py` driver + `scripts/build_streams_ciciot2023.sh`"
  (`TENKO_R2_REVISION_ROADMAP.md:142`).

### 3d. Out-of-sample calibration protocol (added for honesty)

The in-sample recalibration fits η on `benign_test` and then measures FPR on that *same* slice, so
its 1%/5% FPR is **definitional, not predictive** (`recalibrate_ciciot2023.py:13-18`,
`TENKO_R2_REVISION_ROADMAP.md:161`). `recalibrate_ciciot2023_oos.py` fixes this: it splits
`benign_test` in half — **CALIB = first 15,000, EVAL = held-out 15,000** — selects η on CALIB only
(no attack labels), and reports FPR/TPR on the disjoint EVAL + attack set. It reports **both split
directions** (`fwd`: calib=1st half; `rev`: calib=2nd half) because the trace is non-stationary
(`recalibrate_ciciot2023_oos.py:7-23, 96-149`).

---

## 4. The results now

### 4a. Full-trace threshold-independent AUC / EER (headline)

From `ciciot2023_per_class_metrics.csv` (Kitsune rows vs "Tenko (…)" rows; AUC/EER columns).
Tenko's AUC/EER come from the continuous η-normalized fused pattern distance and are **invariant to
the operating point** (`run_ciciot2023.py:203-207`).

| Attack | AUC Kitsune | AUC Tenko | EER Kitsune | EER Tenko | Winner |
|---|---|---|---|---|---|
| DDoS-UDP_Flood | 0.965073 | 0.928822 | 0.123863 | 0.129363 | Kitsune |
| DoS-SYN_Flood | 0.992747 | 0.987792 | 0.036643 | 0.051803 | Kitsune |
| MITM-ArpSpoofing | 0.942003 | **0.949187** | 0.147373 | **0.130690** | **Tenko** |
| Mirai-greeth_flood | 0.929418 | **0.936728** | 0.153343 | **0.139573** | **Tenko** |
| Recon-OSScan | 0.827176 | 0.795871 | 0.216383 | 0.255887 | Kitsune |
| DictionaryBruteForce | 0.703386 | 0.696816 | 0.318927 | 0.284700 | mixed (Tenko EER) |

Source rows: `ciciot2023_per_class_metrics.csv:2,3` (DDoS), `:6,7` (DoS-SYN), `:14,15` (MITM),
`:18,19` (Mirai), `:10,11` (Recon), `:22,23` (Dict). Tenko **wins on MITM and Mirai**
(the sustained-deviation attacks its node aggregation targets) and is **competitive but not
dominant** elsewhere (`manuscript_drafts.md:140, 212`).

### 4b. Operating-point table (benign-calibrated η @ 5%, in-sample)

Rows "Tenko (eta recal benign, FPR@5%)" from `ciciot2023_per_class_metrics.csv`, sorted by TPR. The
FPR column is **in-sample by construction** (η fit and FPR measured on the same benign_test slice) —
a calibration diagnostic, not a deployment guarantee (`manuscript_drafts.md:192-206`).

| Attack | TPR | FPR (in-sample) | Precision | F1 |
|---|---|---|---|---|
| DoS-SYN_Flood | 0.962660 | 0.049967 | 0.969798 | 0.966216 |
| MITM-ArpSpoofing | 0.824020 | 0.049967 | 0.964895 | 0.888910 |
| DDoS-UDP_Flood | 0.783180 | 0.049967 | 0.963131 | 0.863884 |
| Mirai-greeth_flood | 0.711620 | 0.049967 | 0.959574 | 0.817203 |
| — reliability divider — | | | | |
| Recon-OSScan | 0.114620 | 0.049967 | 0.792669 | 0.200280 |
| DictionaryBruteForce | 0.030540 | 0.049967 | 0.504627 | 0.057594 |

Source rows: `ciciot2023_per_class_metrics.csv:5,17,4,21,13,25`. (At the 1% target the same
ordering holds with lower TPR, e.g. DoS-SYN 0.94162, MITM 0.52362 — rows `:8,16,…`.) Recon and
Dictionary stay weak because their AUC is genuinely low (0.796, 0.697) — a separability problem, not
a threshold problem (`TENKO_R2_REVISION_ROADMAP.md:157-160`).

For reference, the Kitsune baseline runs at a **constant benign Median+MAD FPR ≈ 0.3233** on every
class (`ciciot2023_per_class_metrics.csv` Kitsune `FPR` col, all rows = 0.323333), i.e. it is not
operating at a comparably tight false-alarm budget.

### 4c. The out-of-sample FPR non-transfer finding (the honest caveat)

Held-out benign FPR from `ciciot2023_metrics_recalibrated_oos.csv` (double variant; `heldout_benign_fpr`
column) shows a fixed benign-calibrated η **does not transfer** across disjoint benign slices of this
non-stationary trace:

| Target | fwd (calib=1st half → eval=2nd) | rev (calib=2nd half → eval=1st) |
|---|---|---|
| 1% | **0.0** (`oos.csv:2`) | **0.304** (`oos.csv:4`) |
| 5% | **0.0** (`oos.csv:3`) | **0.319267** (`oos.csv:5`) |

I.e. the same calibration recipe yields held-out FPR of **≈ 0%** in one direction and **≈ 30%** in
the other — versus the 1–5% nominal target (`TENKO_R2_REVISION_ROADMAP.md:177-184`). This confirms
the in-sample 1%/5% numbers were definitional. **AUC/EER, being threshold-independent, are stable
and are the honest headline** — e.g. OOS double/fwd DoS-SYN AUC/EER = 0.993620 / 0.024487
(`oos.csv:10`), MITM 0.984969 / 0.065113 (`oos.csv:26`). The corresponding held-out Kitsune AUC/EER,
recomputed on the same slice, are reported in `manuscript_drafts.md:181-186` (e.g. DoS-SYN
0.997 / 0.011). Single-tanh ≈ double-tanh OOS (±0.02 TPR), so the tanh choice is numerically
irrelevant on this data (`TENKO_R2_REVISION_ROADMAP.md:184`).

### 4d. Honest bottom line

- **Strong on sustained-deviation attacks:** DoS-SYN (AUC 0.988), MITM (0.949), Mirai (0.937), DDoS
  (0.929) — Tenko *wins* on MITM and Mirai (`ciciot2023_per_class_metrics.csv`).
- **Weak on benign-overlapping low-rate attacks:** Recon-OSScan (AUC 0.796) and DictionaryBruteForce
  (AUC 0.697) remain hard under benign-only training — low AUC ⇒ genuine separability limit
  (`TENKO_R2_REVISION_ROADMAP.md:157-160`; `manuscript_drafts.md:241-243`).
- **Tenko is competitive, not dominant, vs Kitsune:** a small edge on the two sustained-deviation
  attacks, near-ceiling elsewhere for a well-thresholded per-packet baseline
  (`manuscript_drafts.md:212`).
- **FPR does not transfer** on this non-stationary benign trace, so CICIoT2023 is headlined by
  threshold-independent AUC/EER with the operating point clearly labeled in-sample
  (`manuscript_drafts.md:90-97, 244-252`).

---

## Provenance of every number (re-verify)

| Claim | Source file : location | Value |
|---|---|---|
| Stream layout 150k/30k/50k = 230k, benignLimit 150000 | `stream_counts.csv:2-7`; `scripts/build_streams_ciciot2023.sh:21-23` | as tabled |
| benign_test = pkts 150,001–180,000 same trace | `scripts/build_streams_ciciot2023.sh:47-53` | 30,000 |
| tshark src-IP col 4 / 17 | `scripts/pcap2tsv_tenko.sh:4-9` | — |
| Committed η degenerate (TPR=FPR=0) | `ciciot2023_committedEta_double.csv:3,5,7,9,11,13`; `ciciot2023_tenko_signal_breakdown.csv:2-7` | 0/0, degenerate=1 |
| Recalibrated η @1% / @5% | `ciciot2023_metrics_recalibrated.csv:2,3` | 40.699/2.854 ; 35.834/2.207 |
| Double-tanh location | `example.py:157` + `results.py:805` | tanh(tanh(raw)) |
| Single−double AUC ≤ 0.011 | `ciciot2023_tanh_impact.csv:2-7` (Dict max +0.010911) | ≤ 0.011 |
| Full-trace AUC/EER | `ciciot2023_per_class_metrics.csv:2-25` | as tabled §4a |
| Operating point @5% (in-sample) | `ciciot2023_per_class_metrics.csv:5,17,4,21,13,25` | as tabled §4b |
| Kitsune constant FPR 0.3233 | `ciciot2023_per_class_metrics.csv` Kitsune `FPR` | 0.323333 |
| OOS held-out FPR 0% / ~30% | `ciciot2023_metrics_recalibrated_oos.csv:2-5` `heldout_benign_fpr` | 0.0 / 0.304 / 0.319 |
| `nd_g`/`nd_s` additive returns | `results.py:783-784, 890-891, 946-962, 1060-1062` | — |
| Raw ~548 GB vs pilot ~100–150 MB target | `TENKO_R2_REVISION_ROADMAP.md:78` | — |
