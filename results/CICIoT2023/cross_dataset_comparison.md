# Cross-dataset comparison — CICIoT2023 vs the paper's other datasets

Read-only build. Paper numbers extracted verbatim from the Overleaf LaTeX in the parent-chat
transcript `0f2afd6d-…jsonl`; CICIoT2023 numbers from committed CSVs under `results/CICIoT2023/`.
No git commits; no invented numbers. Every cell cites its source.

## Step 1 — the paper's EXISTING per-dataset results (verbatim)

### 1a. Kitsune dataset — absolute operating-point metrics (`tab:best_weighted_performance`)
Tenko, committed η=50/20 weighted ensemble. "Standard operating conditions." Horizontal divider =
paper's own reliable/degraded split.
Source: transcript, table `tab:best_weighted_performance`.

| Attack (Kitsune ds) | TPR | FPR | Precision | F1 | paper class |
|---|---|---|---|---|---|
| Mirai Botnet      | 0.998 | <0.001 | 0.997 | 0.998 | reliable |
| OS Scan           | 0.964 | 0.049 | 0.457 | 0.620 | reliable |
| SSDP Flood        | 0.982 | 0.006 | 0.890 | 0.934 | reliable |
| SSL Renegotiation | 0.996 | 0.081 | 0.254 | 0.404 | reliable |
| ARP MiTM          | 0.953 | 0.207 | 0.654 | 0.776 | reliable |
| SYN DoS           | 1.000 | 0.133 | 0.012 | 0.023 | degraded |
| Video Injection   | 0.994 | 0.790 | 0.054 | 0.102 | degraded |
| Fuzzing           | 0.981 | 0.581 | 0.302 | 0.464 | degraded |
| Active Wiretap    | 0.999 | 0.498 | 0.525 | 0.689 | degraded |

### 1b. Kitsune dataset — AUC/EER, Kitsune vs Tenko (`tab:kitsune-tenko-new-highlighted`)
Source: transcript, table `tab:kitsune-tenko-new-highlighted` (Tenko bolded = best in paper).

| Attack (Kitsune ds) | AUC Kitsune | AUC Tenko | EER Kitsune | EER Tenko |
|---|---|---|---|---|
| Mirai Botnet      | 0.95 | 0.996 | 0.05 | <0.01 |
| OS Scan           | 0.90 | 0.96  | 0.10 | 0.04 |
| SSDP Flood        | 0.88 | 0.99  | 0.12 | 0.01 |
| SSL Renegotiation | 0.92 | 0.96  | 0.08 | 0.08 |
| ARP MiTM          | 0.96 | 0.96  | 0.04 | 0.02 |
| SYN DoS           | 0.89 | 0.95  | 0.11 | 0.09 |
| Video Injection   | 0.93 | 0.95  | 0.07 | 0.05 |
| Fuzzing           | 0.85 | 0.91  | 0.15 | 0.11 |
| Active Wiretap    | 0.87 | 0.93  | 0.13 | 0.05 |

Note: on the Kitsune dataset **Tenko ≥ Kitsune on AUC and EER for all nine attacks** (Tenko bolded everywhere).

### 1c. N-BaIoT (Hermes vs Tenko) — COMMENTED OUT in the manuscript
Source: transcript — the whole `tabular` is `%`-commented (inactive). It is per-DEVICE (not
per-attack), so it is not directly comparable to CICIoT2023's per-attack axis. Representative
(inactive) rows, Hermes/Tenko: Danmini Doorbell F1 0.973/0.823, FPR 0.082/0.222; Ecobee Thermostat
F1 0.961/0.877, FPR 0.121/0.069; Ennio Doorbell F1 0.966/0.671. (Supervised Hermes vs unsupervised
Tenko; benign-only Tenko trades TPR/FPR for no labels.) Excluded from the quantitative comparison
because it is inactive and per-device.

### 1d. CIC-IDS2018 — NO results table in the manuscript
Search of the LaTeX Evaluation Setup lists only the Kitsune dataset, N-BaIoT, and Mateen
(distribution-shift) as evaluation corpora; "CIC-IDS2018 / CSE-CIC / CICFlowMeter" appear only in
agent/roadmap discussion (the `~/Desktop/archive (1)` flow CSVs), never as a manuscript results
table. → nothing to compare.

### 1e. `resultsNew.py` (origin/Daksh-Mateen) — threshold-SWEEP literals, not the final numbers
`git show origin/Daksh-Mateen:resultsNew.py` holds commented `TPR/FPR/FNR/Precision = np.array([...])`
matrices of shape (7 thresholds × 9 attacks) for {Highest, medium, Lowest, Max, 3-sigma, Med+1.5×MAD,
Logarithmic}. These are per-threshold exploration values (e.g., Med+1.5×MAD TPR row
`[0.910,1.000,1.000,1.000,0.994,1.000,1.000,1.000,1.000]`), NOT the published weighted-ensemble
operating point in `tab:best_weighted_performance`. → the manuscript's final per-attack numbers come
from the transcript tables above; `resultsNew.py` is corroborating exploration only.

---

## Step 2 — side-by-side comparison (CICIoT2023 vs Kitsune dataset)

CICIoT2023 sources: AUC/EER full-trace = `ciciot2023_per_class_metrics.csv` (Kitsune & Tenko rows);
operating point = same CSV, rows "Tenko (eta recal benign, FPR@5%)".

### 2a. AUC/EER — full CICIoT2023 panel (both detectors), grouped by attack character

| CICIoT2023 attack | type | AUC Kitsune | AUC Tenko | EER Kitsune | EER Tenko | Tenko−Kitsune AUC |
|---|---|---|---|---|---|---|
| DoS-SYN Flood        | sustained flood | 0.993 | 0.988 | 0.037 | 0.052 | −0.005 |
| DDoS-UDP Flood       | sustained flood | 0.965 | 0.929 | 0.124 | 0.129 | −0.036 |
| MITM-ArpSpoofing     | entity/sustained | 0.942 | **0.949** | 0.147 | **0.131** | **+0.007** |
| Mirai-greeth Flood   | botnet/sustained | 0.929 | **0.937** | 0.153 | **0.140** | **+0.008** |
| Recon-OSScan         | recon/low-rate | 0.827 | 0.796 | 0.216 | 0.256 | −0.031 |
| Dictionary BruteForce| low-rate/overlap | 0.703 | 0.697 | 0.319 | 0.285 | −0.006 |

On CICIoT2023, **Tenko > Kitsune only on the two entity/sustained attacks (MITM, Mirai)** — exactly
where node aggregation is designed to help — and is at par / slightly below on pure floods and
low-rate attacks. (Contrast: Tenko beat Kitsune on all 9 Kitsune-dataset attacks.)

### 2b. MATCHED attacks — Tenko AUC/EER, paper (Kitsune ds) vs CICIoT2023 (both full-trace, threshold-independent)

| Attack (matched) | AUC Tenko (Kitsune ds) | AUC Tenko (CICIoT2023) | ΔAUC | EER Tenko (Kitsune ds) | EER Tenko (CICIoT2023) | ΔEER |
|---|---|---|---|---|---|---|
| SYN DoS ↔ DoS-SYN     | 0.95  | 0.988 | **+0.038** (better) | 0.09  | 0.052 | −0.038 (better) |
| Mirai ↔ Mirai-greeth  | 0.996 | 0.937 | −0.059 (worse)      | <0.01 | 0.140 | +0.13 (worse) |
| ARP MITM ↔ MITM-Arp   | 0.96  | 0.949 | −0.011 (≈equal)     | 0.02  | 0.131 | +0.11 (worse) |
| OS Scan ↔ Recon-OSScan| 0.96  | 0.796 | **−0.164** (worse)  | 0.04  | 0.256 | +0.22 (worse) |

Matched AUC: 1 better (SYN DoS), 1 ≈equal (ARP MITM), 2 worse (Mirai mildly, OS Scan sharply). EER is
uniformly higher (worse) on CICIoT2023 except SYN DoS → CICIoT2023 is a harder benign regime.

### 2c. Operating-point TPR/FPR/F1 — matched attacks (⚠️ NOT the same η protocol)

Paper = committed η=50/20 (`tab:best_weighted_performance`). CICIoT2023 = benign-recalibrated η at 5%
in-sample FPR (`Table X`), because the committed η=50/20 is **degenerate on CICIoT2023** (flags
nothing — TPR=FPR=0; `ciciot2023_committedEta_double.csv`). So this row-pairing compares two DIFFERENT
operating points and is indicative only; the AUC/EER panel (2a/2b) is the fair cross-dataset axis.

| Attack | Paper (Kitsune ds) TPR/FPR/F1 @η=50/20 | CICIoT2023 TPR/FPR/F1 @η-recal 5% |
|---|---|---|
| SYN DoS ↔ DoS-SYN      | 1.000 / 0.133 / 0.023 (degraded) | 0.963 / 0.050 / 0.966 (strong) |
| Mirai ↔ Mirai-greeth   | 0.998 / <0.001 / 0.998 (best)    | 0.712 / 0.050 / 0.817 |
| ARP MITM ↔ MITM-Arp    | 0.953 / 0.207 / 0.776            | 0.824 / 0.050 / 0.889 |
| OS Scan ↔ Recon-OSScan | 0.964 / 0.049 / 0.620            | 0.115 / 0.050 / 0.200 (weak) |

The paper's SYN-DoS "degraded" F1 (0.023) is a precision artifact (FPR 0.133, few attack packets at
η=50/20); at a benign-calibrated 5% FPR on CICIoT2023 the same attack class is Tenko's strongest
(F1 0.966). Conversely OS-Scan is reliable in the paper (F1 0.620) but weak on CICIoT2023 recon
(F1 0.200). These flips are operating-point + traffic-character effects, not a metric error.

---

## Step 3 — VERDICT

### Is CICIoT2023 CONSISTENT with the paper's established story?
**Yes, at the level of the thesis.** The paper's claim is that Tenko is strong on attacks that drive a
sustained excursion outside the benign cloud and weak on benign-overlapping traffic ("attacks
producing sustained behavioral deviation maintain low false positive rates, whereas attacks whose
traffic overlaps benign distributions produce elevated false positives"). CICIoT2023 reproduces this:
- **Sustained-deviation attacks are strong**: DoS-SYN AUC 0.988, DDoS-UDP 0.929, MITM 0.949, Mirai 0.937.
- **Benign-overlapping / low-rate attacks are weak**: Recon-OSScan 0.796, Dictionary Brute Force 0.697.
- **Node aggregation still helps where designed**: on CICIoT2023 Tenko beats Kitsune exactly on the
  entity/sustained attacks (MITM +0.007, Mirai +0.008 AUC), matching the mechanism the paper credits.

### Matched attacks — same ballpark?
- **SYN DoS**: CICIoT2023 **better** (AUC 0.988 vs 0.95; EER 0.052 vs 0.09).
- **ARP MITM**: **≈ equal** AUC (0.949 vs 0.96), higher EER (0.131 vs 0.02).
- **Mirai**: **mildly worse** (AUC 0.937 vs 0.996; still strong, >0.93).
- **OS Scan**: **notably worse** (AUC 0.796 vs 0.96) — the one real divergence. The Mirsky "OS Scan"
  is a more separable scan; CICIoT2023 "Recon-OSScan" reconnaissance overlaps benign far more, so the
  same name denotes harder traffic. Must be explained, not hidden.

### Bottom line: "are we good on CICIoT2023?" — **QUALIFIED YES.**
Strongest supporting facts:
1. The core mechanism transfers: Tenko's node-aggregation advantage over Kitsune reproduces on exactly
   the sustained/entity attacks it targets (MITM, Mirai), on a genuinely recent trace.
2. The reliable-vs-degraded pattern is preserved (sustained floods/botnet strong 0.93–0.99;
   benign-overlapping recon/brute-force weak ~0.70–0.80) — same story as the paper.
3. Absolute discrimination for the strong classes is in the paper's ballpark (AUC 0.93–0.99).

Caveats a reviewer will raise (state them proactively):
- **Tenko no longer uniformly beats Kitsune** (2/6 on CICIoT2023 vs 9/9 on the Kitsune dataset); on
  pure volumetric floods per-packet Kitsune is already near-ceiling and aggregation adds little.
- **The committed η=50/20 is degenerate on CICIoT2023** (flags nothing); η had to be re-derived from
  benign data per-deployment. This matches the paper's "η is a per-deployment benign multiplier"
  framing but shows the *specific* published η values do not transfer across datasets.
- **Operating-point FPR does not transfer out-of-sample** on this non-stationary benign trace (held-out
  FPR ≈0% or ≈30% vs a 5% target) — already documented; report CICIoT2023 via AUC/EER.
- **CICIoT2023 here is a 6-attack PILOT** (150k benign lead-in + 30k benign test + 50k/attack), not the
  full dataset; EER is uniformly higher than the Kitsune-dataset (harder benign regime).

**Recommendation:** report CICIoT2023 as a generalization result headlined by AUC/EER (full-trace
Table Y), explicitly (i) crediting the MITM/Mirai node-aggregation wins, (ii) conceding floods are
Kitsune-competitive by design, (iii) explaining the OS-Scan/recon gap as a traffic-character
difference, and (iv) carrying the per-deployment-η and in-sample-FPR caveats already drafted. This is
defensible and on-message; do not claim uniform superiority over Kitsune on CICIoT2023.

## Source key
- Paper Kitsune-ds absolute metrics: transcript `tab:best_weighted_performance`.
- Paper Kitsune-ds AUC/EER: transcript `tab:kitsune-tenko-new-highlighted`.
- N-BaIoT: transcript (commented-out `tabular`, per-device).
- CIC-IDS2018: absent from manuscript (Evaluation Setup lists Kitsune/N-BaIoT/Mateen only).
- CICIoT2023 AUC/EER + operating point: `results/CICIoT2023/ciciot2023_per_class_metrics.csv`.
- CICIoT2023 η=50/20 degeneracy: `results/CICIoT2023/ciciot2023_committedEta_double.csv`.
- OOS FPR non-transfer: `results/CICIoT2023/ciciot2023_metrics_recalibrated_oos.csv`.
