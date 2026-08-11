# CICIoT2023 — Single-tanh + Reduced Benign Split + Tolerance Grid-Search

*Repo:* `/Users/sbhola/Desktop/Tenko` (branch `correct-latency`). Every number below is
computed from actual runs / cached arrays and is reproducible with the scripts named
inline. Honesty note is enforced throughout: operating points that use attack labels are
labelled **ORACLE**; benign-only operating points use **no** attack labels.

## Scripts (all under `results/CICIoT2023/`)
- `_st_nd_ranges.py` — TASK 1: single-vs-double nd ranges + committed-η firing (original split, cached arrays).
- `_rerun_reduced.py` — re-runs Tenko X2–X4 (single-tanh) at the reduced split `benignLimit=60000` on **cached raw RMSEs**; writes `arr_{gold,ndg,nds,node,cont}_<attack>_s60k.npy`.
- `_analyze_reduced.py` — TASK 3–5: benign-only calibration, committed-η, ORACLE grid-search, transfer; writes `ciciot2023_singletanh_gridsearch_metrics.csv`.
- `_compare_old_new.py` — old 150k-lead vs reduced, AUC, benign non-stationarity.
- `_committed_reduced.py` — committed η=50/20 by benign window under the reduced split.
- `build_streams_ciciot2023_reduced.sh` — documented reduced stream layout (copy; originals intact).

### Why re-indexing on cached RMSEs == physically rebuilding shorter streams
KitNET freezes after grace (`KitNET/KitNET.py:61`: once `n_trained > FM+AD grace` it only
`execute`s, no weight update). So a benign packet's raw RMSE is **order-independent
post-grace** — it depends only on the frozen model (trained on the same first 55,000
benign packets) and that packet's own features. Tenko's node/pattern models freeze at
`benignLimit`. Therefore re-running X2 with a smaller `benignLimit` on the cached
`rmse_raw_<attack>.npy` produces byte-identical per-packet scores to physically rebuilding
a shorter PCAP stream; a shorter rebuild is just a truncation of the longer run. This let
us avoid re-running the slow X1 (KitNET). `build_streams_ciciot2023_reduced.sh` is provided
for provenance if a physical rebuild is ever preferred.

---

## 1. Single-tanh nd ranges vs double + does committed η fire? (`_st_nd_ranges.py`)

Original split (`benignLimit=150000`; test = 30k benign_test + 50k attack). nd is
η-independent (base = `tol/tol_factor` = mean benign spread); the binary rule fires iff
`nd_g > η_global` **OR** `nd_s > η_node`.

**Correction to the background brief.** The "attack nd tops out ~2.4" figure refers ONLY
to the **single-aggregate channel `nd_s`**. The **global channel `nd_g`** already has large
dynamic range under *both* tanh modes (attack nd_g max ≈ 42 double / ≈ 50 single). The
double-tanh degeneracy is not "nd ≪ η everywhere": it is that η_global=50 sits just *above*
the attack nd_g max (~44) **and** η_node=20 is ~5× the nd_s max (~3.7), so both channels
miss.

| Channel | benign (single) p50 / p99 / max | attack nd max: double → single | uplift |
|---|---|---|---|
| nd_g (global) | 0.487 / 44.294 / 46.654 | DoS-SYN 44.68 → 52.76 | ×1.18 |
| nd_g | — | DDoS 43.30 → 50.75 | ×1.17 |
| nd_g | — | Recon 42.29 → 49.34 | ×1.17 |
| nd_g | — | MITM 43.89 → 51.93 | ×1.18 |
| nd_g | — | Mirai 42.14 → 48.71 | ×1.16 |
| nd_g | — | Dict 45.06 → 53.29 | ×1.18 |
| nd_s (single-agg) | benign max 3.386 (dbl 3.185) | attack max ≈ 2.8–4.2 (dbl 2.5–3.7) | ×1.09–1.13 |

**Does single-tanh raise attack nd?** Yes — uniformly, but modestly: **+16–18% on nd_g**
and **+9–13% on nd_s**.

**Does committed η=50/20 fire under single?** (fused OR, original split)

| Attack | double TPR/FPR | single TPR/FPR |
|---|---|---|
| DoS-SYN_Flood | 0.000 / 0.000 (degenerate) | **0.715** / 0.000 |
| DDoS-UDP_Flood | 0.000 / 0.000 | 0.060 / 0.000 |
| MITM-ArpSpoofing | 0.000 / 0.000 | 0.0008 / 0.000 |
| DictionaryBruteForce | 0.000 / 0.000 | 0.015 / 0.000 |
| Recon-OSScan | 0.000 / 0.000 | 0.000 / 0.000 (still degenerate) |
| Mirai-greeth_flood | 0.000 / 0.000 | 0.000 / 0.000 (still degenerate) |

**Verdict on the theory:** *partially* confirmed. Single-tanh does restore some high-end
range and lifts committed η=50/20 off the floor for 4/6 attacks — but only because the
+17% pushes the *top tail* of attack nd_g just past 50. η_global=50 is still essentially at
the ceiling of the benign nd_g distribution (benign max 46.65), so it catches only the most
extreme attack packets (real TPR ≈ 0.72 for DoS-SYN, ≤0.06 for the rest). η_node=20 never
fires (nd_s max ≈ 4). **The committed 20/50 remains a bad operating point under single-tanh
at the original split; the degeneracy fix is recalibrating η, not switching tanh.**

---

## 2. Rationalized / reduced benign split (final, documented)

KitNET grace is FMgrace 5,000 + ADgrace 50,000 = **55,000** minimum training; we keep it.
Tenko pattern training is `[55001 : benignLimit]`, which must be non-empty, so the lead-in
is set to **60,000** (55,000 KitNET + 4,999 Tenko pattern training). Exact 0-based index
map (identical for all 6 attacks):

| Region | Index range | Size | Role |
|---|---|---|---|
| KitNET training (FM 5k + AD 50k) | `[0 : 55000]` | 55,000 | frozen at 55,001 |
| Tenko pattern-model training | `[55001 : 60000]` | 4,999 | `benignLimit = 60000` |
| η calibration slice | `[60000 : 65000]` | 5,000 | η selection ONLY (disjoint from eval) |
| benign eval / FPR negatives | `[65000 : 124000]` | 59,000 | headline FPR |
| *(extra benign — robustness only)* | `[124000 : 180000]` | 56,000 | beyond the reduced stream |
| attack (TPR positives) | `[180000 : 230000]` | 50,000 | class-1 |

The **reduced stream** proper is 55k+5k+5k+59k+50k = **174,000** packets. The extra benign
`[124000:180000]` is not part of the reduced stream (it only exists because we re-ran the
full 230k cached array); it is reported separately as an out-of-window robustness probe.

**Effect of reducing pattern training to ~5k:** the normalization base (mean benign spread)
shrinks, so nd inflates ≈10×. Reduced-split benign `nd_g`: p50 1.982, **p99 407.9, max
513.0**; benign `nd_s` max 32.57. Attack nd_g max 535–586. This rescaling is why fixed η
values behave completely differently than at the 150k split (see §3).

---

## 3. Tolerance selection — benign-only vs grid-search (`_analyze_reduced.py`)

Evaluated on **eval benign = 59,000** and **attack = 50,000** (reduced split, single-tanh).
Class balance = 50,000 attack : 59,000 benign (≈ 45.9% / 54.1%) — **Accuracy is reported
against this balance and is sensitive to it (flagged).**

### (a) Honest, benign-only operating points (NO attack labels)

| Method | η_global | η_node | mean TPR | mean FPR (eval) | mean Prec | mean F1 | mean Acc |
|---|---|---|---|---|---|---|---|
| committed η=50/20 (fixed) | 50.0 | 20.0 | 0.764 | **0.0083** | 0.983 | 0.822 | 0.887 |
| benign_calib @1% (q on calib slice) | 6.457 | 1.284 | 0.989 | 0.130 | 0.866 | 0.923 | 0.925 |
| benign_calib @5% | 5.447 | 0.442 | 0.995 | 0.202 | 0.807 | 0.891 | 0.889 |

- The benign-only η are **identical across all 6 attacks** (they depend only on benign) —
  i.e. **trivially stable across attacks**. Instability is *temporal* (across benign
  windows), not across attacks.
- **The quantile-based benign calibration badly overshoots FPR** (targets 1%/5%, delivers
  13%/20% on the disjoint eval). Root cause: the 5k calib slice `[60000:65000]` sits in the
  *quietest* early benign window (see §4), so the quantile η is far too small for later
  benign. **The fixed committed η=50/20 transfers much better (0.83% eval FPR)** — not
  because it is principled, but because the ~10× nd inflation from the small training window
  happens to place 50/20 in a sensible spot.

### (b) Grid-search ORACLE — **USES ATTACK LABELS (supervised upper bound)**

Sweep η_global × η_node over pooled test quantiles; pick max-F1 (Youden's J gives the same
pick here). **This selects η using attack-region performance → it is an ORACLE / upper
bound, not a deployable benign-only result.**

| Attack | η_global | η_node | TPR | FPR | Precision | F1 | Accuracy |
|---|---|---|---|---|---|---|---|
| DoS-SYN_Flood | 94.6 | 9.74 | 0.984 | 0.0013 | 0.998 | 0.991 | 0.992 |
| DDoS-UDP_Flood | 27.6 | 9.03 | 0.947 | 0.0139 | 0.983 | 0.965 | 0.968 |
| Recon-OSScan | 119.9 | 1.32 | 0.968 | 0.0423 | 0.951 | 0.959 | 0.962 |
| MITM-ArpSpoofing | 114.9 | 3.95 | 0.989 | 0.0088 | 0.990 | 0.989 | 0.990 |
| Mirai-greeth_flood | 27.8 | 6.37 | 0.981 | 0.0151 | 0.982 | 0.981 | 0.983 |
| DictionaryBruteForce | 215.8 | 1.25 | 0.982 | 0.0456 | 0.948 | 0.965 | 0.967 |
| **mean** | — | — | **0.975** | **0.021** | **0.975** | **0.975** | **0.977** |

- ORACLE η are **highly unstable across attacks** (η_global 27.6 → 215.8), precisely because
  they are tuned per-attack against labels. This is the colleague's fallback: strong
  numbers, but not honestly deployable.

---

## 4. False-positive / FPR analysis (`_analyze_reduced.py`, `_committed_reduced.py`, `_compare_old_new.py`)

### FPR transfer under the reduced split (η fixed from calib slice → disjoint windows)
Same for every attack (benign is shared):

| Operating point | calib `[60–65k]` | eval `[65–124k]` | extra `[124–180k]` |
|---|---|---|---|
| benign_calib @1% | 0.010 | **0.130** | **0.355** |
| benign_calib @5% | 0.050 | **0.202** | **0.560** |
| committed η=50/20 | 0.000 | **0.0083** | 0.109 |

### Why it doesn't transfer — benign non-stationarity (reduced, `nd_g` by 20k window)

| Stream window | p50 | p90 | p99 | max | frac > 6.457 |
|---|---|---|---|---|---|
| `[60000:80000]` (calib is here) | 1.57 | 3.60 | 8.98 | 10.6 | 0.032 |
| `[80000:100000]` | 1.89 | 5.23 | 19.6 | 111.7 | 0.087 |
| `[100000:120000]` | 2.03 | 11.83 | 69.4 | 111.8 | 0.168 |
| `[120000:140000]` | 1.96 | 10.90 | 78.6 | 94.6 | 0.136 |
| `[140000:160000]` **(burst)** | 2.39 | 171.4 | **490.4** | **513.0** | **0.374** |
| `[160000:180000]` | 1.98 | 14.64 | 180.5 | 404.2 | 0.153 |

The benign trace is strongly non-stationary: a large benign burst around stream
`[140000:160000]` drives 37% of packets above the @1% η. The 5k calib slice sits in the
quietest region, so any quantile calibrated there under-estimates η.

### Comparison to the old 150k-lead setup
Old benign_test (`[150000:180000]`) contains the documented **"CDN burst"** at
`[155000:160000]` (nd_g p50 13.4, max 46.7) surrounded by quiet windows (p50 ≈ 0.47). Honest
calibration on old data (calib = first 5k of benign_test, eval = next 25k):

| | old 150k-lead (single) | reduced 60k-lead (single) |
|---|---|---|
| benign_calib @1% → eval FPR | **0.243** (24.3%) | 0.130 (in-window) / 0.355 (extra) |
| committed η=50/20 → eval FPR | 0.000 (degenerate, TPR≈0–0.72) | **0.0083** (non-degenerate, strong TPR) |
| fused AUC (benign_test + attack) | 0.708–0.988 | **0.883–0.994** (all benign) / 0.936–0.996 (eval) |

**Does reducing benign training help or hurt FPR stability?** It does **not fix** the
transfer problem — both setups miss the 1%/5% target on held-out benign, because the cause
is the non-stationary benign trace (bursts), not the training size or the tanh. It does two
things: (i) it inflates the nd scale so the *fixed* committed η=50/20 becomes a usable,
non-degenerate, low-FPR (0.83% in-window) operating point (whereas the quantile calibration
gets *worse*, overshooting to 13%); (ii) the reduced-window separability (AUC) is
comparable-to-higher than the old setup. **The FPR still does not transfer across the burst
(extra-window FPR 11–56%).**

---

## 5. Final metrics table (single-tanh + reduced split)

CSV: `ciciot2023_singletanh_gridsearch_metrics.csv` (30 rows = 6 attacks × 5 methods).
Eval benign = 59,000; attack = 50,000. **Class balance ≈ 45.9% attack / 54.1% benign —
Accuracy is computed as `(TPR·n_atk + (1−FPR)·n_benign)/(n_atk+n_benign)` against this
balance and would change under a different balance (flagged).**

### Honest benign-only operating point — **committed η=50/20** (best transferring honest OP)

| Attack | TPR | FPR | Precision | F1 | Accuracy |
|---|---|---|---|---|---|
| DoS-SYN_Flood | 0.987 | 0.0083 | 0.990 | 0.989 | 0.990 |
| MITM-ArpSpoofing | 0.971 | 0.0083 | 0.990 | 0.981 | 0.982 |
| Mirai-greeth_flood | 0.951 | 0.0083 | 0.990 | 0.970 | 0.973 |
| DDoS-UDP_Flood | 0.920 | 0.0083 | 0.990 | 0.953 | 0.959 |
| Recon-OSScan | 0.554 | 0.0083 | 0.983 | 0.708 | 0.791 |
| DictionaryBruteForce | 0.201 | 0.0083 | 0.954 | 0.332 | 0.629 |
| **mean** | **0.764** | **0.0083** | 0.983 | 0.822 | 0.887 |

### Honest benign-only operating point — **benign_calib @1%** (quantile on calib slice)

| Attack | TPR | FPR | Precision | F1 | Accuracy |
|---|---|---|---|---|---|
| MITM-ArpSpoofing | 0.998 | 0.130 | 0.867 | 0.928 | 0.929 |
| Mirai-greeth_flood | 0.995 | 0.130 | 0.867 | 0.927 | 0.928 |
| DoS-SYN_Flood | 0.995 | 0.130 | 0.867 | 0.926 | 0.927 |
| DictionaryBruteForce | 0.993 | 0.130 | 0.866 | 0.925 | 0.927 |
| Recon-OSScan | 0.980 | 0.130 | 0.865 | 0.919 | 0.921 |
| DDoS-UDP_Flood | 0.970 | 0.130 | 0.864 | 0.914 | 0.916 |
| **mean** | **0.989** | **0.130** | 0.866 | 0.923 | 0.925 |

### Grid-search **ORACLE** (max-F1) — **USES ATTACK LABELS (upper bound, not deployable)**

| Attack | η_g | η_s | TPR | FPR | Precision | F1 | Accuracy |
|---|---|---|---|---|---|---|---|
| DoS-SYN_Flood | 94.6 | 9.74 | 0.984 | 0.0013 | 0.998 | 0.991 | 0.992 |
| MITM-ArpSpoofing | 114.9 | 3.95 | 0.989 | 0.0088 | 0.990 | 0.989 | 0.990 |
| Mirai-greeth_flood | 27.8 | 6.37 | 0.981 | 0.0151 | 0.982 | 0.981 | 0.983 |
| DDoS-UDP_Flood | 27.6 | 9.03 | 0.947 | 0.0139 | 0.983 | 0.965 | 0.968 |
| DictionaryBruteForce | 215.8 | 1.25 | 0.982 | 0.0456 | 0.948 | 0.965 | 0.967 |
| Recon-OSScan | 119.9 | 1.32 | 0.968 | 0.0423 | 0.951 | 0.959 | 0.962 |
| **mean** | — | — | **0.975** | **0.021** | 0.975 | 0.975 | 0.977 |

Note: the ORACLE FPR (mean 2.1%) is measured on the *eval* window and would still degrade on
the burst window like every other fixed-η operating point.

---

## 6. Verdict & recommendation

**(i) Does single-tanh bring nd into a usable range?** Only marginally, and the premise was
partly mis-stated. `nd_g` (global) was *already* in a large usable range (~42) under
double-tanh; single-tanh adds +16–18% (to ~50). `nd_s` (single-aggregate) is compressed in
both (~2.5–4.2) and single adds only +9–13%. At the original 150k split, single-tanh lifts
the committed 20/50 off the floor for 4/6 attacks but at poor TPR — it does **not** by itself
make 20/50 a good operating point. The tanh choice is second-order; the operating point is
what matters.

**(ii) Does grid-search / benign calibration give stable, non-degenerate η?** Non-degenerate:
yes, both do. Stable **across attacks**: benign-only η are identical across attacks
(benign-derived); ORACLE η are wildly unstable (27.6→215.8) because they are label-tuned.
Stable **across time** (the real problem): **no** — no fixed η transfers across the benign
burst. The quantile benign-calibration is actively *fragile* here because the calib slice is
unrepresentatively quiet (targets 1%, delivers 13%).

**(iii) Did reduced benign training hurt anything?** It did not hurt separability (AUC
comparable-to-higher: 0.883–0.994 vs old 0.708–0.988) and it did not hurt the *fixed*-η
operating point (committed 50/20 becomes non-degenerate at 0.83% in-window FPR with strong
TPR on the four sustained attacks). It **does** inflate the nd scale ≈10× (small base) and
makes quantile-on-a-short-slice calibration unreliable, and it does not fix FPR transfer
across the burst.

**(iv) Is FPR controlled and does it transfer?** Controlled *within* the reduced test window
for the fixed committed η (0.83%). It does **not transfer** across the benign burst
(extra-window 11–56%). This is a property of the non-stationary CICIoT2023 benign trace and
is unchanged by the split size or tanh mode.

### Recommendation for the paper
- **Adopt single-tanh** for CICIoT2023 reporting (redundant second tanh removed): it is at
  least as good on every metric and simplifies the normalization story (AUC change ≤ 0.011,
  consistent with prior `ciciot2023_tanh_impact.csv`).
- **Headline threshold-independent AUC/EER** (they are stable: reduced fused AUC 0.883–0.994),
  and present operating points with **explicit label-usage tags**:
  - honest benign-only OP = **fixed committed η=50/20 under the reduced split** (mean F1
    0.822, in-window FPR 0.83%, strong on the four sustained attacks), clearly noting its
    good scaling is a consequence of the reduced training window, not a principled derivation;
  - **ORACLE grid-search** (mean F1 0.975) explicitly labelled as a **supervised upper bound
    that uses attack labels**.
- **Do NOT present benign-quantile-calibrated η as a tight-FPR deployable point** on this
  trace: it overshoots (13–20% eval FPR) because the benign trace is non-stationary. Keep the
  honest caveat that **FPR does not transfer across the benign burst**.
- The **reduced split is acceptable** (equal/better separability, non-degenerate fixed η,
  10× faster to compute) but should be reported *with* the nd-scale-inflation caveat and the
  non-transfer caveat; it is not a fix for the FPR-transfer problem.

### What was and wasn't run
- **Run:** single-tanh Tenko X2–X4 re-executed at `benignLimit=60000` for all 6 attacks on
  cached raw RMSEs (`_rerun_reduced.py`, 6×≈20s); all offline analyses on the resulting
  arrays. Single/double nd ranges use the previously cached arrays.
- **Not physically run:** the reduced PCAP rebuild (`build_streams_ciciot2023_reduced.sh`) —
  provably equivalent to the re-index (KitNET frozen post-grace), so it was not necessary to
  re-extract PCAPs / re-run the slow X1. Original streams, labels, and committed CSVs are
  untouched.
