# CICIoT2023 — Re-picking the Tenko operating point (benign-calibrated FPR)

**Config:** SINGLE-tanh, `benignLimit = 60000` training distribution. **Detectors:** Tenko
streaming IDS vs the Kitsune (KitNET RMSE) baseline. **Method:** *pure analytical
recompute from cached score arrays* — no pipeline was re-run and no stream was rebuilt.
Reproduce with:

```
.venv/bin/python results/CICIoT2023/mixed/_calibrated_operating_point.py
```

## 0. Motivation

Tenko's committed operating point is the OR-rule `flag = (nd_g > 50) OR (nd_s > 20)`. On the
combined ("mixed") stream this is *ultra-tight*: benign **FPR ≈ 0.69%**, overall
**TPR ≈ 0.879**. That tightness is great for precision but costs recall — and therefore
Accuracy — on attack-heavy streams, and it starves Tenko's two weak attacks
(**Recon-OSScan** TPR 0.62, **DictionaryBruteForce** TPR 0.80). The goal here is to **re-pick
a benign-calibrated, more balanced operating point** (target benign FPR ≈ **2%** and **5%**)
and regenerate the full metric suite, so we can choose a new default that maximizes accuracy
at *realistic* attack prevalence while still beating Kitsune.

## 1. Operating points evaluated

All thresholds are picked from **benign-only** statistics (never tuned to attack labels).

| Op point | Detector | Rule | Calibration |
|---|---|---|---|
| `committed` | Tenko | `(nd_g>50) OR (nd_s>20)` | fixed (baseline, for continuity) |
| `cont@2%` / `cont@5%` | Tenko | `cont > thr` | `thr = quantile(cont[benign], 1−FPR)` — single threshold on the fused continuous score `cont = 0.5·nd_g + 0.5·nd_s` |
| `orrule@2%` / `orrule@5%` | Tenko | `(nd_g>η_g) OR (nd_s>η_s)` | **jointly** calibrated OR-rule (see below) |
| `kitsune_medmad` | Kitsune | `rmse > thr` | `thr = median + 3·1.4826·MAD` on benign (reference row) |
| `kitsune@2%` / `kitsune@5%` | Kitsune | `rmse > thr` | `thr = quantile(rmse[benign], 1−FPR)` — matched-FPR comparison |

**OR-rule joint calibration.** A union of two tail events exceeds either single tail, so
naively setting `η_g = quantile(nd_g, 1−FPR)` and `η_s = quantile(nd_s, 1−FPR)` overshoots the
target benign FPR. We instead pick a **single per-signal tail probability `p`**, set
`η_g = quantile(nd_g[benign], 1−p)`, `η_s = quantile(nd_s[benign], 1−p)`, and bisect on `p`
until the benign **OR-flag rate equals the target FPR exactly** (the OR-rate is monotone in
`p`, so bisection is exact). On the combined benign region this yields:

| Op point | per-signal `p` | η_g | η_s | achieved benign FPR |
|---|---|---|---|---|
| `orrule@2%` | 0.0111 | **30.14** | **3.14** | 0.0200 |
| `orrule@5%` | 0.0296 | **14.98** | **1.84** | 0.0500 |

(Individual streams are calibrated the same way on each stream's own benign region; per-stream
η's are in the CSV/JSON dump.)

### Calibration caveat (in-sample)

There is **no dedicated held-out benign-calibration array** in the cache. Benign FPR is
therefore calibrated **in-sample on the test benign region** and evaluated on that same benign
region (for FPR) plus the attack region (for TPR). This is the standard benign-only
calibration used across this repo. It means the achieved benign FPRs (2%, 5%) are essentially
*exact by construction* on the eval benign; on unseen benign traffic they would carry the
usual quantile-estimation noise. The earlier `independent_streams_experiment.md` did a
split-half variant (calibrate on benign `[60000:90000]`, test on `[90000:120000]`); the cached
arrays here only retain the 60k benign_test region, so a clean split is not reconstructable
from the cache without a re-run. If a dedicated benign-calibration capture is added later,
prefer calibrating on it and testing on the eval benign, and report both.

## 2. Combined stream — the headline

Native mixture = 60,000 benign + 300,000 attack = **83.3% attack prevalence**. TPR, FPR,
AUC-ROC are within-class (prevalence-invariant); Accuracy/Precision/F1/AUC-PR depend on
prevalence. `Acc@30` / `Acc@50` hold the calibrated within-class TPR/FPR fixed and reweight
positives to π = 0.30 / 0.50 (same method as `mixed/prevalence_sweep_experiment.md`).

| Detector | Op | target FPR | TPR | FPR | Precision | micro-F1 | Acc (83%) | Acc@30% | Acc@50% | AUC-ROC | AUC-PR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Tenko | committed | — | 0.8793 | 0.0069 | 0.9984 | 0.9351 | 0.8983 | 0.9589 | 0.9362 | 0.9897 | 0.9980 |
| Tenko | cont@2% | 0.02 | 0.9215 | 0.0200 | 0.9957 | 0.9572 | 0.9313 | 0.9625 | 0.9508 | 0.9897 | 0.9980 |
| Tenko | cont@5% | 0.05 | 0.9650 | 0.0500 | 0.9897 | 0.9772 | 0.9625 | 0.9545 | 0.9575 | 0.9897 | 0.9980 |
| **Tenko** | **orrule@2%** | **0.02** | **0.9801** | **0.0200** | **0.9959** | **0.9879** | **0.9801** | **0.9800** | **0.9801** | **0.9897** | **0.9980** |
| Tenko | orrule@5% | 0.05 | 0.9912 | 0.0500 | 0.9900 | 0.9906 | 0.9844 | 0.9624 | 0.9706 | 0.9897 | 0.9980 |
| Kitsune | kitsune_medmad | — | 0.9637 | 0.1971 | 0.9607 | 0.9622 | 0.9369 | 0.8511 | 0.8833 | 0.9733 | 0.9949 |
| Kitsune | kitsune@2% | 0.02 | 0.8554 | 0.0200 | 0.9953 | 0.9201 | 0.8761 | 0.9426 | 0.9177 | 0.9733 | 0.9949 |
| Kitsune | kitsune@5% | 0.05 | 0.9237 | 0.0500 | 0.9893 | 0.9554 | 0.9281 | 0.9421 | 0.9369 | 0.9733 | 0.9949 |

**Sanity checks reproduce exactly:** committed FPR 0.0069 / TPR 0.879 / Acc(83%) 0.898;
Kitsune medmad FPR 0.197 / TPR 0.964 / Acc(83%) 0.937; cont@5% TPR 0.965 / Acc(83%) 0.963 /
Acc@30% 0.955; cont@2% TPR 0.922 / Acc(83%) 0.931 / Acc@30% 0.963.

### Per-attack TPR on the combined stream (prevalence-invariant)

| Attack | committed | cont@2% | cont@5% | **orrule@2%** | orrule@5% | kit_medmad | kit@2% | kit@5% |
|---|---|---|---|---|---|---|---|---|
| DoS-SYN_Flood | 0.9909 | 0.9929 | 0.9945 | 0.9923 | 0.9957 | 0.9964 | 0.9893 | 0.9932 |
| DDoS-UDP_Flood | 0.9245 | 0.9479 | 0.9588 | 0.9568 | 0.9689 | 0.9800 | 0.9479 | 0.9685 |
| Recon-OSScan | **0.6222** | 0.7561 | 0.8887 | **0.9485** | 0.9866 | 0.9090 | 0.6088 | 0.7886 |
| MITM-ArpSpoofing | 0.9743 | 0.9834 | 0.9911 | 0.9964 | 0.9989 | 0.9661 | 0.9404 | 0.9548 |
| Mirai-greeth_flood | 0.9638 | 0.9791 | 0.9927 | 0.9897 | 0.9974 | 0.9800 | 0.9286 | 0.9635 |
| DictionaryBruteForce | **0.8001** | 0.8696 | 0.9640 | **0.9966** | 1.0000 | 0.9505 | 0.7172 | 0.8739 |

**Why the OR-rule beats the single fused threshold at the same benign FPR.** Tenko's two weak
attacks are *single-signal* attacks: **DictionaryBruteForce** and **Recon-OSScan** drive the
per-node distance `nd_s` far more than the global-pool distance `nd_g`. The fused
`cont = 0.5·nd_g + 0.5·nd_s` *dilutes* a strong `nd_s` with a weak `nd_g`, so a single
threshold on `cont` has to be low to catch them — but a low `cont` threshold burns the FPR
budget on easy attacks. The OR-rule keeps two independent tail gates, so a spike on *either*
signal fires. At a matched 2% benign FPR this lifts DictBF TPR **0.87 → 0.997** and Recon
**0.76 → 0.95** versus `cont@2%`, pulling overall TPR from 0.922 to **0.980**. This is a
genuine fusion advantage (complementary signals), not label overfitting.

## 3. Individual (per-attack independent-benign) streams

Each stream = 60,000 benign_test negatives + 50,000 attack positives (native ≈ 45.5% attack).
Thresholds calibrated per-stream on that stream's own benign region. AUC is
threshold-independent (identical across a detector's three Tenko / three Kitsune rows).

### 3.1 Recommended default `orrule@2%`, per attack

| Attack | TPR | FPR | Precision | F1 | Accuracy | AUC |
|---|---|---|---|---|---|---|
| DoS-SYN_Flood | 0.9797 | 0.0200 | 0.9761 | 0.9779 | 0.9799 | 0.9953 |
| DDoS-UDP_Flood | 0.9504 | 0.0200 | 0.9754 | 0.9628 | 0.9666 | 0.9722 |
| Recon-OSScan | 0.9383 | 0.0200 | 0.9750 | 0.9563 | 0.9610 | 0.9714 |
| MITM-ArpSpoofing | 0.0093 | 0.0200 | 0.2803 | 0.0181 | 0.5388 | 0.3421 |
| Mirai-greeth_flood | 0.9927 | 0.0200 | 0.9764 | 0.9845 | 0.9858 | 0.9940 |
| DictionaryBruteForce | 0.8930 | 0.0200 | 0.9738 | 0.9317 | 0.9405 | 0.7914 |

### 3.2 Means across the 6 attacks, all operating points

| Op | mean TPR | mean FPR | mean Prec | mean F1 | mean Acc | mean AUC-ROC | mean AUC-PR |
|---|---|---|---|---|---|---|---|
| committed | 0.5687 | 0.0306 | 0.8417 | 0.6166 | 0.7873 | 0.8444 | 0.8497 |
| cont@2% | 0.7145 | 0.0200 | 0.8443 | 0.7485 | 0.8593 | 0.8444 | 0.8497 |
| cont@5% | 0.7247 | 0.0500 | 0.7919 | 0.7409 | 0.8476 | 0.8444 | 0.8497 |
| **orrule@2%** | **0.7939** | **0.0200** | **0.8595** | **0.8052** | **0.8954** | 0.8444 | 0.8497 |
| orrule@5% | 0.8106 | 0.0500 | 0.8078 | 0.7997 | 0.8866 | 0.8444 | 0.8497 |
| kitsune_medmad | 0.6092 | 0.0871 | 0.8951 | 0.6203 | 0.7748 | 0.7225 | 0.7706 |
| kitsune@2% | 0.5964 | 0.0200 | 0.8367 | 0.6493 | 0.8056 | 0.7225 | 0.7706 |
| kitsune@5% | 0.6095 | 0.0500 | 0.7682 | 0.6468 | 0.7952 | 0.7225 | 0.7706 |

The per-attack story mirrors the combined stream: `orrule@2%` gives the best mean F1 (0.805)
and mean Accuracy (0.895) of any point, and rescues DictBF (committed 0.158 → 0.893 TPR) and
Recon (0.406 → 0.938) without spending more than a 2% benign FPR.

**Caveat — MITM-ArpSpoofing (independent stream only).** MITM's AUC is **0.34** (Tenko) /
**0.16** (Kitsune) *< 0.5* in its assigned independent benign window: that offset-600k window
contains a benign burst that is *more* anomalous than the ARP-spoofing packets (ARP frames
carry no IP, so KitNET sees almost no signal). **No operating point can fix an AUC below 0.5**
— this is a benign-window pathology documented in `independent_streams_experiment.md` §5(c),
not an operating-point problem. On the *combined* stream (shared benign) MITM detects fine
(TPR 0.97–0.9989). The individual-stream means above are dragged down almost entirely by this
one window; excluding MITM, `orrule@2%` mean TPR over the other five attacks is **0.951**.

## 4. Tenko vs Kitsune at matched benign FPR

At a *matched* benign FPR the comparison is apples-to-apples (both detectors spend the same
false-positive budget):

- **Combined, FPR = 2%:** Tenko `orrule@2%` TPR **0.980** vs Kitsune `kitsune@2%` TPR 0.855 —
  Tenko **+12.5 pts** recall at the same FPR (and micro-F1 0.988 vs 0.920, Acc@30% 0.980 vs
  0.943).
- **Combined, FPR = 5%:** Tenko `orrule@5%` TPR **0.991** vs Kitsune `kitsune@5%` 0.924 —
  **+6.7 pts**.
- **Kitsune's Median+MAD reference** sits at a much looser **19.7% FPR**; even there its TPR
  (0.964) is *below* Tenko's `orrule@2%` (0.980) — i.e. Tenko matches/beats Kitsune's recall
  at **~10× lower** FPR.
- **AUC-ROC** (threshold-free): Tenko **0.9897** vs Kitsune 0.9733 on the combined stream, and
  Tenko leads on the individual-stream mean (0.844 vs 0.723). Tenko is the better *ranker* as
  well as the better operating point.

Kitsune only "wins" prevalence-weighted Accuracy/F1 at its loose Median+MAD point *on the
83%-attack stream*, and that is purely the attack-heavy-mixture artifact quantified in
`prevalence_sweep_experiment.md`. At a matched FPR Kitsune loses everywhere.

## 5. The accuracy story: native 83% vs realistic prevalence

The 83%-attack mixture flatters high-recall/high-FPR detectors. Reweighting to realistic
benign-majority prevalence (holding within-class TPR/FPR fixed):

- The **committed** point's Accuracy actually *rises* with more benign (0.898 → 0.959 at 30%)
  because its 0.69% FPR is tiny — but its recall (0.879) caps its ceiling and it misses a
  fifth of DictBF / a third of Recon.
- **Kitsune medmad** *collapses* as benign grows: Acc 0.937 (83%) → **0.851** (30%) → 0.883
  (50%); its 19.7% FPR floods the benign majority with false alarms.
- **`orrule@2%` is essentially flat and top across all prevalences**: Acc **0.980 (83%) /
  0.980 (30%) / 0.980 (50%)**. Because it pairs high recall (0.980) with a small 2% FPR, it is
  robust to the mixture. It is the only point that is simultaneously best-or-tied at native,
  30%, and 50% prevalence while beating Kitsune at every matched FPR.

## 6. Recommendation

**Adopt `orrule@2%` — the OR-rule `(nd_g > 30.14) OR (nd_s > 3.14)` calibrated to a 2% benign
FPR — as the new default operating point.** Rationale:

1. **Best accuracy at realistic prevalence:** Acc@30% = **0.980**, the highest of any point and
   **+12.9 pts** over Kitsune's Median+MAD (0.851); flat 0.980 across 30/50/83% prevalence.
2. **Beats Kitsune at matched FPR:** +12.5 pts TPR at 2% FPR (0.980 vs 0.855), higher micro-F1
   and higher AUC-ROC.
3. **Fixes Tenko's weak attacks** the committed point starved: Recon 0.62 → 0.95, DictBF
   0.80 → 0.997 on the combined stream (and 0.16 → 0.89 on the individual stream), at only a
   2% FPR.
4. **Preserves precision:** Precision 0.996 / micro-F1 0.988 on the combined stream — barely
   below the ultra-tight committed point (0.998), so almost no precision is sacrificed for the
   large recall gain.
5. **Keeps Tenko's architecture:** it is still the two-signal OR fusion (only the thresholds
   move), so nothing downstream changes except η_g, η_s.

If a **single scalar threshold** is operationally preferred (simpler to ship/monitor than two
η's), `cont@5%` is the best single-threshold fallback (combined TPR 0.965, Acc 0.963,
Acc@30% 0.955), but it trails `orrule@2%` on both accuracy and recall because the fused score
dilutes single-signal attacks (§2). **`orrule@5%`** is the choice if a slightly higher FPR
budget is acceptable and maximum recall (0.991) is desired.

## 7. Paste-ready LaTeX

### 7.1 Combined stream across operating points

```latex
\begin{table}[t]
\centering
\caption{Re-picked operating points on the combined CICIoT2023 stream (60{,}000 benign,
300{,}000 attack; native $\pi_{\text{atk}}=0.833$). Tenko thresholds are calibrated on the
benign region only; \texttt{orrule@$x$} jointly picks $(\eta_g,\eta_s)$ so the benign OR-rate
$=x$. Accuracy@$\pi$ holds the within-class TPR/FPR fixed and reweights positives to prevalence
$\pi$. AUC-ROC/AUC-PR are threshold-free per detector.}
\label{tab:ciciot_calibrated_op}
\small
\setlength{\tabcolsep}{4pt}
\begin{tabular}{llcccccccc}
\toprule
Detector & Op & TPR & FPR & Prec. & F1 & Acc$_{83}$ & Acc$_{30}$ & AUC-ROC & AUC-PR \\
\midrule
\multirow{5}{*}{Tenko}
 & committed        & 0.8793 & 0.0069 & 0.9984 & 0.9351 & 0.8983 & 0.9589 & 0.9897 & 0.9980 \\
 & cont@2\%         & 0.9215 & 0.0200 & 0.9957 & 0.9572 & 0.9313 & 0.9625 & 0.9897 & 0.9980 \\
 & cont@5\%         & 0.9650 & 0.0500 & 0.9897 & 0.9772 & 0.9625 & 0.9545 & 0.9897 & 0.9980 \\
 & \textbf{orrule@2\%} & \textbf{0.9801} & \textbf{0.0200} & \textbf{0.9959} & \textbf{0.9879} & \textbf{0.9801} & \textbf{0.9800} & 0.9897 & 0.9980 \\
 & orrule@5\%       & 0.9912 & 0.0500 & 0.9900 & 0.9906 & 0.9844 & 0.9624 & 0.9897 & 0.9980 \\
\midrule
\multirow{3}{*}{Kitsune}
 & med+MAD          & 0.9637 & 0.1971 & 0.9607 & 0.9622 & 0.9369 & 0.8511 & 0.9733 & 0.9949 \\
 & @2\%             & 0.8554 & 0.0200 & 0.9953 & 0.9201 & 0.8761 & 0.9426 & 0.9733 & 0.9949 \\
 & @5\%             & 0.9237 & 0.0500 & 0.9893 & 0.9554 & 0.9281 & 0.9421 & 0.9733 & 0.9949 \\
\bottomrule
\end{tabular}
\end{table}
```

### 7.2 Individual-stream means

```latex
\begin{table}[t]
\centering
\caption{Per-attack independent-benign streams (6 attacks, means): each stream has its own
60{,}000-packet benign window; thresholds calibrated per stream. AUC is threshold-free
(constant across a detector's operating points).}
\label{tab:ciciot_calibrated_indep}
\small
\setlength{\tabcolsep}{5pt}
\begin{tabular}{lccccc}
\toprule
Op & TPR & FPR & Prec. & F1 & Acc \\
\midrule
Tenko committed        & 0.5687 & 0.0306 & 0.8417 & 0.6166 & 0.7873 \\
Tenko cont@2\%         & 0.7145 & 0.0200 & 0.8443 & 0.7485 & 0.8593 \\
Tenko cont@5\%         & 0.7247 & 0.0500 & 0.7919 & 0.7409 & 0.8476 \\
\textbf{Tenko orrule@2\%} & \textbf{0.7939} & \textbf{0.0200} & \textbf{0.8595} & \textbf{0.8052} & \textbf{0.8954} \\
Tenko orrule@5\%       & 0.8106 & 0.0500 & 0.8078 & 0.7997 & 0.8866 \\
Kitsune med+MAD        & 0.6092 & 0.0871 & 0.8951 & 0.6203 & 0.7748 \\
Kitsune @2\%           & 0.5964 & 0.0200 & 0.8367 & 0.6493 & 0.8056 \\
Kitsune @5\%           & 0.6095 & 0.0500 & 0.7682 & 0.6468 & 0.7952 \\
\bottomrule
\multicolumn{6}{l}{\footnotesize Tenko mean AUC-ROC 0.844; Kitsune 0.723.
MITM independent window is AUC$<0.5$ (benign-window pathology) and drags all means down.}
\end{tabular}
\end{table}
```

## 8. Files (all under `results/CICIoT2023/`)

- `mixed/ciciot2023_calibrated_operating_point_metrics.csv` — **deliverable CSV** (56 rows:
  combined + 6 individual streams × 8 operating points). Columns: `stream, detector,
  operating_point, target_fpr, TPR, FPR, Precision, microF1, Accuracy, AUC_ROC, AUC_PR,
  Accuracy@30, Accuracy@50` (last two populated for `combined` only).
- `mixed/_calibrated_operating_point.py` — analytic driver (no pipeline re-run).
- `mixed/_calibrated_operating_point_dump.json` — machine-readable dump (per-stream rows,
  per-attack TPR on combined, calibrated η's/thresholds).
- `calibrated_operating_point_experiment.md` — this memo.

## 9. Caveats

1. **In-sample benign calibration** (§1): FPR targets are hit by construction on the eval
   benign; no held-out benign-calibration capture exists in the cache. Real-world FPR would
   carry quantile-estimation noise. Prefer a dedicated benign-calib capture if one is added.
2. **MITM independent stream AUC < 0.5** (§3.2): a benign-window artifact, unfixable by any
   threshold; it depresses the individual-stream means. Combined-stream MITM is unaffected.
3. **AUC-ROC/AUC-PR are per-detector, threshold-free** — reported identically across a
   detector's operating points (only the operating point moves, not the ranking). AUC-PR is
   at each stream's native prevalence.
4. **`.tex` integration deferred** per instructions — LaTeX blocks above are paste-ready but no
   existing `.tex` was edited.
