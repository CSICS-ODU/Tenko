# Attack-prevalence sweep on the mixed CICIoT2023 stream — Tenko vs Kitsune

**Goal.** The combined ("mixed") CICIoT2023 stream is attack-heavy: 300,000 attack
packets vs 60,000 benign = **83.3% attack prevalence**. That inflates
prevalence-dependent metrics (Accuracy, micro-F1) in favour of a high-recall /
high-FPR detector like Kitsune. This experiment sweeps the attack fraction
π ∈ {0.833, 0.50, 0.30, 0.10, 0.05} toward realistic benign-majority mixes and
shows **exactly which metrics move and which do not**, and at what prevalence
Tenko overtakes Kitsune.

Everything here is computed **analytically from cached score arrays** — no pipeline
was re-run. Reproduce with:

```
.venv/bin/python results/CICIoT2023/mixed/_prevalence_sweep.py
```

## Operating points (fixed, never tuned to labels)

- **Tenko committed η:** flag if `(nd_g > 50) OR (nd_s > 20)`.
  → benign **FPR = 0.006950 (417/60000)**, overall **TPR = 0.879303**. ✔ matches
  the committed sanity numbers exactly.
- **Kitsune:** benign-only Median+MAD threshold on the benign region `[0:60000]` of
  `kitsune_testscores_mixed`, `thr = median + 3·1.4826·MAD`
  (median = 0.004252, MAD = 1.2859e-03, **thr = 0.009971**). Flag `score > thr`.
  → benign **FPR = 0.197133 (11828/60000)**, overall **TPR = 0.963680**.

Stream layout was verified against `arr_gold_mixed`: benign `[0:60000]` all-0, then
six 50k attack blocks all-1, in order DoS-SYN, DDoS-UDP, Recon-OSScan, MITM-Arp,
Mirai-greeth, Dict-BruteForce.

## The invariance principle (why this sweep is honest)

TPR, FPR, and AUC-ROC are **within-class** quantities:

- **TPR** = TP / (all positives) — a rate *inside* the attack class.
- **FPR** = FP / (all negatives) — a rate *inside* the benign class.
- **AUC-ROC** integrates TPR against FPR — both within-class — so it too is
  prevalence-free.

None of these depend on how many attack vs benign packets you put in the stream.
Changing π only re-weights the *mixture*, not the per-class error rates. So the
**fixed within-class panel below is reported once** and applies at every π:

| Detector | FPR | TPR | AUC-ROC |
|---|---|---|---|
| **Tenko** (η 50/20) | **0.006950** (417/60000) | 0.879303 | **0.989682** |
| Kitsune (Median+MAD) | 0.197133 (11828/60000) | **0.963680** | 0.973251 |

**Per-attack TPR (also prevalence-invariant):**

| Attack | Tenko TPR | Kitsune TPR |
|---|---|---|
| DoS-SYN_Flood | 0.9909 | 0.9964 |
| DDoS-UDP_Flood | 0.9245 | 0.9800 |
| Recon-OSScan | **0.6222** | 0.9090 |
| MITM-ArpSpoofing | 0.9743 | 0.9661 |
| Mirai-greeth_flood | 0.9638 | 0.9800 |
| DictionaryBruteForce | **0.8001** | 0.9505 |

Tenko's weak spots are **Recon-OSScan** (low-rate scan, 0.62) and
**DictionaryBruteForce** (0.80); Kitsune keeps higher recall on these but pays for
it with a **28×** higher benign false-positive rate (0.197 vs 0.0069).

## What *does* move with prevalence

Accuracy, Precision, micro-F1, and AUC-PR are mixture quantities. Fixing each
detector's within-class confusion and reweighting the positive class to hit target
π (keep 60,000 benign negatives; set attack positives `P = round(60000·π/(1−π))`;
`TP = TPR·P`, `FN = P−TP`, `FP = FPR·60000`, `TN = 60000−FP`):

| Detector | π (attack) | TPR | FPR | Precision | micro-F1 | Accuracy | AUC-ROC | AUC-PR |
|---|---|---|---|---|---|---|---|---|
| Tenko   | 0.833 | 0.8793 | 0.0069 | 0.9984 | 0.9351 | 0.8983 | 0.9897 | 0.9980 |
| Kitsune | 0.833 | 0.9637 | 0.1971 | 0.9606 | 0.9621 | 0.9368 | 0.9733 | 0.9949 |
| Tenko   | 0.500 | 0.8793 | 0.0069 | 0.9922 | 0.9323 | 0.9362 | 0.9897 | 0.9920 |
| Kitsune | 0.500 | 0.9637 | 0.1971 | 0.8302 | 0.8920 | 0.8833 | 0.9733 | 0.9804 |
| Tenko   | 0.300 | 0.8793 | 0.0069 | 0.9819 | 0.9278 | 0.9589 | 0.9897 | 0.9847 |
| Kitsune | 0.300 | 0.9637 | 0.1971 | 0.6769 | 0.7952 | 0.8511 | 0.9733 | 0.9649 |
| Tenko   | 0.100 | 0.8793 | 0.0069 | 0.9336 | 0.9056 | 0.9817 | 0.9897 | 0.9624 |
| Kitsune | 0.100 | 0.9637 | 0.1971 | 0.3520 | 0.5156 | 0.8189 | 0.9733 | 0.9259 |
| Tenko   | 0.050 | 0.8793 | 0.0069 | 0.8694 | 0.8743 | 0.9874 | 0.9897 | 0.9423 |
| Kitsune | 0.050 | 0.9637 | 0.1971 | 0.2046 | 0.3376 | 0.8109 | 0.9733 | 0.8962 |

Reading the table:

- **AUC-ROC is flat** at 0.9897 (Tenko) / 0.9733 (Kitsune) across every π — the
  invariance check.
- **Precision, micro-F1, Accuracy collapse for Kitsune** as benign becomes the
  majority: its 19.7% FPR generates a flood of false positives that now outnumber
  the shrinking attack class. Kitsune Precision falls 0.96 → 0.20; micro-F1
  0.96 → 0.34 from π = 0.833 → 0.05.
- **Tenko stays high**: Precision 0.998 → 0.869, micro-F1 0.935 → 0.874, and its
  Accuracy *rises* to 0.987 as the easy benign majority grows against a 0.69% FPR.
- **AUC-PR** drops for both (it is prevalence-dependent) but Tenko stays above
  Kitsune at every π (0.998→0.942 vs 0.995→0.896).

## The crossover

At the native 83.3% attack prevalence, Kitsune's raw recall wins the
prevalence-weighted metrics (Accuracy 0.937 vs 0.898; micro-F1 0.962 vs 0.935).
Lowering the attack fraction flips this:

- **Tenko's Accuracy ≥ Kitsune's for attack prevalence ≤ 0.6926.**
- **Tenko's micro-F1 ≥ Kitsune's for attack prevalence ≤ 0.6638.**

So for **any realistic benign-majority mix (π ≤ 0.5), Tenko wins Accuracy,
Precision, micro-F1, and AUC-PR simultaneously**, while already leading on the two
prevalence-invariant discrimination metrics (AUC-ROC, and macro/per-class balance).
The 83% stream is the *only* regime where Kitsune's high-FPR operating point looks
competitive; it is an artifact of the attack-heavy mixture, not of better detection.

## Faithfulness note — how to physically realize a lower prevalence

The analytic reweighting above is valid **only because within-class TPR/FPR are
invariant to prevalence**, i.e. only if a lower-π stream is built without distorting
the per-class score distributions. The two honest ways to do that:

1. **Add more benign packets** (more negatives), or
2. **Uniformly subsample each attack block** — draw a random sample spanning the
   *whole* block, preserving each attack's onset/ramp-up/steady-state composition.

What is **not** allowed: truncating each attack block to its first N packets. We
already observed that truncating to the first 20–30k **lowers TPR**, because each
attack's false negatives are **front-loaded at the ramp-up** (the detector needs a
few packets before the pattern distance crosses η). Taking only the tail would be
the opposite cherry-pick — discarding attack onset to inflate TPR. Uniform
subsampling keeps the within-class TPR fixed, which is precisely the assumption that
makes the reweighted Accuracy/Precision/F1/AUC-PR numbers above exact rather than
approximate.

**AUC-PR method.** AUC-PR is computed analytically at each π: take `(fpr_t, tpr_t)`
at every threshold from `roc_curve` on the full pooled scores (recall = tpr_t), then
re-derive precision at the target prevalence as
`prec(π) = π·tpr_t / (π·tpr_t + (1−π)·fpr_t)`, and integrate precision over recall
average-precision style, `AP = Σ_k (R_k − R_{k−1})·P_k`. This reproduces the earlier
subsampling estimate (Tenko AUC-PR@5% = 0.9423 analytic vs 0.9431 ± 0.0032 over 20
random subsamples; Kitsune 0.8962 vs 0.8969 ± 0.0050), confirming the method.

## Paste-ready LaTeX table

```latex
\begin{table}[t]
\centering
\caption{Attack-prevalence sweep on the combined CICIoT2023 stream (60{,}000 benign
negatives, attack positives reweighted to target prevalence $\pi$). TPR, FPR and
AUC-ROC are \emph{within-class} and therefore invariant to $\pi$ (reported once);
Accuracy, Precision, micro-F1 and AUC-PR are prevalence-dependent. Tenko uses its
committed operating point $\eta$ (flag if $nd_g>50$ or $nd_s>20$); Kitsune uses a
benign-only Median+MAD threshold. Tenko overtakes Kitsune on Accuracy for
$\pi\le0.69$ and on micro-F1 for $\pi\le0.66$.}
\label{tab:ciciot_prevalence_sweep}
\small
\setlength{\tabcolsep}{4pt}
\begin{tabular}{llcccccc}
\toprule
Detector & $\pi_{\text{atk}}$ & Precision & micro-F1 & Accuracy & AUC-PR & TPR$^\dagger$ & FPR$^\dagger$ \\
\midrule
\multirow{5}{*}{Tenko}
 & 0.833 & 0.9984 & 0.9351 & 0.8983 & 0.9980 & \multirow{5}{*}{0.8793} & \multirow{5}{*}{0.0069} \\
 & 0.500 & 0.9922 & 0.9323 & 0.9362 & 0.9920 & & \\
 & 0.300 & 0.9819 & 0.9278 & 0.9589 & 0.9847 & & \\
 & 0.100 & 0.9336 & 0.9056 & 0.9817 & 0.9624 & & \\
 & 0.050 & 0.8694 & 0.8743 & 0.9874 & 0.9423 & & \\
\midrule
\multirow{5}{*}{Kitsune}
 & 0.833 & 0.9606 & 0.9621 & 0.9368 & 0.9949 & \multirow{5}{*}{0.9637} & \multirow{5}{*}{0.1971} \\
 & 0.500 & 0.8302 & 0.8920 & 0.8833 & 0.9804 & & \\
 & 0.300 & 0.6769 & 0.7952 & 0.8511 & 0.9649 & & \\
 & 0.100 & 0.3520 & 0.5156 & 0.8189 & 0.9259 & & \\
 & 0.050 & 0.2046 & 0.3376 & 0.8109 & 0.8962 & & \\
\bottomrule
\multicolumn{8}{l}{\footnotesize $^\dagger$Within-class, prevalence-invariant.
AUC-ROC (also invariant): Tenko 0.9897, Kitsune 0.9733.}
\end{tabular}
\end{table}
```

## Files (all under `results/CICIoT2023/mixed/`)

- `ciciot2023_prevalence_sweep_metrics.csv` — the sweep (columns: detector,
  attack_prevalence, TPR, FPR, Precision, microF1, Accuracy, AUC_ROC, AUC_PR).
- `_prevalence_sweep.py` — analytic driver (no pipeline re-run).
- `_prevalence_sweep_dump.json` — machine-readable dump of fixed rates + rows.
- `prevalence_sweep_experiment.md` — this memo.

## Discrepancy note

Kitsune's fixed FPR/TPR here (0.1971 / 0.9637) differ slightly from the main
`mixed_stream_experiment.md` aggregate (0.2136 / 0.9645). The difference is the
threshold-calibration window: this sweep follows the task spec and calibrates
Median+MAD on the **full benign region `[0:60000]`** (thr = 0.009971), whereas the
main run calibrated on the Tenko pattern-model window `[55001:60000]`
(thr = 0.009578). Both are benign-only calibrations; the wider window yields a
marginally higher threshold and slightly lower FPR. All qualitative conclusions
(invariance, collapse of Kitsune's prevalence-weighted metrics, crossover near
π ≈ 0.66–0.69) are unaffected.
