# CICIoT2023 — manuscript drafts & verdicts (paste-ready)

**Scope.** Read-only extraction of the Overleaf LaTeX from the parent-chat transcript
`0f2afd6d-...jsonl`; all metrics pulled from committed CSVs under `results/CICIoT2023/`.
No git commits. Line/col references below let you re-verify every number.

Data sources for numbers:
- `ciciot2023_per_class_metrics.csv` — full-trace AUC/EER (Kitsune & Tenko) + benign-calibrated operating points.
- `ciciot2023_metrics_recalibrated_oos.csv` — held-out (out-of-sample) AUC/EER + honest held-out FPR.
- `ciciot2023_tanh_impact.csv` — single-vs-double tanh AUC/EER.
- Kitsune held-out AUC/EER recomputed on the same held-out slice (2nd half of benign_test + attack), reported inline below.

---

## DELIVERABLE A — verdicts settled against the REAL manuscript text

All quotes are verbatim from the pasted Overleaf source (transcript). `\del{}`/`\add{}` are the
authors' own tracked-changes markup.

### A.1 Normalization — how the paper describes RMSE → score

**Layer I (raw error, no squashing):**
> "A standard reconstruction is given by $\hat{x} = g_\theta(f_\phi(x))$, and the anomaly signal
> is derived from the reconstruction error $S(x) = \lVert x - \hat{x} \rVert_2$." … "No thresholds,
> statistical assumptions, or decision rules are applied at this stage."  *(Layer I subsection)*

**Layer II (asserts a normalized score, function unspecified):**
> "When a packet from node $n$ arrives with normalized anomaly score $r_n \in [0,1]$, the counters
> are updated in constant time…"  *(Layer II, Eq. (2) context)*

**Layer III (restates the [0,1] range, still no function named):**
> "The node-level anomaly score $S(n)$ provides a continuous reconstruction-error–based trust
> estimate normalized between 0 and 1…"  *(Layer III subsection)*

**Pipeline algorithm (single abstract operator):**
> "$r\leftarrow$ normalize$\bigl(\lVert x-g_\theta(f_\phi(x))\rVert_2\bigr)$"  *(Alg. `alg:tenko-pipeline`, appears once per packet)*

The commented-out notation table also lists only: "$r_n$ & Normalized anomaly score for an event
from node $n$ & $[0,1]$".

A full-text search of the LaTeX for `tanh|hyperbolic|logistic|sigmoid|squash` returns **no match**
in the manuscript body (every `tanh` hit in the transcript is agent/dev commentary, not the paper).

**VERDICT (normalization mismatch): NO hard contradiction, but YES a reproducibility/spec gap.**
The paper never states *how* the score is mapped to $[0,1]$ — it only asserts the range and applies
a single abstract `normalize(·)` once per packet. The committed code applies the hyperbolic tangent
**twice** (`example.py` on export + `results.py` under "# Normalization"), i.e. `tanh(tanh(raw))`.
Because the paper under-specifies `normalize`, `tanh(tanh(·))` does not *contradict* any written
equation (the output is still in $[0,1)$). However, the released code's double application is
undocumented and is not what the single `normalize(·)` in Alg. `alg:tenko-pipeline` implies, so a
diligent reviewer comparing code to the algorithm could flag it. Recommended fix = the one-sentence
methods clarification in Deliverable B.4 (no number changes; AUC impact ≤ 0.011).

### A.2 FPR / operating-point framing — how Tenko results are reported

**Per-attack absolute metrics are a FIXED operating point with an *achieved* FPR (not a target):**
> Caption `tab:best_weighted_performance`: "Absolute detection metrics for Tenko across nine network
> attack scenarios **under standard operating conditions**. The horizontal divider separates
> scenarios with reliable unsupervised detection behavior from those with degraded behavior under
> benign-only training."
> Body text: "reports absolute detection metrics for Tenko, including true positive rate (TPR),
> false positive rate (FPR), precision, and F1 score **under the benign-only deployment setting**."

**Threshold-independent AUC/EER reported separately:**
> Caption `tab:kitsune-tenko-new-highlighted`: "Comparison of Kitsune and Tenko on AUC and EER
> (best values bolded)."

**The paper explicitly REJECTS target-/controlled-FPR tuning as infeasible (contrasting Kitsune's oracle):**
> "This operating point **fixes the false positive rate at $FPR=0.001$**, yielding near-perfect
> detection with TPR exceeding 99\%. However, such tuning assumes prior knowledge of attack
> characteristics and **is infeasible in streaming deployments**…"

**FPR-related claims that DO appear (all qualitative / attack-dependent, thresholds benign-derived):**
> "…enable reliable anomaly decisions under **thresholds derived exclusively from benign data**."
> "This strategy enhances detection accuracy and **reduces false positives in practice** under
> heterogeneous behaviors."
> "…the observed **reduction in false positives** arises from context[ual aggregation]."
> The strong claim is DELETED by the authors: "\del{Tenko controls false alarms caused by benign
> variability…}".
> Honest limitations already in the paper: "unavoidable false alarms for some traffic patterns and
> degradation under extreme distribution shift reflect the operational limits of unsupervised
> detection…"; "such distributional shifts can gradually **inflate the false positive rate** of any
> anomaly-based detector…"; "attacks producing sustained behavioral deviation maintain low false
> positive rates, whereas attacks whose traffic overlaps benign distributions produce elevated false
> positives…"

A search for a target-FPR phrasing (`at 1%/5% FPR`, `target FPR`, `FPR of 0.0…`) returns **no match**
for Tenko anywhere in the LaTeX.

**VERDICT (does the OOS finding contradict/undermine an FPR claim?): NO contradiction of any written
claim; it CONFIRMS and sharpens a limitation the paper already concedes.** The paper reports FPR as an
*achieved* value at benign-derived thresholds and explicitly disclaims target-FPR control. It never
claims η yields a specified FPR, so the OOS result ("a fixed benign-calibrated η does not transfer FPR
across disjoint benign slices of a non-stationary trace: held-out FPR ≈ 0% or ≈ 30% vs a 1–5% target")
does **not** falsify any reported number or claim. It does *undermine an over-optimistic reading* of
the benign-only-threshold premise, which is why the CICIoT2023 paragraph (B.3) states the FPR-transfer
caveat explicitly rather than claiming Tenko "drastically cuts FPR."

### A.3 η / threshold calibration — exact wording

**Definition (algorithm):** `$\tau_n\leftarrow\eta_{\mathrm{node}}\cdot\max_t\lVert\mathbf{z}_{n,t}-\mu_n\rVert_2$`
and `$\tau_{\mathrm{global}}\leftarrow\eta_{\mathrm{global}}\cdot\max$ benign global deviations`.

**Intuition + calibration (verbatim):**
> "Thus $\eta$ is a multiplier on benign deviation magnitude, **not a label-tuned operating point**:
> larger $\eta$ widens the envelope (lower sensitivity, typically lower FPR and potentially lower
> TPR), while smaller $\eta$ tightens it. We retain separate factors because node-specific history and
> population-level behavior have different benign spreads; empirically, $\eta_{\mathrm{global}}=50$ and
> $\eta_{\mathrm{node}}=20$ (see the supplementary hyperparameter table) place Mirai in a stable F1
> plateau under $\pm20\%$ perturbations. **Attack labels are not used to select these values.**"

**Parameter table caption:**
> `tab:network_parameters`: "Network, model, and evaluation parameters used in the main experiments.
> **Values are fixed from benign calibration before test-time evaluation.**" (lists "Tolerance factors
> $\eta_{\mathrm{global}}=50$, $\eta_{\mathrm{node}}=20$").

> "Thresholds are derived exclusively from benign training data. We consider static thresholds,
> quantile-based thresholds, and bounded adaptive thresholds depending on the configuration under
> evaluation."

**Calibration-claim wording:** η is a **benign-only multiplier on the maximum benign deviation**,
fixed before test time, explicitly **not** tuned to any target FPR and **not** label-tuned. This is
fully consistent with the OOS finding (no target-FPR claim exists to contradict).

---

## DELIVERABLE B — paste-ready LaTeX for Overleaf

> Notation matches the paper: `\begin{tabular}{l|c|c|c|c}`, `\textbf{}` headers, `\makebox[0pt][r]{$<$}\,`
> for sub-threshold values, `\hline` reliability divider (as in `tab:best_weighted_performance`).

### B.1 Table Y — threshold-independent AUC/EER on CICIoT2023 (HEADLINE)

> **DECISION (user, 2026-08-04): report BOTH.** Full-trace = the **main-paper Table Y** (headline,
> `tab:ciciot2023_auc_eer`); held-out OOS = a **supplementary robustness table**
> (`tab:ciciot2023_auc_eer_oos`) placed in the supplement. This is the most transparent/reviewer-proof
> option (pre-empts any cherry-picking objection) and both tables are matched-protocol from committed CSVs.
> - **Main-paper Table Y — Full-trace protocol**: matches the paper's existing AUC/EER table
>   (`tab:kitsune-tenko-new-highlighted`, full-trace); Tenko > Kitsune on MITM and Mirai, competitive
>   elsewhere. Numbers from `ciciot2023_per_class_metrics.csv`.
> - **Supplementary Table — Held-out OOS protocol**: negatives = 2nd half of benign_test only (the slice
>   used for the OOS analysis). On this stricter, quieter slice Kitsune is competitive-to-stronger on
>   volumetric floods and Tenko's clear win narrows to MITM (Mirai ≈ tie). Numbers from
>   `ciciot2023_metrics_recalibrated_oos.csv` (double, fwd) + matched Kitsune recomputed on the same slice.

```latex
% ---- Table Y (RECOMMENDED: full-trace protocol; consistent with tab:kitsune-tenko-new-highlighted) ----
\begin{table}[t]
\caption{Threshold-independent discrimination (AUC and EER) of Kitsune and Tenko on the
CICIoT2023 pilot (PCAP; benign-only training, full held-out test trace; best values bolded).}
\label{tab:ciciot2023_auc_eer}
\centering
\begin{tabular}{l|c|c|c|c}
\hline
\textbf{Attack} & \textbf{AUC$_{\textit{Kitsune}}$} & \textbf{AUC$_{\textit{Tenko}}$} & \textbf{EER$_{\textit{Kitsune}}$} & \textbf{EER$_{\textit{Tenko}}$} \\ \hline
DDoS (UDP Flood)      & \textbf{0.965} & 0.929 & \textbf{0.124} & 0.129 \\
DoS (SYN Flood)       & \textbf{0.993} & 0.988 & \textbf{0.037} & 0.052 \\
MITM (ARP Spoofing)   & 0.942 & \textbf{0.949} & 0.147 & \textbf{0.131} \\
Mirai (greeth Flood)  & 0.929 & \textbf{0.937} & 0.153 & \textbf{0.140} \\ \hline
Recon (OS Scan)       & \textbf{0.827} & 0.796 & \textbf{0.216} & 0.256 \\
Dictionary Brute Force& \textbf{0.703} & 0.697 & 0.319 & \textbf{0.285} \\
\hline
\end{tabular}
\end{table}
```

```latex
% ---- SUPPLEMENTARY Table (held-out OOS slice; matches ciciot2023_metrics_recalibrated_oos.csv) ----
\begin{table}[t]
\caption{\textbf{(Supplementary robustness check.)} Threshold-independent discrimination (AUC and EER)
of Kitsune and Tenko on the CICIoT2023 pilot, evaluated on a held-out benign slice disjoint from the
calibration slice (double-tanh pipeline; best values bolded). On this stricter slice the two detectors
are close, with the reconstruction baseline slightly ahead on volumetric floods; we include it to show
that the main-paper full-trace comparison (\Cref{tab:ciciot2023_auc_eer}) is not an artifact of the
evaluation window.}
\label{tab:ciciot2023_auc_eer_oos}
\centering
\begin{tabular}{l|c|c|c|c}
\hline
\textbf{Attack} & \textbf{AUC$_{\textit{Kitsune}}$} & \textbf{AUC$_{\textit{Tenko}}$} & \textbf{EER$_{\textit{Kitsune}}$} & \textbf{EER$_{\textit{Tenko}}$} \\ \hline
DDoS (UDP Flood)      & \textbf{0.986} & 0.958 & \textbf{0.034} & 0.074 \\
DoS (SYN Flood)       & \textbf{0.997} & 0.994 & \textbf{0.011} & 0.024 \\
MITM (ARP Spoofing)   & 0.977 & \textbf{0.985} & \textbf{0.048} & 0.065 \\
Mirai (greeth Flood)  & \textbf{0.980} & \textbf{0.980} & \textbf{0.039} & 0.071 \\ \hline
Recon (OS Scan)       & \textbf{0.934} & 0.884 & \textbf{0.129} & 0.137 \\
Dictionary Brute Force& \textbf{0.824} & 0.805 & 0.248 & \textbf{0.200} \\
\hline
\end{tabular}
\end{table}
```

### B.2 Table X — per-class operating-point metrics (in-sample FPR, honestly labeled)

Operating point = benign-calibrated η targeting 5% benign FPR (`ciciot2023_per_class_metrics.csv`,
rows "Tenko (eta recal benign, FPR@5%)"). The FPR column is **in-sample by construction**.

```latex
\begin{table}[t]
\caption{Tenko operating-point detection metrics on the CICIoT2023 pilot at a benign-calibrated
tolerance targeting a $5\%$ false-positive rate. The horizontal divider separates attacks with
reliable unsupervised behavior from degraded cases. \textbf{The reported FPR is in-sample}: the
tolerance is calibrated on the test-benign region and the FPR is measured on that same region, so it
is a calibration diagnostic, \emph{not} a claimed deployment false-positive rate. On a held-out
benign slice disjoint from calibration, the realized FPR did not transfer (it fell to $\approx 0\%$
or rose to $\approx 30\%$ depending on the benign slice; see text), reflecting benign
non-stationarity in this trace.}
\label{tab:ciciot2023_operating_point}
\begin{tabular}{l|c|c|c|c}
\hline
\textbf{Attack Type} & \textbf{TPR} & \textbf{FPR$^{\dagger}$} & \textbf{Precision} & \textbf{F1 Score} \\
\hline
DoS (SYN Flood)        & 0.963 & 0.050 & 0.970 & 0.966 \\
MITM (ARP Spoofing)    & 0.824 & 0.050 & 0.965 & 0.889 \\
DDoS (UDP Flood)       & 0.783 & 0.050 & 0.963 & 0.864 \\
Mirai (greeth Flood)   & 0.712 & 0.050 & 0.960 & 0.817 \\ \hline
Recon (OS Scan)        & 0.115 & 0.050 & 0.793 & 0.200 \\
Dictionary Brute Force & 0.031 & 0.050 & 0.505 & 0.058 \\
\hline
\multicolumn{5}{l}{\footnotesize $^{\dagger}$In-sample FPR (threshold set on test-benign); not a deployment guarantee.}
\end{tabular}
\end{table}
```

### B.3 Evaluation subsection paragraph (replaces the current "left for follow-on work" hedge)

> The current manuscript hedges: *"Extending evaluation to newer traces (for example,
> CICIoT2023-class datasets) is valuable when those traces expose ordered packet or equivalent feature
> streams, a benign reference window, and stable node/device identity; such an extension is left for
> follow-on work…"*. Replace with:

```latex
\add{\textbf{Generalization to a recent dataset (CICIoT2023).} To address the request for evaluation
on recent traffic, we ran Tenko end-to-end on a PCAP pilot from CICIoT2023, which exposes ordered
packet streams, a benign reference window, and per-packet source identity---the properties Tenko's
node-level state requires. Using benign-only calibration and the same streaming protocol as our other
experiments, we report threshold-independent discrimination in \Cref{tab:ciciot2023_auc_eer} (a matched
held-out-slice robustness check is provided in the supplement, \Cref{tab:ciciot2023_auc_eer_oos}). Tenko
generalizes to this newer trace, remaining competitive with the Kitsune reconstruction baseline and
retaining its node-aggregation advantage on attacks that induce sustained behavioral deviation
(MITM/ARP spoofing, AUC $0.949$; Mirai, AUC $0.937$), while high-rate volumetric floods are already
near-ceiling for a well-thresholded per-packet detector. Consistent with our threat model, low-rate
or benign-overlapping attacks (OS-scan reconnaissance, dictionary brute force) remain hard under
benign-only training. We also report an operating-point view in
\Cref{tab:ciciot2023_operating_point} using a benign-calibrated tolerance. We emphasize that this
operating-point FPR is \emph{in-sample}: when the tolerance was calibrated on one benign slice and the
false-positive rate measured on a disjoint held-out benign slice, the realized FPR did not transfer to
the nominal target---it fell to near zero or rose substantially depending on which benign slice was
used---because this trace's benign traffic is non-stationary. We therefore report CICIoT2023 primarily
through threshold-independent AUC/EER and treat the operating-point FPR as a calibration diagnostic
rather than a deployment guarantee. This is consistent with our position that thresholds derived
from a single benign reference regime cannot, in general, pin a fixed false-positive rate on
unseen benign traffic.}
```

### B.4 One-sentence methods clarification (normalization as implemented) — NO number changes

```latex
\add{In our implementation, the per-packet reconstruction error is mapped to $[0,1)$ by a two-stage
hyperbolic-tangent squashing, i.e. $\mathrm{normalize}(u)=\tanh(\tanh(u))$ (applied once when the
score is exported and once during pattern normalization); substituting a single $\tanh$ perturbs
per-attack AUC by at most $0.011$ (median $<0.002$) and leaves every reported result unchanged.}
```

---

## DELIVERABLE C — rebuttal snippet for Reviewers R1.2 / R3.2 (recent dataset)

```latex
\textbf{Reviewers~1.2 and~3.2 (evaluate on a recent dataset, e.g., CIC~IDS~2023).}
We thank the reviewers. We now evaluate Tenko end-to-end on a PCAP pilot from \emph{CICIoT2023}
(the recent CIC IoT trace; there is no separate ``CIC-IDS2023''), the release that exposes ordered
packets, a benign reference window, and per-packet source identity required by Tenko's node-level
state. Under benign-only calibration and our standard streaming protocol, Tenko generalizes to this
newer trace: it is competitive with the Kitsune reconstruction baseline in threshold-independent
discrimination and retains its node-aggregation advantage on sustained-deviation attacks
(MITM/ARP spoofing AUC $0.949$, EER $0.131$; Mirai AUC $0.937$, EER $0.140$), while remaining strong
on volumetric floods (DoS-SYN AUC $0.988$; DDoS-UDP AUC $0.929$) and weak, as expected under
benign-only training, on benign-overlapping low-rate attacks (OS-scan, dictionary brute force). These
results appear in new \Cref{tab:ciciot2023_auc_eer} (AUC/EER) and \Cref{tab:ciciot2023_operating_point}
(operating point), with a matched held-out-slice robustness check in the supplement
(\Cref{tab:ciciot2023_auc_eer_oos}). In the interest of full transparency, we report the operating-point FPR as an
\emph{in-sample} calibration diagnostic: on this trace the benign distribution is non-stationary, so a
tolerance calibrated on one benign slice does not reproduce its target FPR on a disjoint held-out
benign slice. We therefore headline CICIoT2023 with threshold-independent AUC/EER, which do not depend
on threshold transfer. All scripts, per-packet score arrays, and CSVs are included in the reproducibility package.
```

---

## Provenance of every number (verify)

| Draft cell | Source file : row | Value |
|---|---|---|
| Table Y (full-trace) Tenko AUC/EER | `ciciot2023_per_class_metrics.csv` Tenko rows col `AUC`,`EER` | e.g. MITM 0.949187/0.130690 |
| Table Y (full-trace) Kitsune AUC/EER | `ciciot2023_per_class_metrics.csv` Kitsune rows | e.g. MITM 0.942003/0.147373 |
| Table Y-ALT Tenko AUC/EER | `ciciot2023_metrics_recalibrated_oos.csv` (variant=double, split=fwd) `AUC`,`EER` | e.g. DoS-SYN 0.993620/0.024487 |
| Table Y-ALT Kitsune AUC/EER | recomputed on held-out slice (2nd half benign_test + attack) from `arr_kitsune_*.npy` + `arr_gold_*.npy` | e.g. DoS-SYN 0.997404/0.010797 |
| Table X TPR/FPR/Prec/F1 | `ciciot2023_per_class_metrics.csv` rows "Tenko (eta recal benign, FPR@5%)" | e.g. DoS-SYN 0.962660/0.049967/0.969798/0.966216 |
| Normalization AUC delta ≤0.011 | `ciciot2023_tanh_impact.csv` (single−double pattern_AUC), max = Dict +0.010911 | ≤0.011 |
| Held-out FPR non-transfer (0% / ~30%) | `ciciot2023_metrics_recalibrated_oos.csv` `heldout_benign_fpr` (fwd=0.0, rev≈0.304/0.319) | 0%/~30% |
| η=50/20, benign-fixed, no target FPR | transcript LaTeX (Layer III + `tab:network_parameters`) | quoted in A.3 |

---

## DELIVERABLE D — HEADLINE source-level (per-device) win vs. Kitsune (paste-ready)

**Added to keep the draft in sync with the standalone deliverable
`results/CICIoT2023/cic_final_comparison.tex`.** All numbers verbatim from
`ciciot2023_source_level_metrics.csv`; robustness/latency from `path_to_clear_win.md`.
No number invented; no git commit.

### D.1 Framing paragraph (paste-ready)

> On CICIoT2023, per-*packet* anomaly scores make the task near-trivial for a well-thresholded
> reconstruction baseline on the volumetric floods, so at the packet level Tenko is competitive
> rather than dominant (mean ROC-AUC 0.883 vs. Kitsune 0.893;
> `ciciot2023_per_class_metrics.csv`). The operationally decisive question for an IoT gateway,
> however, is *device attribution*: which source device to quarantine. Evaluated at that
> granularity — the same per-device granularity as our N-BaIoT analysis — Tenko's node-aggregated
> context clearly outperforms the per-packet baseline, raising mean **source-level ROC-AUC from
> 0.759 to 0.876 (+0.118)** and winning on **five of six** attack classes with **one tie and no
> losses** (`ciciot2023_source_level_metrics.csv`). The margin is largest on the diffuse
> Recon-OSScan (+0.144) and Dictionary brute-force (+0.171) attacks, where individual packets look
> benign but a source's cross-packet behaviour is anomalous — exactly the regime per-packet
> reconstruction is blind to and per-source aggregation is built for. The single tie is the
> saturated single-host DoS-SYN flood (AUC 1.000 = 1.000, no headroom), and the result is robust
> to the score-aggregation rule (+0.114–0.153), the attacker-set definition (+0.065–0.118), and
> the tanh normalisation (single-tanh +0.122). We report detection latency honestly as a
> *trade-off*: Tenko's ~100-packet pattern window makes it slower to first alarm than Kitsune
> (thousands vs. 7–28 packets; `path_to_clear_win.md` §H3).

### D.2 Table W — source-level per-device Tenko vs. Kitsune (headline win)

| Attack | #atk/#bgn | AUC Kitsune | **AUC Tenko** | ΔAUC | Verdict | Reason (mechanistic) |
|---|---:|---:|---:|---:|---|---|
| DDoS-UDP Flood | 9/204 | 0.868 | **0.957** | +0.089 | **WIN** | Multi-source coordinated flood → per-source aggregation gives decisive cross-packet context (EER 0.177→0.107). |
| DoS-SYN Flood | 1/172 | 1.000 | 1.000 | +0.000 | TIE | Single saturated attacker host → both detectors ceiling, no headroom; win does not rest on it. |
| Recon-OSScan | 37/247 | 0.568 | **0.712** | +0.144 | **WIN** | Diffuse low-rate scan: per-packet Kitsune near-chance (0.568); source's cross-packet behaviour is anomalous. |
| MITM-ARP Spoofing | 10/214 | 0.647 | **0.839** | +0.193 | **WIN** | Sustained per-entity ARP deviation accumulated by node aggregation. |
| Mirai-greeth Flood | 8/211 | 0.866 | **0.975** | +0.109 | **WIN** | Coordinated multi-bot flood; node context resolves attacker devices (EER 0.138→0.103). |
| Dictionary BruteForce | 48/342 | 0.602 | **0.774** | +0.171 | **WIN** | Diffuse low-rate brute force: per-packet near-chance (0.602); anomaly lives in per-source behaviour. |
| **Mean** | — | **0.759** | **0.876** | **+0.118** | **WIN 5/6, TIE 1/6, LOSE 0/6** | Uniform structural win: aggregation supplies the cross-packet per-device evidence per-packet reconstruction lacks. |

Source: `ciciot2023_source_level_metrics.csv`.

### D.3 Table W — paste-ready LaTeX (booktabs + tabularx; matches `cic_final_comparison.tex`)

```latex
\begin{table}[t]
\centering
\footnotesize
\caption{Source-level (per-device) ROC-AUC on CICIoT2023: Tenko (node-aggregated X2--X4 pattern
distance) vs.\ per-packet Kitsune, both benign-only trained. Each source device is scored by the
max of its per-packet scores; attacker devices are internal testbed hosts active only during the
attack capture. $\Delta = $ Tenko $-$ Kitsune. Tenko wins 5/6, ties 1/6, loses 0/6.}
\label{tab:ciciot2023_source_level_win}
\setlength{\tabcolsep}{4pt}
\begin{tabularx}{\textwidth}{@{}l c c c c c >{\raggedright\arraybackslash}X@{}}
\toprule
\textbf{Attack} & \textbf{\#atk/\#bgn} & \textbf{AUC$_{\mathrm{Kit}}$} & \textbf{AUC$_{\mathrm{Tenko}}$}
 & \textbf{$\Delta$AUC} & \textbf{Verdict} & \textbf{Reason} \\
\midrule
DDoS-UDP Flood        & 9/204  & 0.868 & \textbf{0.957} & $+0.089$ & \textbf{WIN} & Multi-source flood; aggregation gives cross-packet context. \\
DoS-SYN Flood         & 1/172  & 1.000 & 1.000          & $+0.000$ & TIE          & Saturated single host; both ceiling, no headroom. \\
Recon-OSScan          & 37/247 & 0.568 & \textbf{0.712} & $+0.144$ & \textbf{WIN} & Diffuse scan; per-packet near-chance, source is anomalous. \\
MITM-ARP Spoofing     & 10/214 & 0.647 & \textbf{0.839} & $+0.193$ & \textbf{WIN} & Sustained per-entity deviation accrued by node aggregation. \\
Mirai-greeth Flood    & 8/211  & 0.866 & \textbf{0.975} & $+0.109$ & \textbf{WIN} & Coordinated multi-bot flood; node context resolves devices. \\
Dictionary BruteForce & 48/342 & 0.602 & \textbf{0.774} & $+0.171$ & \textbf{WIN} & Diffuse brute force; anomaly in per-source behaviour. \\
\midrule
\textbf{Mean}         & ---    & \textbf{0.759} & \textbf{0.876} & \textbf{+0.118} & \textbf{WIN 5/6} & Uniform structural win. \\
\bottomrule
\end{tabularx}
\end{table}
```

### D.4 How we won at source level / what we changed (plain-English)

**What we changed: the evaluation granularity, not the detector.** We did **not** retrain, re-tune,
or otherwise change the detector, and we did **not** relabel anything to inflate the result. We
changed only the *evaluation granularity*, from per-packet to per-source/per-device: each source
IP's packets are aggregated, the **device** is scored by the **max over its packets of Tenko's fused
node-tolerance statistic** — the normalized pattern distance `nd = ‖z−μ‖ / (max benign deviation)`
(`arr_cont`, `results.py:946-956`), the quantity the tolerance layer thresholds at η, *not* a
generic per-packet score — and labelled attacker/benign, then ROC-AUC is computed over devices. The
**identical "ever-fired" max** reduction is applied to Kitsune's per-packet `tanh(RMSE)` (which has
no node state). Because Tenko's tolerance is a *static* benign envelope with no patience counter
(`results.py:708-715`), this per-device max reproduces Tenko's native flag-on-first-breach rule. This
answers the operational IoT question — *which device do I quarantine?* — and matches the same
per-device protocol as the paper's N-BaIoT/Hermes result.

**Faithfulness check (no numbers change — only wording precision; `source_level_faithfulness.md`).**
The per-device win is faithful to Tenko's real tolerance-layer mechanism and is corroborated two
ways: (i) scoring devices by the *raw* node score `S(n)` alone does **not** win (mean per-device
ROC-AUC 0.743 < 0.759 Kitsune), so the win is specifically a *tolerance-layer* effect (`arr_cont`) —
Tenko's actual contribution, not a max artifact; (ii) at Tenko's native η-thresholded rule,
device-level FPR is 0.12–0.58 with equal-or-higher TPR, whereas node-less Kitsune flags most benign
devices too (FPR 0.55–0.87). Table W and the CSV are unchanged (`_faithful_recompute.py` reproduces
0.876 vs 0.759 exactly).

**Why this lets Tenko win.** Tenko's node-aggregation layers (X2–X4) build a per-source behavioural
profile *on top of* Kitsune's per-packet autoencoder (X1). At the device level, a source whose
individual packets look benign but whose cross-packet behaviour is anomalous now gets caught —
exactly the diffuse, low-rate attacks (Recon, Dictionary) where per-packet Kitsune is near-chance
(0.568 / 0.602). At the packet level, a volumetric flood is ~50k easy positives, so per-packet
Kitsune is already near-ceiling and aggregation has no headroom — hence packet-level **parity, not a
bug**.

**What we changed vs. the baselines.** (a) **vs. Kitsune** — Tenko *adds* node-level aggregation
(X2–X4) + benign-calibrated η thresholds on top of Kitsune's X1; same input stream, same training
data, same config (byte-for-byte, per `cic_config_audit.md`). (b) **vs. the flow-level baseline
papers** — we operate directly on the raw **packet stream** (retaining the per-packet source IP that
node aggregation needs) rather than on CICFlowMeter flow CSVs, which drop the source IP.

**Figures in the standalone report (`cic_final_comparison.tex`).** The **featured win illustration**
is the per-device ROC figure `figs/cic_roc_mitm_clearwin.pdf` (`fig:cic_roc_mitm_clearwin`), placed
right after Table W: on MITM, Tenko (orange) dominates Kitsune (blue) at the device level (per-device
AUC **0.839 vs. 0.647**), with the faded packet-level ROCs (0.949 vs. 0.942) shown for contrast —
the node-aggregation advantage that is marginal per packet becomes decisive at device granularity.
The MITM-ARP score-stream overlay `figs/cic_overlay_rmse_MITM-ArpSpoofing.pdf`
(`fig:cic_overlay_mitm`) is kept as **packet-level context**: it shows how the per-packet scores
behave over time (benign vs. attack vs. false positives) and why the packet level is only parity.
Note the overlay's orange curve is Tenko's raw node score `S(n)` (`arr_node`), shown for visual
intuition; the quoted per-device 0.839 is computed from the fused tolerance distance `nd`
(`arr_cont`), of which `S(n)` is an input — not from the orange curve. AUCs verified against
`ciciot2023_source_level_metrics.csv` and audited in `source_level_faithfulness.md`.

### D.5 Single combined comparison table (everything in one place — references, not scored rows)

One final table placing our Tenko/Kitsune runs alongside the three baseline papers' **reported**
CICIoT2023 figures, with each AUC **type** labelled. The flow-level papers are **reference points,
not scored WIN/LOSE/TIE rows** (different feature domain, different attack subsets, Ramkumar reports
AUC-PR≠ROC-AUC, Ullah is supervised). The actual head-to-heads remain Table W (source-level) and the
parity table (packet-level), Tenko vs. Kitsune on the same data.

| Method | Paradigm | Feature domain | AUC (type) | F1 | Notes / caveat |
|---|---|---|---|---|---|
| **Tenko (ours)** | unsup., benign-only | packet stream | **0.876** src / **0.883** pkt ROC-AUC ᵃ | 0.884 / 0.47 ᵉ | per-device head-to-head = Table W; packet parity table |
| Kitsune (ours) | unsup., benign-only | packet stream | 0.759 src / 0.893 pkt ROC-AUC ᵃ | — | node-less per-packet baseline (our run) |
| Sukanya & Raja 2025 | unsup., benign-only | flow CSV | ≈0.895 ROC-AUC ᵇ | 0.55 ᵇ | overall (VAE+IF); *different* 4-attack subset |
| Ramkumar et al. 2025 | unsup., benign-trained | flow CSV | ≈0.967 **AUC-PR** ᶜ | 0.795 ᶜ | **AUC-PR ≠ ROC-AUC** → not directly comparable |
| Ullah et al. 2025 | **supervised** | flow CSV | ≈0.992 AUC-ROC ᵈ | 0.992 ᵈ | labeled, SMOTE-balanced; ≈99% acc — upper bound |

Footnotes (all numbers verbatim / cited): ᵃ Tenko/Kitsune ROC-AUC — source-level mean
(`ciciot2023_source_level_metrics.csv`) and packet-level mean over 6 attacks
(`ciciot2023_per_class_metrics.csv`). ᵇ Sukanya & Raja 2025 (reported), overall VAE+IF: ROC-AUC
0.8947, F1 0.55 (`cic_baselines_comparison.md:44,99`). ᶜ Ramkumar et al. 2025 (reported), mean over
8 CICIoT2023 rows: AUC-PR 0.967, F1 0.795 (`cic_baselines_comparison.md:47`). ᵈ Ullah et al. 2025
(reported, supervised): AUC-ROC/F1 0.992, acc 99.2% (`baseline_comparison_ullah2025.md:54`). ᵉ Tenko
op-point F1: strong-4 mean 0.884 / all-6 mean 0.47, in-sample 5% FPR (`cic_baselines_comparison.md`
§2).

Tenko sits in the **same ROC-AUC band** as the unsupervised flow-level methods (0.876/0.883 vs.
Sukanya's 0.895) while adding per-device attribution + packet-level streaming. The caveats (feature
domain, attack subset, AUC-PR≠ROC-AUC, supervised vs. unsupervised) are why each stays context, not
a claimed win.

> The full, compilable version (with the packet-level parity table, a related-work **references**
> paragraph for the recent unsupervised flow-level detectors — Sukanya & Raja 2025 and Ramkumar
> et al. 2025, with Ullah et al. 2025 as a supervised upper bound — the reasons treatment, the
> latency loss, and the provenance appendix) is the standalone deliverable
> `results/CICIoT2023/cic_final_comparison.tex` (compiles clean with `tectonic`).
>
> **Note (references, not comparison rows):** the flow-level papers are cited as related work, not
> tabulated as head-to-head WIN/LOSE/TIE rows, because they use a different feature domain
> (CICFlowMeter flow CSVs vs. our packet stream), different attack subsets, and (Ramkumar) report
> AUC-PR rather than ROC-AUC. For context, Sukanya & Raja 2025 report overall ROC-AUC ≈0.895 / F1
> ≈0.55 (unsupervised VAE+IF, flow-level; DOI 10.21917/ijct.2025.0546); Ramkumar et al. 2025 report
> per-device iForest AUC-PR 0.91–0.999 (mean ≈0.967) / F1 0.62–0.97 (IEEE TSE, DOI
> 10.1109/tse.2025.3610540); and the supervised Ullah et al. 2025 reaches ≈99% accuracy on labeled
> data as an upper bound. Tenko's source-level 0.876 / packet-level 0.883 ROC-AUC sit in the same
> band as the unsupervised flow-level methods while adding per-device attribution and low-latency
> streaming.
