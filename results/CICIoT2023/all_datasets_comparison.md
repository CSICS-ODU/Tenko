# Unified cross-dataset comparison — Tenko across ALL datasets in the paper

Read-only build. Paper numbers extracted verbatim from the Overleaf LaTeX in the parent-chat
transcript `0f2afd6d-…jsonl`; CICIoT2023 numbers from committed CSVs under `results/CICIoT2023/`.
No git commits; no invented numbers. Every value cites its source.

---

## Step 1 — per-dataset inventory: what the paper actually reports for Tenko

| Dataset | In manuscript? | Granularity | Tenko metrics available | Baseline | Usable for AUC overview? |
|---|---|---|---|---|---|
| **Kitsune (Mirsky)** | Yes, **active** (`tab:kitsune-tenko-new-highlighted` + `tab:best_weighted_performance`) | per-attack (9 attacks) | **AUC/EER** (both) + TPR/FPR/Prec/F1 operating point | Kitsune | **Yes** — 9 AUC values |
| **CICIoT2023 (this work)** | New (committed CSVs) | per-attack (6 classes) | **AUC/EER** + operating point | Kitsune | **Yes** — 6 AUC values |
| **Kitsune combined-attack (Mateen-style shift stress)** | Yes, **active** (`tab:mateen_comparative_performance`) | single mixed-attack regime | Accuracy 0.9021, F1 0.6603, Macro-F1 0.8016, **AUC-ROC 0.6068** | INSOMNIA/OWAD/Mateen (reproduced from prior work) | **Partly** — 1 AUC-ROC value, different protocol |
| **N-BaIoT** | **Commented-out** table only (per-device Hermes vs Tenko) | per-device (9 devices) | Accuracy/TPR/Precision/F1/FPR — **NO AUC/EER** | Hermes (supervised) | **No** — no AUC; inactive in draft |
| **CIC-IDS2018** | **No results table** (named only in setup/roadmap discussion; the "IDS 2025" folder is CSE-CIC-IDS2018 flow CSVs, unused) | — | none | — | **No** — nothing to compare |

**What is missing / dropped (explicitly):**
- **N-BaIoT** — dropped from the AUC overview. The only N-BaIoT table in the source is `%`-commented
  per-device and reports F1/TPR/FPR/Accuracy, not AUC/EER. Representative (inactive) Tenko F1 span:
  Ennio 0.671 → Ecobee 0.877 (vs supervised Hermes ~0.96). Kept in the inventory, excluded from AUC
  aggregates.
- **CIC-IDS2018** — dropped entirely. No manuscript results table exists; the local "IDS 2025" CSVs
  are CSE-CIC-IDS2018 flow features with no source-IP column (incompatible with Tenko's node key).

**Source verification (transcript quotes):**
- Mateen table is active: `\label{tab:mateen_comparative_performance}` … `Tenko & 0.9021 & 0.6603 &
  0.8016 & 0.6068`; text: "combined-attack Kitsune trace. Results for INSOMNIA, OWAD, and Mateen …
  are reproduced from prior work."
- N-BaIoT table is commented: every row is `% Doorbell & Danmini … 0.9730 & 0.9985 …` (leading `%`),
  metrics = Accuracy/TPR/Precision/F1/FPR (no AUC column).
- CIC-IDS2018: transcript only discusses `~/Desktop/archive (1)` = "CSE-CIC-IDS2018 flow-level CSVs
  (CICFlowMeter: 80 features + Label), no Source IP column"; never a results table.

---

## Step 2 — aggregates (computed ONLY over extracted values)

**Kitsune dataset (n=9):** Tenko AUC = {0.996, 0.96, 0.99, 0.96, 0.96, 0.95, 0.95, 0.91, 0.93} →
mean **0.956**, min 0.91, max 0.996. Kitsune AUC = {0.95, 0.90, 0.88, 0.92, 0.96, 0.89, 0.93, 0.85,
0.87} → mean **0.906**, min 0.85, max 0.96. (Source: `tab:kitsune-tenko-new-highlighted`.)

**CICIoT2023 (n=6):** Tenko AUC = {0.928822, 0.987792, 0.795871, 0.949187, 0.936728, 0.696816} →
mean **0.883**, min 0.697, max 0.988. Kitsune AUC = {0.965073, 0.992747, 0.827176, 0.942003,
0.929418, 0.703386} → mean **0.893**, min 0.703, max 0.993. (Source:
`ciciot2023_per_class_metrics.csv`.)

**Kitsune combined-attack / Mateen shift (n=1):** Tenko AUC-ROC **0.607**; adaptive baselines
Mateen 0.722, OWAD 0.710, INSOMNIA 0.473. (Source: `tab:mateen_comparative_performance`.)

---

## Step 3 — paste-ready LaTeX (drop into Overleaf)

> Requires `\usepackage{booktabs}`, `\usepackage{tabularx}`, `\usepackage{array}` in the preamble.
> These blocks use plain `\texttt{}` for labels so they paste into any standard document.

### Table A — dataset-level summary

```latex
\begin{table}[t]
\centering
\footnotesize
\caption{Tenko across all datasets with usable numbers in the paper (plus the CICIoT2023 pilot).
AUC aggregates are mean~[min--max] over the $n$ extracted per-class/per-regime values only. This is a
generalization overview across heterogeneous protocols, \emph{not} a controlled ranking (different
traffic, thresholds, granularity, and---for the Mateen regime---an explicit distribution-shift stress).}
\label{tab:tenko-alldatasets}
\renewcommand{\arraystretch}{1.25}
\setlength{\tabcolsep}{4pt}
\begin{tabularx}{\textwidth}{@{}>{\raggedright\arraybackslash}p{2.2cm} c
  >{\raggedright\arraybackslash}p{1.95cm} c
  >{\raggedright\arraybackslash}p{1.95cm} >{\raggedright\arraybackslash}p{1.95cm}
  >{\raggedright\arraybackslash}X@{}}
\toprule
\textbf{Dataset} & \textbf{Year} & \textbf{Granularity} & \textbf{$n$}
  & \textbf{Tenko AUC mean [min--max]} & \textbf{Baseline AUC mean [min--max]} & \textbf{Notes / source} \\
\midrule
Kitsune (Mirsky) & 2018 & per-attack & 9 & 0.956 [0.91--0.996] & 0.906 [0.85--0.96]
  & Active; \texttt{tab:kitsune-tenko-new-highlighted}. Baseline $=$ Kitsune; Tenko $\ge$ Kitsune on all 9. \\
CICIoT2023 (this work) & 2023 & per-attack & 6 & 0.883 [0.70--0.988] & 0.893 [0.70--0.993]
  & \texttt{ciciot2023\_per\_class\_metrics.csv}. Baseline $=$ Kitsune; Tenko $>$ Kitsune on MITM, Mirai. \\
Kitsune combined-attack (shift stress) & 2018 & single mixed regime & 1 & 0.607 & 0.722 (Mateen)
  & AUC--ROC; \texttt{tab:mateen\_comparative\_performance}. Adaptive baselines: OWAD 0.710, INSOMNIA 0.473. \\
N-BaIoT & 2018 & per-device & 9 & --- & ---
  & F1/TPR/FPR only, \textbf{commented-out} in draft; Tenko F1 $0.67$--$0.88$ vs supervised Hermes. No AUC $\Rightarrow$ excluded. \\
CIC-IDS2018 & 2018 & --- & --- & --- & ---
  & \textbf{No results table} in manuscript $\Rightarrow$ excluded. \\
\bottomrule
\end{tabularx}
\end{table}
```

### Table B — matched per-attack alignment (the fair axis)

```latex
\begin{table}[t]
\centering
\small
\caption{Matched per-attack alignment: Tenko AUC on the Kitsune dataset vs CICIoT2023 (both
full-trace, threshold-independent). Positive $\Delta$ means CICIoT2023 is better. This is the only
directly comparable, same-attack axis across the two per-attack datasets.}
\label{tab:tenko-matched-attacks}
\begin{tabular}{lccc}
\toprule
\textbf{Attack (matched)} & \textbf{Tenko AUC (Kitsune ds)} & \textbf{Tenko AUC (CICIoT2023)} & \textbf{$\Delta$AUC} \\
\midrule
SYN DoS $\leftrightarrow$ DoS-SYN        & 0.95  & 0.988 & $+0.038$ \\
ARP MITM $\leftrightarrow$ MITM-Arp      & 0.96  & 0.949 & $-0.011$ \\
Mirai $\leftrightarrow$ Mirai-greeth     & 0.996 & 0.937 & $-0.059$ \\
OS Scan $\leftrightarrow$ Recon-OSScan   & 0.96  & 0.796 & $-0.164$ \\
\bottomrule
\end{tabular}
\end{table}
```

---

## Source key
- Kitsune-ds AUC/EER: transcript `tab:kitsune-tenko-new-highlighted`.
- Kitsune-ds operating point: transcript `tab:best_weighted_performance`.
- Mateen combined-attack shift (Tenko AUC-ROC 0.6068): transcript `tab:mateen_comparative_performance` (active).
- N-BaIoT per-device F1/TPR/FPR: transcript, `%`-commented `tabular` (no AUC).
- CIC-IDS2018: absent from manuscript (setup/roadmap discussion only).
- CICIoT2023 AUC/EER: `results/CICIoT2023/ciciot2023_per_class_metrics.csv`.
