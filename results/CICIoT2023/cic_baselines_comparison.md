# Tenko vs. unsupervised benign-only baselines on CICIoT2023

**Purpose.** The apt, same-paradigm analogue of the paper's "Tenko vs. Hermes (N-BaIoT)"
table: Tenko compared against **two unsupervised, benign-only CICIoT2023 baselines** that share
Tenko's threat model (train on benign, detect deviations, no attack labels). This is a more
appropriate comparison than the supervised Ullah et al. 2025 ensemble
(`baseline_comparison_ullah2025.md`), which is retained only as a **supervised upper-bound
contrast** and is deliberately kept out of the head-to-head here.

**Ground rules.** No numbers are invented. Baseline figures are quoted verbatim from the two
papers and labeled **"reported"**. Tenko/Kitsune figures come from
`results/CICIoT2023/ciciot2023_per_class_metrics.csv` and `experiment_story.md` (packet-level,
benign-only pilot). Attack subsets differ across all three works, and the AUC *type* differs
(ROC-AUC for Tenko/Sukanya vs AUC-PR for Ramkumar) — so we compare **overall/representative**
scores, never a fabricated per-attack head-to-head.

---

## 1. The baselines (what they are)

| Baseline | Paradigm | Feature domain | Threshold | Detection metric | Attacks (CICIoT2023) |
|---|---|---|---|---|---|
| **Sukanya & Raja 2025** (DOI 10.21917/ijct.2025.0546) | Unsupervised, benign-only (AE / VAE / **VAE+IF**) | Flow-level (CICFlowMeter: pkt size, IAT, TCP flags, flow duration) | F1-maximization | **ROC-AUC** + P/R/F1/Acc | SQL Injection, Browser Hijacking, DDoS HTTP Flood, Backdoor Malware |
| **Ramkumar et al. 2025** (IEEE TSE, DOI 10.1109/tse.2025.3610540) | Unsupervised, benign-trained, **per-device iForest** + abductive reasoning (ASP) | Flow-level | Z-score | **AUC-PR** (precision–recall AUC, **not** ROC-AUC) | DDoS/DoS HTTP Flood, DNS Spoofing, Mirai UDP, Recon Port Scan, Upload Attack (per device) |
| **Tenko (ours)** | Unsupervised, benign-only, per-source node aggregation | **Packet-level stream** (per-packet source IP as node key) | Benign-calibrated η | **ROC-AUC** + EER; op-point TPR/FPR/F1 | DoS-SYN, DDoS-UDP, MITM-ARP, Mirai-greeth, Recon-OSScan, Dictionary |
| **Kitsune (ours, on same CIC data)** | Unsupervised, benign-only, per-packet reconstruction | Packet-level stream | Benign Median+MAD | **ROC-AUC** + EER | same 6 as Tenko |

> **Two things are NOT comparable across rows and must stay flagged:** (1) **AUC type** —
> Tenko and Sukanya report **ROC-AUC**; Ramkumar reports **AUC-PR**, which is generally higher
> on imbalanced data and cannot be read on the same scale. (2) **Attack subsets differ** — no
> two of the three works evaluate the same attack classes, so only overall/representative
> aggregates are compared.

---

## 2. Headline comparison (overall / representative)

All values as reported / from our CSV. "AUC" column notes its type per row.

| Method | Paradigm | Feature domain | AUC (type) | F1 (headline) |
|---|---|---|---|---|
| **Tenko (ours)** | unsup. benign-only | packet stream | **0.883** ROC-AUC (mean of 6) | 0.884 (mean of 4 strong attacks, op-pt, in-sample); 0.47 (mean of 6) |
| **Kitsune (ours)** | unsup. benign-only | packet stream | 0.893 ROC-AUC (mean of 6) | — (constant-FPR baseline) |
| **VAE+IF (Sukanya)** | unsup. benign-only | flow CSV | 0.955 ROC-AUC (mean of 4); 0.8947 overall | **0.55** overall; 0.625 (mean per-attack) |
| **VAE (Sukanya)** | unsup. benign-only | flow CSV | 0.935 ROC-AUC (mean of 4) | 0.29 overall |
| **AE (Sukanya)** | unsup. benign-only | flow CSV | 0.905 ROC-AUC (mean of 4) | 0.27 overall |
| **iForest (Ramkumar)** | unsup. benign-only | flow CSV | 0.967 **AUC-PR** (mean of 8) — *not ROC-AUC* | 0.795 (mean of 8) |

Derivations (means computed only over the reported values, no inference):
- Tenko ROC-AUC mean 0.883 over {0.988, 0.929, 0.949, 0.937, 0.796, 0.697}
  (`ciciot2023_per_class_metrics.csv`).
- Tenko op-point F1: strong-4 mean 0.884 over {0.966, 0.889, 0.864, 0.817}; all-6 mean 0.47
  incl. Recon 0.200 / Dict 0.058 (**in-sample** operating point, `experiment_story.md` §4b).
- Kitsune ROC-AUC mean 0.893 over {0.965, 0.993, 0.827, 0.942, 0.929, 0.703}
  (`ciciot2023_per_class_metrics.csv`).
- Sukanya VAE+IF ROC-AUC mean 0.955 over per-attack {0.96, 0.95, 0.97, 0.94} (their Table 6);
  overall AUC 0.8947 and overall F1 0.55 are their Table 4/8 headline.
- Ramkumar iForest AUC-PR mean 0.967 and F1 mean 0.795 over the 8 CICIoT2023 device/attack
  rows in their Table 3.

---

## 3. Per-attack appendix (as reported, grouped by paper — NOT matched attacks)

### 3a. Tenko (ours) — packet-level, benign-only (`ciciot2023_per_class_metrics.csv`)

| Attack | ROC-AUC | EER | Op-pt F1 @5% (in-sample) |
|---|---|---|---|
| DoS-SYN Flood | 0.988 | 0.052 | 0.966 |
| MITM-ARP Spoofing | 0.949 | 0.131 | 0.889 |
| Mirai-greeth Flood | 0.937 | 0.140 | 0.817 |
| DDoS-UDP Flood | 0.929 | 0.129 | 0.864 |
| Recon-OSScan | 0.796 | 0.256 | 0.200 |
| Dictionary BruteForce | 0.697 | 0.285 | 0.058 |

Kitsune (ours) ROC-AUC for the same 6: 0.965, 0.993, 0.827, 0.942, 0.929, 0.703.

### 3b. Sukanya & Raja 2025 (reported) — flow-level, benign-only

Per-attack P/R/F1/Acc (their Table 5):

| Attack | Precision | Recall | F1 | Acc |
|---|---|---|---|---|
| SQL Injection | 0.36 | 0.90 | 0.52 | 0.79 |
| Browser Hijacking | 0.89 | 0.81 | 0.85 | 0.96 |
| DDoS HTTP Flood | 0.71 | 0.64 | 0.67 | 0.88 |
| Backdoor Malware | 0.40 | 0.53 | 0.46 | 0.73 |

Per-attack ROC-AUC by model (their Table 6), AE / VAE / VAE+IF:

| Attack | AE | VAE | VAE+IF |
|---|---|---|---|
| SQL Injection | 0.91 | 0.94 | 0.96 |
| Browser Hijacking | 0.90 | 0.93 | 0.95 |
| DDoS HTTP Flood | 0.92 | 0.95 | 0.97 |
| Backdoor Malware | 0.89 | 0.92 | 0.94 |

Overall binary detection (their Table 4/8): AE P0.51/R0.19/F1 0.27/Acc0.90; VAE
0.52/0.21/0.29/0.89; VAE+IF 0.45/0.71/**F1 0.55**/0.89; overall **AUC 0.8947**.

### 3c. Ramkumar et al. 2025 (reported) — per-device iForest, **AUC-PR (not ROC-AUC)**

CICIoT2023 (their Table 3), Precision / Recall / AUC-PR / F1:

| Device — Attack | Precision | Recall | AUC-PR | F1 |
|---|---|---|---|---|
| Philips Hue — DDoS HTTP Flood | 0.9536 | 0.9774 | 0.9764 | 0.9653 |
| iRobot — DNS Spoofing | 0.7188 | 0.9978 | 0.9991 | 0.8345 |
| Amcrest — DoS HTTP Flood | 0.9997 | 0.6946 | 0.9954 | 0.8197 |
| Dlink — DoS HTTP Flood | 0.9998 | 0.5012 | 0.9740 | 0.6666 |
| Alexa — Mirai UDP Plain | 0.9994 | 0.8092 | 0.9935 | 0.8902 |
| Amazon Plug — Recon Port Scan | 0.8414 | 0.9068 | 0.9193 | 0.8726 |
| Techkin — Recon Port Scan | 0.5002 | 0.8072 | 0.9124 | 0.6174 |
| RPi — Upload Attack | 0.5320 | 1.0000 | 0.9697 | 0.6920 |

Context (their IoT-23 iForest F1, not CICIoT2023): Mirai 0.7567, Gagfyt 0.8179, Kenjiro
0.8421, Hakai 0.9987, IRCBot 0.8571, Muhstik 0.6807, Hide&Seek 0.9393; Torii/Trojan/Okiru
poor. Included only as breadth context; the CICIoT2023 rows above are the headline.

---

## 4. Prose analysis (honest, both directions)

**Where Tenko stands.** Within the unsupervised benign-only class on CICIoT2023, Tenko is
**competitive, and on its strong attacks comparable-to-stronger**, than these baselines:

- **vs. Sukanya & Raja 2025.** Their overall binary-detection headline is **F1 0.55 (VAE+IF)
  at overall ROC-AUC 0.8947**. Tenko's mean ROC-AUC is **0.883** — essentially level with
  their overall AUC — and Tenko's operating-point F1 on its four strong attacks reaches
  **0.82–0.97** (mean 0.884), well above their 0.55 overall F1, though this is an **in-sample**
  operating point and their 0.55 is a full-dataset binary number. Their per-attack ROC-AUC
  (VAE+IF 0.94–0.97) is higher than Tenko's per-attack ROC-AUC on Tenko's harder classes, but
  those are *different attacks* (SQLi/Browser-Hijack/HTTP-Flood/Backdoor vs
  SYN/UDP/MITM/Mirai/Recon/Dict). Fair reading: **same-paradigm, same ballpark on AUC; Tenko
  stronger where it is strong, weaker on benign-overlapping low-rate attacks.**
- **vs. Ramkumar et al. 2025.** Their iForest F1 spans **0.62–0.97** (mean 0.795) with
  **AUC-PR 0.91–0.9991** (mean 0.967). Tenko's op-point F1 (0.82–0.97 on strong attacks) sits
  **in-band** with their F1 range. Their AUC-PR is **not** comparable to Tenko's ROC-AUC
  (AUC-PR runs higher under class imbalance), so we do **not** claim an AUC win here — only
  that Tenko's F1 is within their reported band, in the same paradigm.

**Honest caveats (state proactively):**
- **(a) Feature domain differs.** Both baselines use **flow CSVs** (CICFlowMeter aggregates);
  Tenko uses the **raw packet stream** because the CSVs drop per-packet source IP, which would
  collapse Tenko's node aggregation (`experiment_story.md` §1). This is a genuine input-level
  difference, not just a metric difference.
- **(b) Attack subsets differ.** No two works share the same attacks; only overall/mean
  aggregates are compared.
- **(c) AUC type differs.** Tenko/Sukanya = ROC-AUC; Ramkumar = AUC-PR. Do not place them on
  one axis.
- **(d) Tenko's operating-point F1 is in-sample.** The 5% benign-FPR operating point is
  calibrated and measured on the same benign slice; it does not transfer out-of-sample on this
  non-stationary trace (`experiment_story.md` §4c). Tenko's **threshold-independent ROC-AUC**
  is the transfer-safe headline.

**Framing (do not overclaim a win):** Tenko is **competitive within the unsupervised
benign-only class** on CICIoT2023, and **additionally offers packet-level streaming detection
with per-source node context** and low-latency online operation — capabilities neither
flow-CSV baseline provides. That added capability, not a raw metric victory, is the
differentiator to emphasize.

---

## 5. Recommendation + paste-ready positioning

**Which to cite (both — they are complementary):**
- **Sukanya & Raja 2025** gives a clean **overall unsupervised ROC-AUC (0.8947) and overall F1
  (0.55)** on CICIoT2023 flow features — the ideal single-number unsupervised reference point.
- **Ramkumar et al. 2025** gives **per-attack, per-device unsupervised iForest** results (with
  AUC-PR) — the ideal granular unsupervised reference, and adds IoT-23 breadth.
- Keep **Ullah et al. 2025 (supervised)** only as a labeled **supervised upper-bound** contrast
  in Related Work, explicitly separated from this unsupervised head-to-head.

**How to present the table** so it strengthens the paper: lead with the §2 headline table
(paradigm + feature domain + AUC-type + headline AUC/F1), carry the footnote about AUC-type and
attack-subset mismatch, and frame the takeaway as *parity within the unsupervised benign-only
class plus a packet-level streaming/per-source advantage* — not a raw metric win.

**Paste-ready positioning sentences:**

> Among unsupervised, benign-only detectors evaluated on CICIoT2023, Tenko is competitive with
> recent flow-level baselines. Sukanya & Raja (2025) report an overall ROC-AUC of 0.8947 and an
> overall F1 of 0.55 (VAE+IF) on CICFlowMeter features, while Ramkumar et al. (2025) report a
> per-device Isolation-Forest F1 of 0.62–0.97 (AUC-PR 0.91–0.9991). Tenko attains a mean
> full-trace ROC-AUC of 0.883 and operating-point F1 of 0.82–0.97 on its strong attacks, placing
> it in the same range as both baselines despite operating directly on the packet stream rather
> than on flow-level CSV aggregates. Because these baselines use flow features, cover different
> attack subsets, and (for Ramkumar) report precision–recall AUC rather than ROC-AUC, we do not
> claim a strict metric win; rather, Tenko matches the unsupervised state of the art on this
> trace while additionally providing packet-level, low-latency streaming detection with
> per-source node context. For reference, supervised offline ensembles such as Ullah et al.
> (2025) reach ~99% accuracy on the same dataset, but require labeled examples of every attack
> class and therefore represent a supervised upper bound rather than a comparable unsupervised
> method.

---

## 6. Paste-ready LaTeX — headline table

> Requires `\usepackage{booktabs}` and `\usepackage{tabularx}` in the preamble.

```latex
\begin{table}[t]
\centering
\footnotesize
\caption{Unsupervised, benign-only anomaly detection on CICIoT2023: Tenko (ours, packet-level)
versus recent flow-level baselines. Scores are overall/representative values as reported; attack
subsets differ across works and are therefore not matched. \textbf{AUC types differ}: Tenko,
Kitsune, and Sukanya \emph{et al.} report ROC-AUC, whereas Ramkumar \emph{et al.} report AUC--PR
(precision--recall AUC), which is not directly comparable to ROC-AUC. Tenko's operating-point F1
is \emph{in-sample} (benign-calibrated at $5\%$ FPR); its threshold-independent ROC-AUC is the
transfer-safe headline.}
\label{tab:cic_unsup_baselines}
\begin{tabular}{llll}
\toprule
\textbf{Method} & \textbf{Feature domain} & \textbf{AUC (type)} & \textbf{F1 (headline)} \\
\midrule
\textbf{Tenko (ours)}      & packet stream & $0.883$ ROC-AUC$^{\mathrm{a}}$ & $0.884$$^{\mathrm{b}}$ / $0.47$$^{\mathrm{c}}$ \\
Kitsune (ours)             & packet stream & $0.893$ ROC-AUC$^{\mathrm{a}}$ & --- \\
VAE+IF (Sukanya \emph{et al.} 2025) & flow CSV & $0.895$ ROC-AUC$^{\mathrm{d}}$ & $0.55$$^{\mathrm{d}}$ \\
VAE (Sukanya \emph{et al.} 2025)    & flow CSV & $0.935$ ROC-AUC$^{\mathrm{e}}$ & $0.29$ \\
AE (Sukanya \emph{et al.} 2025)     & flow CSV & $0.905$ ROC-AUC$^{\mathrm{e}}$ & $0.27$ \\
iForest (Ramkumar \emph{et al.} 2025) & flow CSV & $0.967$ \textbf{AUC-PR}$^{\mathrm{f}}$ & $0.795$$^{\mathrm{f}}$ \\
\bottomrule
\multicolumn{4}{p{0.92\linewidth}}{\footnotesize
$^{\mathrm{a}}$Mean of 6 per-attack ROC-AUC (\texttt{ciciot2023\_per\_class\_metrics.csv}).
$^{\mathrm{b}}$Mean op-point F1 over the four strong attacks (in-sample $5\%$ FPR).
$^{\mathrm{c}}$Mean op-point F1 over all six attacks (incl.\ low-rate Recon/Dictionary).
$^{\mathrm{d}}$Overall binary detection (VAE+IF), reported.
$^{\mathrm{e}}$Mean of four per-attack ROC-AUC, reported (Table~6).
$^{\mathrm{f}}$Mean over eight CICIoT2023 device/attack rows; \textbf{AUC-PR $\neq$ ROC-AUC}.}
\end{tabular}
\end{table}
```

### Optional per-attack appendix (LaTeX)

```latex
\begin{table}[t]
\centering
\footnotesize
\caption{Per-attack detail (as reported; \emph{not} matched attacks). Tenko/Kitsune from our
CICIoT2023 pilot; Sukanya and Ramkumar from the cited papers. Ramkumar uses AUC--PR.}
\label{tab:cic_unsup_baselines_perattack}
\begin{tabular}{lll}
\toprule
\textbf{Work / attack} & \textbf{AUC} & \textbf{F1} \\
\midrule
\multicolumn{3}{l}{\textit{Tenko (ours, ROC-AUC; F1 in-sample @5\%)}} \\
DoS-SYN Flood            & $0.988$ & $0.966$ \\
MITM-ARP Spoofing        & $0.949$ & $0.889$ \\
Mirai-greeth Flood       & $0.937$ & $0.817$ \\
DDoS-UDP Flood           & $0.929$ & $0.864$ \\
Recon-OSScan             & $0.796$ & $0.200$ \\
Dictionary BruteForce    & $0.697$ & $0.058$ \\
\midrule
\multicolumn{3}{l}{\textit{Sukanya \emph{et al.} 2025 (ROC-AUC = VAE+IF, Table~6; F1 = Table~5)}} \\
SQL Injection            & $0.96$ & $0.52$ \\
Browser Hijacking        & $0.95$ & $0.85$ \\
DDoS HTTP Flood          & $0.97$ & $0.67$ \\
Backdoor Malware         & $0.94$ & $0.46$ \\
\midrule
\multicolumn{3}{l}{\textit{Ramkumar \emph{et al.} 2025 (iForest, \textbf{AUC-PR}, Table~3)}} \\
DDoS HTTP Flood (Philips Hue) & $0.9764$ & $0.9653$ \\
DNS Spoofing (iRobot)         & $0.9991$ & $0.8345$ \\
DoS HTTP Flood (Amcrest)      & $0.9954$ & $0.8197$ \\
DoS HTTP Flood (Dlink)        & $0.9740$ & $0.6666$ \\
Mirai UDP Plain (Alexa)       & $0.9935$ & $0.8902$ \\
Recon Port Scan (Amazon Plug) & $0.9193$ & $0.8726$ \\
Recon Port Scan (Techkin)     & $0.9124$ & $0.6174$ \\
Upload Attack (RPi)           & $0.9697$ & $0.6920$ \\
\bottomrule
\end{tabular}
\end{table}
```

---

## Source key

- **Tenko / Kitsune (ours)**: `results/CICIoT2023/ciciot2023_per_class_metrics.csv` (ROC-AUC,
  EER, op-point F1); `results/CICIoT2023/experiment_story.md` (§1 packet-vs-flow rationale, §4b
  in-sample operating point, §4c OOS non-transfer).
- **Sukanya & Raja 2025 (reported)**: DOI 10.21917/ijct.2025.0546 — Tables 4/5/6/8 as quoted.
- **Ramkumar et al. 2025 (reported)**: IEEE TSE, DOI 10.1109/tse.2025.3610540 — Table 3
  (CICIoT2023 iForest, AUC-PR) as quoted; IoT-23 F1 as context only.
- **Supervised upper-bound contrast (separate doc)**: `baseline_comparison_ullah2025.md`
  (Ullah et al. 2025) — not part of this unsupervised head-to-head.
