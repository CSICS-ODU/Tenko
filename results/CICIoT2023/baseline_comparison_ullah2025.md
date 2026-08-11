# TENKO vs. Ullah et al. (2025) — a rigorous baseline comparison on CICIoT2023

**Baseline paper.** Ullah, Wu, Lin, Kamal, Mostafa, Sheraz, Chuah. *"Comparative analysis
of deep learning and traditional methods for IoT botnet detection using a multi-model
framework across diverse datasets."* **Scientific Reports (2025) 15:31072.**
<https://doi.org/10.1038/s41598-025-16553-w>

**Scope of this document.** A senior-researcher, both-directions read of whether this paper
is a fair competitor to Tenko on CICIoT2023. All baseline figures are labeled
**"Ullah et al. 2025 (reported)"** and are taken only from the facts supplied for this paper;
none are inferred. All Tenko figures are cited to their artifact under
`results/CICIoT2023/` (chiefly `ciciot2023_per_class_metrics.csv`, with narrative context
from `experiment_story.md`, `cross_dataset_comparison.md`, `all_datasets_comparison.md`, and
`manuscript_drafts.md`). No numbers are invented; no results were re-run.

---

## 1. TL;DR verdict

**No — this is not an apples-to-apples competitor to Tenko; it is a different paradigm.**
Ullah et al. 2025 is a *supervised, offline, multi-class* ensemble (CNN + BiLSTM + Random
Forest + Logistic Regression, weighted soft-voting) trained on **flow-level CSV features**
with **SMOTE** balancing and per-dataset threshold tuning, evaluated by *in-distribution
k-fold cross-validation*. Tenko is *unsupervised, benign-only, packet-level, online/streaming*
with *per-source node aggregation*, evaluated by *threshold-independent AUC/EER on a held-out
trace*. Their headline 99.2% accuracy and Tenko's ~0.88 mean AUC measure different things on
different inputs under different assumptions, so neither "beats" the other in any direct sense.
The honest framing is **complementary, not competitive**: they set a supervised
in-distribution upper bound on *known* attacks; Tenko targets label-free, zero-day-capable,
streaming detection.

---

## 2. Paradigm comparison

| Axis | Ullah et al. 2025 (reported) | Tenko |
|---|---|---|
| Learning setting | Supervised, multi-class classification (34 classes: 33 attacks + benign) | Unsupervised, benign-only (one-class) anomaly detection |
| Training signal | Labeled attack + benign data | Benign traffic only; **no attack labels used** (`experiment_story.md` §3a; `manuscript_drafts.md` A.3) |
| Input representation | Flow-level CSV features (46 → 42 selected; flow_duration, header_length, protocol_type, …) | Raw **packet stream** (per-packet features via KitNET), with **per-packet source IP** as node key (`experiment_story.md` §1, §2a) |
| Model | Hybrid ensemble CNN + BiLSTM + RF + LR, weighted soft-voting (weights = val macro-F1) | Reconstruction (KitNET/RMSE) + node-level pattern aggregation (Tenko X2–X4), benign-normalized fused distance (`experiment_story.md` §2d) |
| Preprocessing / balancing | IQR outlier removal, Quantile-Uniform skew transform (skew 81.49 → 0.0003), multi-layer feature selection, **SMOTE** balancing | None of the above; streaming with a benign lead-in window for calibration (150k benign lead / 30k benign test / 50k attack) (`stream_counts.csv`; `experiment_story.md` §2c) |
| Evaluation protocol | 5-fold stratified cross-validation, **in-distribution**; per-dataset decision-threshold tuning | Online stream over a held-out trace; **threshold-independent AUC/EER**; benign-calibrated η operating points reported separately (`experiment_story.md` §4a–4c) |
| Primary metric | Accuracy / F1 / AUC-ROC (+ MSE/RMSE/MAE, timing) | AUC / EER (threshold-independent); TPR/FPR/Precision/F1 at benign-calibrated η (`ciciot2023_per_class_metrics.csv`) |
| Zero-day / novel-attack capability | No — label-dependent (authors' own stated limitation) | Yes by construction — benign-only training flags deviations from benign, no attack labels required |
| Per-source / node modeling | No — flow CSVs drop source IP / ordering / timestamp | Yes — node aggregation keyed on per-packet source IP is the core contribution (`experiment_story.md` §1) |
| Deployment / latency | Offline batch; heavy DL training (~12,320 s reported) | Online, low-latency, single-pass streaming; constant-time per-packet node update (`manuscript_drafts.md` A.1 Layer II) |
| CICIoT2023 coverage | Subset of 234,745 records, 34 classes | 6-attack PCAP **pilot** (DDoS-UDP, DoS-SYN, MITM-ArpSpoofing, Mirai-greeth, Recon-OSScan, DictionaryBruteForce) (`experiment_story.md` §1) |

---

## 3. Head-to-head on CICIoT2023 — why the numbers aren't comparable

**Ullah et al. 2025 (reported), CICIoT2023.** Ensemble Accuracy **99.2%**, F1 **0.992**,
AUC-ROC **0.992**, MSE **0.0003**, training ~**12,320 s**. Individual (balanced) models:
CNN 98% (AUC 0.98), BiLSTM 99% (0.99), RF 98% (0.98), LR 99.15% (0.99). They compare against
SOTA on CICIoT2023 (DBN+GAN+AE 98.86%, Stacking-ensemble 93%, SV-SC 98.6%,
SCEEHO-…-DBN 98.95%) and claim a +0.25% to +6.2% margin.

**Tenko, CICIoT2023 pilot (threshold-independent, full-trace AUC).** From
`ciciot2023_per_class_metrics.csv`:

| Attack | Tenko AUC | Tenko EER |
|---|---|---|
| DoS-SYN_Flood | 0.988 | 0.052 |
| MITM-ArpSpoofing | 0.949 | 0.131 |
| Mirai-greeth_flood | 0.937 | 0.140 |
| DDoS-UDP_Flood | 0.929 | 0.129 |
| Recon-OSScan | 0.796 | 0.256 |
| DictionaryBruteForce | 0.697 | 0.285 |
| **mean** | **~0.883** | — |

(Mean 0.883 over the 6 classes; `all_datasets_comparison.md` Step 2.)

**Why these numbers cannot be placed on the same axis:**

- **Different label regime.** Their 99.2% is the accuracy of a *supervised* classifier that
  has *seen labeled examples of every one of the 33 attack classes*. Tenko never sees an
  attack label; its AUC measures how separable attack packets are from benign using
  benign-only calibration. A supervised model *should* score higher on attacks it was
  trained on — that is the definition of the setting, not evidence of superiority.
- **Different input.** They use flow-level CSV aggregates (46 features). Tenko uses the raw
  packet stream because the CSVs "drop [the source IP] column, which would collapse node
  aggregation" (`experiment_story.md` §1). The two methods are literally not reading the same
  data.
- **Different balancing.** Their evaluation is on a **SMOTE-balanced** multi-class set;
  accuracy/F1 on a synthetically balanced set does not reflect the naturally skewed traffic a
  streaming detector faces.
- **Different metric.** Accuracy/weighted-F1 on balanced classes vs. threshold-independent
  AUC/EER on an imbalanced held-out stream. AUC 0.92 and accuracy 0.99 are not on the same
  scale.
- **Different evaluation window.** k-fold *in-distribution* (train and test drawn from the
  same distribution) vs. a single held-out **pilot** trace with benign-only calibration.

**Both-directions honesty (state both explicitly):**

- *In their favor:* on the exact task they measure — supervised, in-distribution,
  SMOTE-balanced, flow-level classification of the known 33 attacks — their reported numbers
  are genuinely higher than Tenko's per-attack AUC, and Tenko makes no claim to match them
  there.
- *In Tenko's favor:* their setting is the easier one (labels for every attack, balanced
  classes, in-distribution test, offline batch). None of their numbers demonstrate zero-day
  detection, streaming latency, per-source attribution, or robustness to natural class
  imbalance — the axes on which Tenko is designed to operate. So "99.2% > 0.88 AUC" is not a
  meaningful comparison in either direction.

---

## 4. Critical read of the baseline — where we can legitimately push back

**(a) The macro-F1 tell: minority-class weakness hidden by accuracy.** Their own Table 8
cross-validation on CICIoT2023 (reported) gives, for the base learners:

| Model (Ullah et al. 2025, reported) | Accuracy | F1-Macro | F1-Weighted |
|---|---|---|---|
| Random Forest | 0.9882 | **0.6806** | 0.9866 |
| Logistic Regression | 0.9757 | **0.6171** | 0.9731 |

The **~0.31 gap between weighted-F1 (~0.99) and macro-F1 (~0.62–0.68)** is the classic
signature of a model that is excellent on the frequent classes and *poor on the rare
(minority) attack classes*, with the failure masked by accuracy and weighted-F1. A headline
"99.2%" says almost nothing about how the system does on the low-frequency attacks that often
matter most operationally. (Note the ensemble's *reported* macro numbers are not given to us;
the base-learner macro-F1 is the honest window we have, and it is low.)

**(b) Accuracy on a SMOTE-balanced multiclass set overstates real-world skewed performance.**
Balancing the classes with SMOTE before measuring accuracy inflates the headline relative to
what the same model would score on naturally imbalanced production traffic, where benign and a
few flood classes dominate. Accuracy on a balanced set is not a deployment metric.

**(c) Label dependency ⇒ no zero-day (their own admission).** The paper explicitly concedes
"reliance on labeled data limits its ability to detect zero-day attacks" and "dependency on
labeled data may hinder applicability where labels are scarce," listing unsupervised /
semi-supervised / federated learning as *future work*. This is precisely the gap Tenko fills:
benign-only training requires no attack labels and is not confined to a fixed known-attack
taxonomy.

**(d) Offline heavy training + flow features discard per-source / temporal identity.**
Training ~12,320 s offline, and the flow-CSV representation drops the per-packet source IP,
ordering, and timestamps. That forecloses per-source attribution and online, low-latency
operation — both of which are central to Tenko's node-level, streaming design.

**(e) k-fold in-distribution ≠ novel-attack generalization.** 5-fold stratified CV measures
interpolation within the *same* distribution the model was trained on. It says nothing about
generalization to attack behaviors absent from training — exactly the regime an
anomaly-detection method like Tenko is built to address.

---

## 5. Where they are genuinely stronger / what Tenko is missing

Stated candidly:

- **(a) Supervised in-distribution detection of trained attacks is higher.** For the 33
  attack classes they trained on, their reported accuracy/F1 (~0.99) exceeds Tenko's
  per-attack AUC (mean ~0.883). On known attacks with labels available, a supervised ensemble
  is the stronger tool, full stop.
- **(b) Scale and coverage.** They evaluate the full **34-class / 234,745-record** CICIoT2023
  slice and report BOT-IoT (100% acc) and IoT-23 (91.5% acc) as well. Tenko's CICIoT2023
  result is a **6-attack pilot** (`experiment_story.md` §1). Their coverage is broader.
- **(c) A single punchy headline metric.** "99.2% accuracy, F1 0.992, AUC 0.992" is a clean,
  reviewer-friendly headline. Tenko's honest story is a per-attack AUC spread (0.70–0.99)
  plus an explicit in-sample-FPR caveat — more nuanced, less quotable.
- **(d) Mature multi-dataset breadth.** Three datasets (BOT-IoT, CICIoT2023, IoT-23) under one
  framework is a strong generality narrative. Tenko's multi-dataset story exists (Kitsune
  dataset, CICIoT2023 pilot; `all_datasets_comparison.md`) but the CIC portion is a pilot.

---

## 6. What Tenko can improve — concrete, realistic action items

- **(i) Scale the CIC pilot.** Extend beyond 6 attack classes toward the full CICIoT2023
  attack taxonomy and a larger benign window, so coverage is comparable to the baseline's
  33-class breadth. This is the single most impactful gap to close (§5b).
- **(ii) Add a supervised / semi-supervised upper-bound reference point.** Report a supervised
  or semi-supervised classifier on the *same* pilot as a context anchor, so readers can see
  Tenko's unsupervised AUC relative to a supervised ceiling — turning "no labels" from an
  apparent weakness into a quantified trade-off.
- **(iii) Report macro-averaged detection across classes.** Present a macro-averaged
  (per-class) detection summary to directly counter the accuracy/weighted-F1 framing, and to
  make the point that Tenko is measured on the harder, imbalance-robust axis (§4a–b).
- **(iv) Consider a hybrid as future work.** Position Tenko as an unsupervised front-line
  detector feeding a light supervised/semi-supervised head for known-attack labeling — this
  directly addresses the baseline's own "future work = unsupervised/semi-supervised" note and
  frames the two paradigms as complementary.
- **(v) Emphasize streaming latency / memory as the differentiator.** Foreground per-packet
  latency and constant-time node-update memory numbers — the axis on which an offline
  ~12,320 s DL ensemble simply does not compete.
- **(vi) Cite this paper as a supervised upper-bound baseline in Related Work.** Use Ullah
  et al. 2025 as the reference supervised-ensemble point on CICIoT2023, framing Tenko as the
  label-free, streaming, zero-day-capable counterpart rather than a head-to-head rival.

---

## 7. Tenko's limitations (candid)

- **Unsupervised ceiling on seen attacks.** Without labels, Tenko cannot match a supervised
  ensemble's accuracy on attacks that ensemble was trained on; mean pilot AUC ~0.883 vs. their
  reported ~0.99 accuracy (`ciciot2023_per_class_metrics.csv`).
- **Pilot scale.** 6 attacks, one PCAP per class, 150k benign lead + 30k benign test +
  50k/attack (`stream_counts.csv`) — not the full dataset.
- **In-sample-FPR / OOS non-transfer.** A fixed benign-calibrated η does **not** transfer
  across disjoint benign slices of this non-stationary trace: held-out FPR fell to ≈0% in one
  split direction and rose to ≈30% in the other, versus a 1–5% nominal target
  (`ciciot2023_metrics_recalibrated_oos.csv`; `experiment_story.md` §4c). This is why
  CICIoT2023 is headlined by threshold-independent AUC/EER and the operating-point FPR is
  labeled in-sample.
- **Weak on benign-overlapping low-rate attacks.** Recon-OSScan (AUC 0.796) and
  DictionaryBruteForce (AUC 0.697) remain hard under benign-only training — a genuine
  separability limit, not a threshold artifact (`experiment_story.md` §4d;
  `cross_dataset_comparison.md` Step 3). At a 5% in-sample operating point their TPR is only
  ~0.11 and ~0.03 respectively (`ciciot2023_per_class_metrics.csv`).
- **Competitive, not dominant, vs. Kitsune on this trace.** Tenko wins only 2/6 attacks
  (MITM, Mirai) on CICIoT2023, versus 9/9 on the Kitsune dataset
  (`cross_dataset_comparison.md` Step 2a).

---

## 8. Positioning paragraph (paste-ready)

> Tenko and supervised offline ensembles such as Ullah et al. (2025) address complementary
> problems and should not be read as direct competitors. Their multi-model framework
> (CNN + BiLSTM + Random Forest + Logistic Regression) attains high in-distribution accuracy
> on CICIoT2023 (reported 99.2% accuracy, F1 0.992) by learning from labeled examples of every
> attack class on SMOTE-balanced, flow-level features under k-fold cross-validation — a setting
> in which a supervised classifier is expected to excel, and one we do not attempt to beat.
> Tenko instead performs unsupervised, benign-only, packet-level detection over a live stream,
> with per-source node aggregation and threshold-independent AUC/EER (mean ~0.88 on our
> CICIoT2023 pilot), and therefore detects deviations from benign behavior without any attack
> labels or a fixed known-attack taxonomy. Consistent with the baseline authors' own stated
> limitation — that "reliance on labeled data limits its ability to detect zero-day attacks" —
> Tenko is designed precisely for the label-scarce, novel-attack, low-latency regime their
> framework leaves as future work. We concede that supervised ensembles achieve higher
> in-distribution accuracy on the attacks they are trained on; the contribution of Tenko is
> orthogonal: label-free, streaming, per-source, and zero-day-capable detection.

---

## Source key

- **Baseline (all rows labeled "Ullah et al. 2025 (reported)")**: Ullah et al.,
  *Scientific Reports* (2025) 15:31072, <https://doi.org/10.1038/s41598-025-16553-w>, using only
  the facts supplied for this comparison.
- **Tenko AUC/EER + operating points**: `results/CICIoT2023/ciciot2023_per_class_metrics.csv`.
- **Tenko mean AUC (0.883) over 6 pilot classes**: `results/CICIoT2023/all_datasets_comparison.md` (Step 2).
- **Pilot layout, benign-only η, double/single-tanh, OOS FPR non-transfer**:
  `results/CICIoT2023/experiment_story.md` (§1–§4); `results/CICIoT2023/manuscript_drafts.md`
  (A.1–A.3); `results/CICIoT2023/ciciot2023_metrics_recalibrated_oos.csv`.
- **Kitsune vs. Tenko win/loss on CICIoT2023 and matched-attack alignment**:
  `results/CICIoT2023/cross_dataset_comparison.md` (Steps 2–3).
