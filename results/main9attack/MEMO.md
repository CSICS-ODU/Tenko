# Nine-attack Kitsune table — rebuild memo (reviewer blocker B2)

**Goal.** Turn the main-paper nine-attack table (Active Wiretap, ARP MitM, Fuzzing, Mirai,
OS Scan, SSDP Flood, SSL Renegotiation, SYN DoS, Video Injection) from unreproducible
hard-coded literals into (a) a committed copy of those literals, (b) a committed driver that
regenerates per-attack TPR/FPR/FNR/Precision **plus AUC/EER** from real anomaly scores, and
(c) a real, data-derived rebuild **for all nine attacks**.

Status: **COMPLETE — all 9 attacks downloaded and rebuilt from real data** (previously only
Mirai was reproducible locally).

## Where the paper numbers lived

`resultsNew.py` is **not** a working-tree file — it is `git show Daksh-Mateen:resultsNew.py`
(the `:` is git `<branch>:<path>` syntax). It holds a 7-thresholding-method × 9-attack matrix
for TPR/FPR/FNR/Precision, with **no AUC/EER** and **no driver/CSV**. Those arrays are
transcribed verbatim (read-only) by `recover_paper_literals.py` → `paper_literals_resultsNew.csv`
(63 rows), so the table is now diffable and traceable.

## Data source (public, NDSS'18 Mirsky et al.)

Downloaded once from the **UCI Machine Learning Repository, dataset id=516** ("Kitsune Network
Attack", DOI 10.24432/C5D90Q):

```
https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip   (~19 GB)
```

(The same data is linked from `github.com/ymirsky/Kitsune-py` via the authors' Google-Drive
mirror `https://goo.gl/iShM7E`; UCI was used because it offers a single scriptable HTTPS URL.)

The archive contains one directory per attack, each with `<Attack>_dataset.csv.gz`
(115 AfterImage features, **no** index/header, one packet per row) and `<Attack>_labels.csv.gz`
(0=benign, 1=malicious). It is stored under `results/main9attack/data/` and is **gitignored**
(`results/main9attack/.gitignore` → `data/`); only the metrics/verification CSVs, memo, and
scripts are public.

### Integrity checks (all passed)

- `unzip -t` on the archive: OK.
- Per-attack row counts match the published dataset sizes, e.g. OS Scan 1,697,850; ARP MitM
  2,504,266; SSDP Flood 4,077,265; SSL Reneg. 2,207,570 (see run logs under `data/`).
- Labels present and 0/1 for every attack; dataset row count == label row count per attack.

**Label format quirk:** the 8 non-Mirai label files are R-exported (`"","x"` header + a
row-index column, label in column 2), unlike Mirai's plain labels. They are normalized to a
plain single-column file (`data/clean/<attack>_labels.csv`) before evaluation.

## Method (mirrors how the Mirai row was produced)

Two stages per attack, driven by `rebuild_8attacks.sh`:

1. **`gen_scores.py` — authentic Kitsune score stream.** Uses the repo `KitNET` with a
   **learned** corClust feature map (`feature_map=None`): FM-grace = 5,000 packets to learn the
   feature→autoencoder mapping, AD-grace = 50,000 packets to train the ensemble (55,000 grace
   packets total, **excluded from evaluation**), then `execute` over the remainder. This is the
   authentic pipeline from `ymirsky/Kitsune-py` (`example.py`) and matches how the committed
   Mirai row was produced (`tenko_eval/run_kitsune_mirai.py`). Emits an npz `{scores, labels,
   benign_cal}` where **`benign_cal` = post-grace, PRE-ATTACK benign scores** (indices
   `[grace, first_attack_idx)`), i.e. attack-free calibration computed in execute mode.
2. **`run_kitsune_9attack.py --scores-npz` — the committed evaluator.** Computes the benign-only
   thresholds (mean / min / max / max+std / mean+3σ / median+1.5·MAD / p95 / p99), the confusion
   metrics at each, and the threshold-independent **AUC + EER**, appending to
   `kitsune_9attack_metrics.csv`.

Two calibration facts that matter:
- The pure-benign prefix precedes the first attack packet in every capture (first-attack index
  ≥ 1.3 M for all 8), so the 55 k grace is safely attack-free; benign traffic *continues during*
  the attack, so those packets correctly count as test negatives.
- Benign thresholds are taken from **execute-mode** benign scores, never from the training-warmup
  scores (untrained autoencoders produce astronomically large RMSE that would otherwise destroy
  the `max`/`mean` thresholds).

Reproduce (after placing the archive at `data/kitsune_uci.zip`):

```
bash results/main9attack/rebuild_8attacks.sh      # regenerates the 8 non-Mirai rows
python results/main9attack/verify_vs_paper.py      # writes nineattack_verification_vs_paper.csv
```

## Rebuilt nine-attack table (real data)

Threshold-independent summary + the best-F1 operating point actually attained:

| Attack | AUC | EER | best-F1 threshold | TPR | FPR | Prec | F1 |
|---|---|---|---|---|---|---|---|
| Mirai             | 0.928 | 0.129 | (max+std) | 0.853 | 0.000 | 1.000 | 0.920 |
| OS Scan           | 0.979 | 0.040 | max       | 0.994 | 0.041 | 0.500 | 0.665 |
| SSDP Flood        | 1.000 | 0.001 | max+std   | 0.999 | 0.001 | 0.999 | 0.999 |
| SSL Renegotiation | 0.931 | 0.152 | p99       | 0.848 | 0.025 | 0.607 | 0.707 |
| ARP MitM          | 0.833 | 0.308 | p99       | 0.659 | 0.010 | 0.984 | 0.789 |
| SYN DoS           | 0.708 | 0.272 | (p95/p99) | see CSV | | | |
| Fuzzing           | 0.534 | 0.461 | —         | — | — | — | — |
| Video Injection   | 0.484 | 0.544 | —         | — | — | — | — |
| Active Wiretap    | 0.425 | 0.506 | —         | — | — | — | — |

(Full per-method rows incl. tn/fp/fn/tp are in `kitsune_9attack_metrics.csv`. For Mirai the
best-F1 raw row is `min`, but that is the degenerate flag-everything point; the honest Mirai
operating point is max+std, shown above.)

**New (never in the literals): AUC + EER for all nine attacks.**

## Verification vs paper literals (`nineattack_verification_vs_paper.csv`)

Per-attack max |ΔTPR| / max |ΔFPR| across the six comparable thresholds:

| Attack | max\|ΔTPR\| | max\|ΔFPR\| | AUC | Assessment |
|---|---|---|---|---|
| Mirai             | 0.029 | 0.030 | 0.928 | **Tight match** (FPR at max+std & 3σ agree to 3 d.p.). |
| OS Scan           | 0.007 | 0.818 | 0.979 | TPR matches (~1.0); our FPR far lower (cleaner, larger benign calibration). Strong detector. |
| SSDP Flood        | 0.999 | 0.899 | **1.000** | Near-perfect separation. Paper's max+std row was degenerate (TPR=0); ours is not. |
| SSL Renegotiation | 0.848 | 0.967 | 0.931 | At **p99** we hit TPR 0.848 / FPR 0.025 — essentially the paper's max+std (0.848 / 0.019). |
| ARP MitM          | 1.000 | 0.969 | 0.833 | Detectable (AUC 0.83); high-recall paper thresholds not reproduced (see below). |
| SYN DoS           | 0.999 | 0.934 | 0.708 | Partially detectable. |
| Fuzzing           | 1.000 | 0.974 | 0.534 | Near-random under this KitNET. |
| Video Injection   | 1.000 | 0.981 | 0.484 | Near-random. |
| Active Wiretap    | 1.000 | 0.942 | 0.425 | Below random — attack packets score *lower* than benign. |

### Honest interpretation

- **Mirai, OS Scan, SSDP Flood, SSL Reneg.** reproduce the paper's story well (high AUC; the
  paper's headline operating points are recovered at max+std / p99).
- **The paper's literal table is itself full of degenerate cells** (e.g. SSDP Flood and Video
  Injection show TPR=0 at max+std; many attacks show TPR=1 only at min/mean where FPR≈1, i.e.
  "flag everything"). So large per-cell ΔTPR/ΔFPR are partly the paper's own threshold artifacts,
  not a rebuild error — which is exactly why we add the threshold-independent **AUC/EER**.
- **`max` / `max+std` are fragile here:** the benign calibration is huge (1.2–2.7 M packets) and
  for a few attacks (SSL Reneg., SYN DoS) contains a rare benign RMSE spike, which pushes those
  thresholds so high that TPR collapses to ~0. The robust `p95`/`p99` rows (and AUC/EER) are the
  meaningful operating points; e.g. SSL Reneg. p99 reproduces the paper's max+std almost exactly.
- **Fuzzing / Active Wiretap / Video Injection have low/near-random AUC and this is a genuine
  property of this KitNET variant + these captures**, not a bug: (i) switching between the fixed
  contiguous feature map and the authentic *learned* corClust map left Active Wiretap essentially
  unchanged (AUC 0.4236 → 0.4246), confirming the feature map is not the cause; (ii) for the
  MitM/injection attacks the "malicious" packets are relayed/near-benign LAN traffic, so at the
  115-feature AfterImage level they overlap benign and can even score lower. The paper only ever
  reported high TPR for these at flag-everything thresholds (FPR ≈ 0.8–1.0).

## Outputs

| File | What | Committed? |
|---|---|---|
| `paper_literals_resultsNew.csv` | Paper's 7×9 literals, committed & traceable. | yes |
| `recover_paper_literals.py` | Transcribes the literals (read-only) from `Daksh-Mateen:resultsNew.py`. | yes |
| `run_kitsune_9attack.py` | The committed evaluator (thresholds + AUC/EER). | yes |
| `gen_scores.py` | Authentic-Kitsune score-stream generator (learned FM). | yes |
| `rebuild_8attacks.sh` | End-to-end runner for the 8 downloaded attacks. | yes |
| `verify_vs_paper.py` | Emits the verification deltas. | yes |
| `kitsune_9attack_metrics.csv` | **Rebuilt** per-method metrics + AUC/EER for all 9 attacks. | yes |
| `nineattack_verification_vs_paper.csv` | Rebuilt-vs-paper deltas (54 rows). | yes |
| `mirai_verification_vs_paper.csv` | Earlier Mirai-only side-by-side. | yes |
| `data/kitsune_uci.zip`, `data/npz/*`, `data/clean/*`, `data/*log*` | Raw archive + intermediates (~18 GB). | **no — gitignored** |

## Status

- **All 9 attacks: rebuilt from real, publicly downloaded data.** ✔
- Large raw captures/CSVs/score streams kept out of git (`data/` is gitignored). ✔
- Mirai row unchanged (already from real Kitsune scores). ✔
