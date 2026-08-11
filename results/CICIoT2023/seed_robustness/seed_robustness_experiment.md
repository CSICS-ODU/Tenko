# Multi-seed robustness — CICIoT2023 MIXED stream (reviewer blocker M4 / Reviewer-1)

**Question (reviewer).** The paper reports a single fixed seed (42). Are Tenko's
CICIoT2023 mixed-stream numbers robust to the random seed?

**Answer (TL;DR).** Yes — and the reason is stronger than "low variance":

1. The committed detection pipeline is **deterministic** with respect to the
   Python/NumPy global seed. The paper's `seed=42` does **not** touch the
   mixed-stream detection metrics at all (it seeds only the X3/X4 *latency-noise*
   simulation in `workflow.py`, not detection).
2. The **only** genuine source of model randomness that can change a detection
   score on this stream is the KitNET autoencoder weight initialization, which is
   hard-coded to `numpy.random.RandomState(1234)` (`KitNET/dA.py:64`). We
   overrode that init seed and re-ran the **entire** pipeline (X1→X2–X4→Kitsune)
   for **6 seeds** `{1, 7, 42, 123, 1234, 2024}` (1234 = the committed run).
3. Across those 6 seeds the headline numbers are extremely stable. The
   **threshold-free** AUC-ROC has std **0.0004** (AUC-PR std 0.00007); the
   **operating-point** metrics move only in the third decimal (committed TPR std
   0.0033, orrule@2% Accuracy std 0.0011).

All numbers below come from actual pipeline runs (no fabricated values). The
seed=1234 run reproduces the committed cached arrays (`mixed/arr_*_mixed.npy`)
**bit-for-bit** (`np.array_equal == True`), which both validates the harness and
confirms the committed run corresponds to the default KitNET seed.

---

## 1. Where does randomness actually enter? (end-to-end audit)

Every stage was read for RNG use (`KitNET/`, `results.py`, `tracker.py`,
`example.py`, `run_ciciot2023.py`, `mixed/run_mixed.py`):

| Stage | Component | Randomness? | Seed-dependent? |
|---|---|---|---|
| X1 | Feature-map clustering (`KitNET/corClust.py`) | Incremental correlation matrix + SciPy hierarchical linkage | **No** — fully deterministic |
| X1 | Training sample order | Fixed stream order, **no shuffle** | **No** |
| X1 | **Autoencoder weight init** (`KitNET/dA.py:64`) | `numpy.random.RandomState(1234).uniform(...)` | **YES — the only score-affecting RNG** |
| X1 | AE input corruption (`get_corrupted_input`) | `rng.binomial(...)` | No — `corruption_level=0`, never called |
| X2–X4 | Node scoring (`tracker.nodeScore`/`scoreClass`) | Pure arithmetic accumulators | **No** |
| X2–X4 | Pattern recognizers (`RMSEPatternRecognizerDist`) | `np.mean`/`np.linalg.norm` centroid+tolerance | **No** |
| X2–X4 | `nodeScore.name` (`tracker.py:112`) | `random.choice` of 4 letters | No — a cosmetic node name, unused in `offline` mode, never enters a score |
| Kitsune | Median+MAD threshold | Deterministic on the RMSE stream | Only via X1's RMSEs |

**Conclusion — exactly one stage is perturbed by the seed: KitNET autoencoder
weight initialization (X1).** Everything downstream (node scores, pattern
centroids/tolerances, the fused η-normalized distance `out[9]`, the committed
OR-rule, the Kitsune Median+MAD point) is a **deterministic function of the
resulting RMSE stream**. Because `results.py`/`tracker.py` never consume the
global `np.random`/`random` state in any score-affecting path, setting
`np.random.seed(42)` (as the paper does) leaves the committed mixed-stream
metrics **unchanged** — the committed run is deterministic, pinned by
`RandomState(1234)`.

To genuinely exercise seed sensitivity we therefore had to override that
hard-coded init seed. The perturbation propagates as:

```
seed → KitNET AE weight init W ~ U[-1/n, 1/n]  (X1, the only RNG)
     → per-packet RMSE stream (X1 output)
     → node scores + pattern centroids/tolerances (X2–X4, deterministic)
     → fused distance nd_g / nd_s / cont (deterministic)
     → committed OR-rule + orrule@2% + Kitsune metrics (deterministic)
```

### How the seed was injected (no source edits)

The harness (`run_one_seed.py`) monkey-patches the imported
`KitNET.dA.dA.__init__` at runtime so each autoencoder draws `W` from
`RandomState(seed)` instead of `RandomState(1234)`, reproducing the exact init
math (`W ~ U[-1/n_visible, +1/n_visible]`, `hbias=vbias=0`). No file in the
repository source tree is modified; all outputs live under
`results/CICIoT2023/seed_robustness/`. For `seed=1234` the patch is a no-op and
the run is bit-identical to the committed one (verified).

---

## 2. Across-seed results (n = 6 seeds: 1, 7, 42, 123, 1234, 2024)

Test region = 60,000 benign negatives + 300,000 attack positives (single stream,
node state carried across all six attack blocks, `benignLimit=60000`, single-tanh).
95% CI = Student-t interval, `mean ± t₀.₉₇₅,₅ · s/√6` (sample std, ddof=1).

### Tenko — committed operating point η = (50, 20)

| Metric | mean ± 95% CI | std | range |
|---|---|---|---|
| TPR | 0.8799 ± 0.0035 | 0.00333 | [0.8766, 0.8860] |
| FPR | 0.0076 ± 0.0007 | 0.00065 | [0.0069, 0.0088] |
| Precision | 0.9983 ± 0.0001 | 0.00014 | [0.9980, 0.9984] |
| micro-F1 | 0.9354 ± 0.0019 | 0.00184 | [0.9335, 0.9387] |
| Accuracy | 0.8987 ± 0.0028 | 0.00270 | [0.8959, 0.9036] |
| **AUC-ROC** | **0.9890 ± 0.0004** | **0.00040** | [0.9885, 0.9897] |
| AUC-PR | 0.9979 ± 0.0001 | 0.00007 | [0.9978, 0.9980] |

### Tenko — orrule@2% (η re-derived per seed from that seed's benign — principled)

| Metric | mean ± 95% CI | std | range |
|---|---|---|---|
| TPR | 0.9793 ± 0.0014 | 0.00132 | [0.9773, 0.9811] |
| FPR | 0.0200 ± 0.00002 | 0.00002 | [0.0200, 0.0200] |
| Precision | 0.9959 ± 0.00001 | 0.00001 | [0.9959, 0.9959] |
| micro-F1 | 0.9875 ± 0.0007 | 0.00067 | [0.9865, 0.9885] |
| Accuracy | 0.9794 ± 0.0011 | 0.00110 | [0.9778, 0.9809] |
| **AUC-ROC** | **0.9890 ± 0.0004** | **0.00040** | [0.9885, 0.9897] |
| AUC-PR | 0.9979 ± 0.0001 | 0.00007 | [0.9978, 0.9980] |

### Tenko — orrule@2% (committed thresholds η=(30.14, 3.14) **held fixed** across seeds)

| Metric | mean ± 95% CI | std | range |
|---|---|---|---|
| TPR | 0.9799 ± 0.0011 | 0.00102 | [0.9787, 0.9818] |
| FPR | 0.0216 ± 0.0022 | 0.00212 | [0.0200, 0.0249] |
| Accuracy | 0.9797 ± 0.0006 | 0.00061 | [0.9789, 0.9806] |
| AUC-ROC | 0.9890 ± 0.0004 | 0.00040 | [0.9885, 0.9897] |

### Kitsune baseline (scores are seed-dependent via KitNET's RMSEs)

| Operating point | Metric | mean ± 95% CI | std |
|---|---|---|---|
| Median+MAD | TPR | 0.9622 ± 0.0014 | 0.00133 |
| Median+MAD | **FPR** | **0.1885 ± 0.0142** | **0.01354** |
| Median+MAD | Accuracy | 0.9370 ± 0.0017 | 0.00164 |
| Median+MAD | AUC-ROC | 0.9727 ± 0.0006 | 0.00063 |
| @2% FPR | TPR | 0.8567 ± 0.0030 | 0.00289 |
| @2% FPR | AUC-ROC | 0.9727 ± 0.0006 | 0.00063 |

---

## 3. AUC (threshold-free) vs operating-point stability

This is the key robustness message.

- **AUC-ROC is essentially seed-invariant:** std **0.00040** (≈0.04 pp), a
  coefficient of variation of **0.04%**. AUC-PR std is **0.00007** (CV 0.007%).
  The seed shifts the ranking of packets by fused distance so slightly that the
  area under the curve barely moves; the full spread over 6 seeds is only
  0.9885–0.9897 for AUC-ROC.
- **Operating-point metrics are marginally more seed-sensitive but still tiny**,
  because a fixed threshold on a slightly-perturbed score can flip a handful of
  borderline packets:
  - Committed η(50,20): TPR CV = 0.0033/0.880 = **0.38%**; the largest *relative*
    wobble is FPR (CV 8.6%) but on a minuscule absolute base (0.69%–0.88% FPR).
  - **orrule@2% re-derived pins FPR to 2% exactly** (std 2×10⁻⁵ — it is a benign
    quantile by construction), so only TPR varies, and only by ±0.0014.
- **Contrast — Kitsune's Median+MAD point is ~30× more seed-sensitive on FPR**
  (std 0.0135, range 16.5%–20.5%) than Tenko's operating point, because a fixed
  median+3·1.4826·MAD cut sits on a fat benign tail whose shape shifts with the
  seed. Tenko's benign-quantile calibration is inherently more seed-robust.

**Takeaway for the paper:** report AUC-ROC/AUC-PR as the headline (they are
seed-invariant to 3–4 decimals), and report operating-point metrics as
`mean ± CI` over seeds. Tenko's advantage over Kitsune holds at every seed.

---

## 4. Re-derived vs held-fixed thresholds (the principled question)

The task asks whether the orrule@2% η were re-derived per seed or held fixed. We
did **both**, and it matters:

- **Re-derived (principled):** for each seed we jointly bisected the per-signal
  tail probability so the benign OR-flag rate on **that seed's** benign test
  region equals 2% (same routine as `mixed/_calibrated_operating_point.py`). This
  keeps the operating point *honest* — FPR is pinned at 0.0200 ± 0.00002 across
  all seeds, and TPR is 0.9793 ± 0.0014. The re-derived η drift a little with the
  seed (η_g ∈ [30.1, 35.5], η_s ∈ [2.8, 3.15]), exactly compensating the RMSE
  perturbation to hold FPR fixed.
- **Held fixed (committed η=30.14/3.14 from seed 1234, applied to all seeds):**
  FPR is no longer pinned — it drifts to **0.0216 ± 0.0022 (up to 2.49%)** because
  the benign distribution shifts slightly per seed while the thresholds do not.
  TPR is essentially unchanged (0.9799 ± 0.0011).

**Recommendation:** re-derive η from benign per run (the principled choice); it
costs nothing (a benign quantile) and makes the reported FPR seed-invariant. If
thresholds must be frozen for deployment, expect FPR to wander by ≈±0.2 pp around
the 2% target — still tight, but no longer exact.

---

## 5. Per-attack TPR stability (Tenko)

| Attack | committed η(50,20) mean ± std | orrule@2% re-derived mean ± std |
|---|---|---|
| DoS-SYN_Flood | 0.9906 ± 0.0007 | 0.9919 ± 0.0003 |
| DDoS-UDP_Flood | 0.9249 ± 0.0016 | 0.9547 ± 0.0014 |
| Recon-OSScan | 0.6208 ± 0.0067 | 0.9471 ± 0.0062 |
| MITM-ArpSpoofing | 0.9750 ± 0.0015 | 0.9964 ± 0.0002 |
| Mirai-greeth_flood | 0.9654 ± 0.0021 | 0.9889 ± 0.0005 |
| DictionaryBruteForce | 0.8026 ± 0.0091 | 0.9967 ± 0.0009 |

The volumetric/rich attacks are seed-invariant to the fourth decimal. The two
low-rate attacks (Recon-OSScan, DictionaryBruteForce) are the most seed-sensitive
under the ultra-tight committed η (std 0.0067 / 0.0091) — but even their spread is
< 1 pt, and the principled orrule@2% both lifts them (0.62→0.95, 0.80→0.997) and
tightens their variance.

---

## 6. Paste-ready LaTeX

```latex
% Multi-seed robustness on the CICIoT2023 MIXED stream (n=6 seeds: 1,7,42,123,1234,2024).
% Seed perturbs ONLY the KitNET autoencoder weight init (KitNET/dA.py); all
% downstream stages are deterministic. Values are mean $\pm$ 95\% CI (Student-t).
\begin{table}[t]
\centering
\caption{Seed robustness of Tenko on the CICIoT2023 mixed stream (60k benign +
300k attack), across six random seeds. AUC-ROC/AUC-PR are threshold-free;
operating-point rows use the committed $\eta{=}(50,20)$ and a per-seed
benign-calibrated OR-rule at 2\% FPR. Kitsune (Median+MAD) shown for reference.
Values are mean $\pm$ 95\% CI.}
\label{tab:seed_robustness_ciciot2023}
\small
\begin{tabular}{llccccc}
\toprule
Detector & Operating point & TPR & FPR & micro-F1 & AUC-ROC & AUC-PR \\
\midrule
Tenko   & committed $\eta(50,20)$   & $0.8799 \pm 0.0035$ & $0.0076 \pm 0.0007$ & $0.9354 \pm 0.0019$ & $0.9890 \pm 0.0004$ & $0.9979 \pm 0.0001$ \\
Tenko   & orrule@2\% (re-derived)   & $0.9793 \pm 0.0014$ & $0.0200 \pm 0.0000$ & $0.9875 \pm 0.0007$ & $0.9890 \pm 0.0004$ & $0.9979 \pm 0.0001$ \\
Tenko   & orrule@2\% (fixed $\eta$) & $0.9799 \pm 0.0011$ & $0.0216 \pm 0.0022$ & $0.9877 \pm 0.0004$ & $0.9890 \pm 0.0004$ & $0.9979 \pm 0.0001$ \\
Kitsune & Median+MAD                & $0.9622 \pm 0.0014$ & $0.1885 \pm 0.0142$ & $0.9622 \pm 0.0010$ & $0.9727 \pm 0.0006$ & $0.9948 \pm 0.0001$ \\
Kitsune & @2\% FPR                  & $0.8567 \pm 0.0030$ & $0.0200 \pm 0.0000$ & $0.9209 \pm 0.0018$ & $0.9727 \pm 0.0006$ & $0.9948 \pm 0.0001$ \\
\bottomrule
\end{tabular}
\end{table}
```

---

## 7. Honest stability statement

> **Is Tenko stable across random seeds? Yes.** On the CICIoT2023 mixed stream,
> the only source of model randomness that affects detection is the KitNET
> autoencoder weight initialization (`KitNET/dA.py`, hard-coded to
> `RandomState(1234)`); the entire downstream Tenko/Kitsune scoring path is
> deterministic given the resulting RMSE stream. Varying that init seed over six
> values `{1,7,42,123,1234,2024}` and re-running the full pipeline, Tenko's
> **threshold-free AUC-ROC is 0.9890 ± 0.0004 (std 0.0004)** and **AUC-PR is
> 0.9979 ± 0.0001** — effectively seed-invariant. Operating-point metrics move
> only in the third decimal: at the committed $\eta{=}(50,20)$, TPR = 0.8799 ±
> 0.0035 and FPR = 0.0076 ± 0.0007; at a per-seed benign-calibrated OR-rule with
> the threshold **re-derived from each seed's benign** (the principled choice),
> FPR is pinned at 0.0200 ± 0.00002 and TPR = 0.9793 ± 0.0014. If the committed
> thresholds are instead **held fixed** across seeds, FPR drifts to 0.0216 ±
> 0.0022 (up to 2.5%) — which is precisely why we re-derive $\eta$ per seed and
> report both. Tenko's separation of benign from attack is thus not an artifact
> of the paper's single seed=42; the seed=42 run in fact reproduces the committed
> (seed 1234) numbers to within these CIs, and the committed detection metrics
> are deterministic with respect to the global NumPy/Python seed the paper sets.

**Caveats / faithfulness.**
- Benign FPR is calibrated in-sample on the 60k benign test region (no dedicated
  held-out benign array exists in this pipeline), identical to the committed
  `mixed/_calibrated_operating_point.py` convention — the seed sweep changes only
  the seed, not this convention, so cross-seed comparison is exact.
- The seed does **not** vary the *stream* (packets/labels are fixed); it varies
  only the model's random init, which is the correct target for a "robustness to
  random seed" study. Data-split/subsampling robustness is a separate axis (see
  the prevalence sweep) and is out of scope here.

---

## 8. Files & reproduction

All under `results/CICIoT2023/seed_robustness/`:

- `run_one_seed.py` — full-pipeline driver for one seed (installs the KitNET
  init-seed patch, runs X1→X2–X4→Kitsune, writes `_seed<seed>.json` + arrays).
- `run_sweep.sh` — runs a list of seeds sequentially.
- `seed_metrics.py` — metric definitions (identical semantics to
  `mixed/_calibrated_operating_point.py`), validated against the committed arrays.
- `aggregate_seeds.py` — builds `seed_robustness_metrics.csv` + across-seed stats.
- `seed_robustness_metrics.csv` — **per-seed raw rows** (30 rows = 6 seeds × 5
  operating points; `is_committed_seed=1` marks seed 1234).
- `_seed_robustness_stats.json` — mean/std/95%CI per metric (machine-readable).
- `arrays/` — per-seed cached `rmse_raw`, `arr_ndg/nds/cont/gold/pred`, Kitsune
  scores (so the analysis can be recomputed without re-running X1).
- `log_seed*.txt`, `log_sweep.txt` — run logs (X1 timing ≈ 545–629 s/seed).

Reproduce:

```bash
# one seed (≈11 min: X1 ≈ 10 min + X2–X4 ≈ 1 min)
MPLBACKEND=Agg MPLCONFIGDIR=results/CICIoT2023/seed_robustness/mplcache \
  .venv/bin/python results/CICIoT2023/seed_robustness/run_one_seed.py --seed 42

# full sweep + aggregate
bash results/CICIoT2023/seed_robustness/run_sweep.sh 42 1 7 123 2024
.venv/bin/python results/CICIoT2023/seed_robustness/run_one_seed.py --seed 1234   # committed baseline
.venv/bin/python results/CICIoT2023/seed_robustness/aggregate_seeds.py
```

Sanity: the `seed=1234` run prints
`seed=1234 reproduces committed arrays exactly: True` and its metrics match the
committed mixed memo (committed η: TPR 0.8793 / FPR 0.0069 / AUC 0.9897;
orrule@2%: TPR 0.9801 / FPR 0.0200 / AUC 0.9897 with η=(30.14, 3.14)).
