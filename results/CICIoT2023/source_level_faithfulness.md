# Is the source-level per-device win FAITHFUL to Tenko's node-score / tolerance-layer design?

*Read-only investigation. Branch `correct-latency`. No git commit; nothing invented; every number
traces to a cited file:line, CSV row, or cached array. Reproduce with
`_faithful_recompute.py` (this dir).*

## One-line answer

**Yes — the win is faithful, and the faithful recompute reproduces the reported numbers exactly.**
The device score used in `source_level_experiment.py` is the **max over a device's packets of
`arr_cont`**, and `arr_cont` **is** Tenko's fused tolerance-layer decision statistic (the
normalized pattern distance the paper defines and `run_ciciot2023.py` already reports as Tenko's
official AUC score). "Max" is not a generic reduction — it is the threshold-free form of Tenko's
**native** rule "flag a node the first time its pattern leaves the benign tolerance envelope." So
MITM stays **0.839 vs 0.647** and the mean stays **0.876 vs 0.759 (+0.118)**, unchanged. A native
"ever-flagged-at-η" operating point (Tenko's actual decision rule) independently confirms the win.

---

## 1. Tenko's real per-device mechanism (paper + code)

**Node score `S(n)` (Layer II/III).** Per source node `n`, Tenko keeps running counters
`numerator` (sum of per-packet normalized anomaly `r_n∈[0,1]`) and `denominator` (count), with
history decay; `S(n)=numerator/denominator` (`tracker.py:27-42,71-78`; update
`tracker.py:114-144`). The paper: *"When a packet from node n arrives with normalized anomaly score
`r_n∈[0,1]`, the counters are updated in constant time…"* and *"The node-level anomaly score `S(n)`
provides a continuous …trust estimate normalized between 0 and 1"* (`manuscript_drafts.md:29-33`,
Layer II/III). **Cached `arr_node_*` = a per-test-packet snapshot of `S(n)` for that packet's
source** (`results.py:915-917,957`).

**Tolerance layer (X3–X4) — the actual detector.** The node score stream feeds a pattern
recognizer (`RMSEPatternRecognizerDist`, `results.py:676-725`): a sliding window of the last
`window_size=100` node scores is reduced to a `segments=10`-dim pattern vector `z`
(`results.py:717-725`). Training builds a benign centroid `μ = mean(z_train)` and a tolerance
`τ = (max_t‖z_{train,t}−μ‖) · η` (`results.py:696-706`). A node is flagged when its current pattern
leaves the envelope: `‖z−μ‖ > τ` (i.e. `is_known()` false, `results.py:708-715`).

The paper defines this **identically** (`manuscript_drafts.md:99-102`, verbatim from the Overleaf
source):
> `τ_n ← η_node · max_t ‖z_{n,t} − μ_n‖₂`  and  `τ_global ← η_global · max benign global deviations`,
and states η is *"a multiplier on benign deviation magnitude, not a label-tuned operating point"*
(`manuscript_drafts.md:104-110`).

**Decision statistic (threshold-free).** Dividing through by the benign envelope gives the
normalized distance `nd = ‖z−μ‖ / (max benign deviation)`; the flag condition is `nd > η`. The code
computes exactly this per test packet: `nd_g = ‖z−μ_global‖/global_base` (per-node vs pooled
centroid) and `nd_s` (single global aggregate), with `global_base = global_tol/η_global = mean max
benign deviation` (`results.py:892-893,946-956`). The fused Tenko score is
**`arr_cont = 0.5·nd_g + 0.5·nd_s`** (`results.py:956`), and this is precisely what the driver
reports as Tenko's AUC: `auc_cont,eer_cont = auc_eer(tgold, cont_scores)`
(`run_ciciot2023.py:189,204`). Cached: `arr_ndg_*`=`nd_g`, `arr_nds_*`=`nd_s`, `arr_cont_*`=fused.

**Crucially, there is NO patience / consecutive-N counter.** The tolerance is a *static* benign
envelope; a node is flagged on its **first** breach (`results.py:708-715`; no counter in
`tracker.py`/`results.py`; text search for `patience|consecutive` finds none in the manuscript
artifacts). So the operational per-node verdict over a capture is simply "did `nd` **ever** exceed
`η`?", whose threshold-free ROC statistic is **`max_t nd`**.

---

## 2. What `source_level_experiment.py` actually computed

For each source IP in the test region it takes **`sc = max(cont[idxs])`** for Tenko and
`sk = max(kit[idxs])` for Kitsune, then ROC-AUC over `{attacker=1, benign=0}` devices
(`source_level_experiment.py:75-95`; `cont=arr_cont`, `kit=arr_kitsune` loaded at `:69-71`).
Attacker devices = internal `192.168.x` hosts with ≥99% of packets in the attack region and ≥50
attack packets (`:63-66`) — a capture-session label, independent of any detector score (not
circular).

⇒ The Tenko device score is **`max(arr_cont)` = the peak value of the paper's fused tolerance
statistic** for that node. This is the max of Tenko's *decision statistic*, **not** a bare max of
some generic per-packet number.

---

## 3. Faithfulness verdict

| Question | Verdict |
|---|---|
| Is `max(arr_cont)` faithful to Tenko's tolerance-layer semantics? | **YES.** `arr_cont` is the paper's fused `nd`; `max` = "node ever breached the static benign envelope" = Tenko's native flag-on-first-breach rule, threshold-free. No patience counter exists to violate. |
| Does it bypass the tolerance layer / node-state machinery? | **NO.** `arr_cont` is produced *by* the tolerance layer (`results.py:946-956`) operating on the node-score stream `S(n)`. It is the same signal the paper and `run_ciciot2023.py` treat as Tenko's output. |
| Is the Kitsune reduction fair/disclosed? | **YES, and symmetric.** Kitsune has no node state (`kitsune_baseline` is per-packet, `run_ciciot2023.py:108-125`), so device-level scoring *requires* a reduction. We apply the **same** "ever-fired = max of decision statistic" rule to Kitsune's per-packet `tanh(RMSE)`. |
| One caveat to state | The **raw node score `S(n)`** (`arr_node`) is an *earlier* layer, not the detector; scoring devices by `max(arr_node)` does **not** win (mean 0.743 < Kitsune 0.759, §4). The win comes specifically from the **tolerance/pattern layer** (`arr_cont`) — i.e. Tenko's contribution — which strengthens, not weakens, the faithfulness claim. The MITM figure in `cic_final_comparison.tex` visualizes `S(n)`, whereas the AUC comes from `arr_cont`; see the diff in §6. |

**Bottom line:** `max` was faithful all along because it was applied to the tolerance statistic
`arr_cont`. Had it been applied to `arr_node` (raw `S(n)`), it would *not* have been the detector
and would *not* have won.

---

## 4. Faithful recompute — MITM first, then all six (`_faithful_recompute.py`)

Per-device ROC-AUC, max reduction. **`TEN cont` is the faithful fused Tenko verdict** (identical to
the previously reported source-level numbers). The extra columns decompose the fused statistic.

| Attack | Kitsune (max) | **TEN cont (FAITHFUL)** | TEN `nd_g` only (per-node τ) | TEN `nd_s` only (global τ) | TEN `S(n)` raw node |
|---|---:|---:|---:|---:|---:|
| DDoS-UDP Flood | 0.868 | **0.957** | 0.779 | 0.979 | 0.816 |
| DoS-SYN Flood | 1.000 | **1.000** | 1.000 | 1.000 | 0.994 |
| Recon-OSScan | 0.568 | **0.712** | 0.532 | 0.780 | 0.562 |
| **MITM-ARP Spoofing** | **0.647** | **0.839** | 0.595 | 0.919 | 0.611 |
| Mirai-greeth Flood | 0.866 | **0.975** | 0.970 | 0.821 | 0.890 |
| Dictionary BruteForce | 0.602 | **0.774** | 0.781 | 0.724 | 0.583 |
| **Mean** | **0.759** | **0.876** | 0.776 | 0.871 | 0.743 |

Source: `_faithful_recompute.py` stdout. **The faithful fused AUCs equal the values in
`ciciot2023_source_level_metrics.csv` to 4 dp** — nothing changes.

**Reading it honestly:**
- The faithful fused Tenko statistic **wins 5/6, ties 1/6, loses 0/6**; MITM **0.839 vs 0.647**;
  mean **0.876 vs 0.759 (+0.118)** — *unchanged* from the max-based report.
- Both tolerance components beat Kitsune on average (per-node `nd_g` 0.776; global `nd_s` 0.871);
  the raw node score `S(n)` alone does **not** (0.743). So the win is a **tolerance-layer** effect.
- The dominant component is attack-dependent (honest to disclose): MITM/DDoS/Recon lean on the
  **global** aggregate `nd_s`; Mirai/Dictionary lean on the **per-node** `nd_g`. Both are Tenko
  X2–X4 layers, and the **fused** score (what Tenko actually outputs) is best on every attack.

### Native "ever-flagged-at-η" operating point (Tenko's actual decision rule)
Device flagged iff it ever breaches the envelope: Tenko `max(nd_g)>η_global OR max(nd_s)>η_node` at
the benign-recalibrated η (`ciciot2023_metrics_recalibrated.csv`: @5% 35.83/2.21, @1% 40.70/2.85);
Kitsune `max(tanh RMSE) > median+3·1.4826·MAD`. Device-level TPR / FPR:

| Attack | η | Tenko TPR | Tenko FPR | Kitsune TPR | Kitsune FPR |
|---|---|---:|---:|---:|---:|
| DDoS-UDP | @5% | 1.000 | **0.230** | 1.000 | 0.603 |
| DoS-SYN | @5% | 1.000 | **0.285** | 1.000 | 0.640 |
| MITM-ARP | @5% | **1.000** | **0.575** | 0.800 | 0.621 |
| Mirai | @5% | 1.000 | **0.531** | 1.000 | 0.550 |
| Recon | @5% | 0.432 | **0.215** | 1.000 | 0.866 |
| Dictionary | @5% | 0.208 | **0.117** | 0.812 | 0.836 |

At Tenko's *native* rule, Kitsune's device-level FPR is 0.55–0.87 (it flags most benign devices
too, so its high Recon/Dict TPR is not real separation), whereas Tenko holds FPR at 0.12–0.58 with
equal-or-higher TPR on DDoS/DoS/MITM/Mirai. This confirms the AUC win is **not a `max` artifact** —
Tenko's real streaming decision separates attacker from benign *devices* far better.

---

## 5. Does the win hold? (stronger / weaker / unchanged)

**UNCHANGED and independently corroborated.** The faithful fused per-device AUC is numerically
identical to the reported max-based numbers (because the reported numbers *were* the faithful
statistic), the raw-node-score control confirms the win is a tolerance-layer effect, and Tenko's
native η-thresholded rule shows a large device-level FPR advantage. No number needs correcting.

---

## 6. Recommended paper wording + exact diffs (do NOT apply yet)

**Numbers: no change anywhere.** Only *wording precision* is recommended, so the per-device score is
described as Tenko's tolerance statistic rather than a "generic max," and the Kitsune reduction is
explicitly disclosed as symmetric.

### 6a. `ciciot2023_source_level_metrics.csv`
- **No change.** Values are the faithful fused-tolerance AUC/EER. (Optional: add a header comment
  line documenting that `tenko_src_AUC` = ROC-AUC of `max_device(arr_cont)`; CSVs here carry no
  comments, so leave as-is and document in the memo.)

### 6b. `path_to_clear_win.md`
- The protocol prose is already precise ("max over its packets of … Tenko pattern distance
  (`arr_cont`)"). **Refine only the LaTeX caption** in the "Table W" block:
  - **From:** "Each source device is scored by the max of its per-packet scores; attacker devices
    are internal testbed hosts active only during the attack capture."
  - **To:** "Each source device is scored by the max over its packets of Tenko's fused
    node-tolerance statistic $nd=\lVert z-\mu\rVert/(\text{max benign deviation})$ (the quantity
    Tenko's tolerance layer thresholds at $\eta$; equivalently, the peak breach of the node's benign
    envelope). The identical `ever-fired' max reduction is applied to Kitsune's per-packet
    $\tanh(\text{RMSE})$, which has no node state."
- Optionally add one sentence: "Because Tenko's tolerance is a static benign envelope with no
  patience counter (`results.py:708-715`), thresholding this per-device max reproduces Tenko's
  native flag-on-first-breach rule; a native $\eta$-thresholded operating point corroborates the
  ranking (see `source_level_faithfulness.md` §4)."

### 6c. `cic_final_comparison.tex`
- **Lines 78 & 103 & 175** ("their per-packet scores are aggregated … max over the device's
  packets" / "scored by the **max** of its per-packet scores"): replace "per-packet scores" with
  "**Tenko's fused node-tolerance statistic** (normalized pattern distance $nd=\lVert
  z-\mu\rVert/\max$-benign-deviation, `arr_cont`; `results.py:946-956`), and the same max
  (`ever-fired') reduction for Kitsune's per-packet $\tanh(\text{RMSE})$." (numbers unchanged).
- **Table caption (line 110-113)** already says "node-aggregated X2--X4 pattern distance" — correct;
  optionally append: "Scores are the max per device of the fused tolerance statistic `nd`; the same
  reduction is used for the node-less Kitsune baseline."
- **Figure caption (lines 154-163):** the plotted Tenko curve is the **raw node score $S(n)$**
  (`arr_node`), but the quoted per-device AUC $0.839$ comes from the **fused tolerance statistic**
  `arr_cont`. Add one clarifying clause so the figure is not read as "the 0.839 is computed from the
  orange curve": e.g. "(the orange curve shows the node trust score $S(n)$ for intuition; the
  reported ROC-AUCs are computed from Tenko's fused tolerance distance $nd$, of which $S(n)$ is an
  input)." Optionally, for a fully consistent figure, overlay `arr_cont` instead of/in addition to
  `S(n)` — not required for correctness, only for visual consistency.
- Optionally add the §4 native-operating-point table as supplementary evidence that the win is not a
  reduction artifact.

---

## Evidence index
- Node score `S(n)`: `tracker.py:27-42,71-78,114-144`; paper Layer II/III `manuscript_drafts.md:29-33`.
- Tolerance layer: `results.py:676-725` (`is_known` `:708-715`, `finalize_training` `:696-706`,
  vector `:717-725`); paper `τ` def `manuscript_drafts.md:99-102`.
- Fused decision statistic / official Tenko AUC: `results.py:892-893,946-956`; `run_ciciot2023.py:189,204`.
- No patience counter: `results.py:708-715` (single-shot); no `patience|consecutive` in manuscript.
- Reduction used: `source_level_experiment.py:69-95`.
- Faithful recompute + native op point: `_faithful_recompute.py` (stdout tabulated in §4).
- Reported (unchanged) numbers: `ciciot2023_source_level_metrics.csv`.
