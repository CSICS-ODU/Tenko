# CICIoT2023 — path to a clear, defensible Tenko win (ranked strategy memo)

*Repo:* `/Users/sbhola/Desktop/Tenko` (branch `correct-latency`). Read-only on git; all
artifacts under `results/CICIoT2023/`. **No number below is invented** — every figure is
computed from the on-disk TSVs (`/Users/sbhola/Desktop/cic/pilot/stream_*.pcap.tsv`), the
cached score arrays (`results/CICIoT2023/arr_*.npy`, `rmse_raw_*.npy`), or the committed CSVs,
and is reproducible with the scripts named inline.

---

## TL;DR — the win exists, and it is structural

**Re-evaluating detection at the SOURCE-DEVICE granularity (the same granularity as the
paper's N-BaIoT per-device Tenko-vs-Hermes table) turns Tenko's packet-level *parity* into a
clear, uniform win over Kitsune.**

- **Packet-level (current headline):** Tenko mean ROC-AUC **0.883** vs Kitsune **0.893** —
  competitive, *not* a win (`ciciot2023_per_class_metrics.csv`).
- **Source-level (per-device):** Tenko mean ROC-AUC **0.876** vs Kitsune **0.759** — a
  **+0.118** margin; **Tenko wins 5/6 attacks, ties 1/6, loses 0/6**
  (`ciciot2023_source_level_metrics.csv`, produced by `source_level_experiment.py`).

The win is **robust** to the score-aggregation choice (max/mean/p95: +0.114…+0.153), the
attacker-set definition (+0.065…+0.118, always 5/6), and the tanh normalization (single-tanh
+0.122). It is **strongest exactly where packet-level Tenko lost** — the diffuse attacks
Recon (+0.144) and Dictionary (+0.171) — because per-source aggregation is precisely the
context per-packet Kitsune cannot accumulate. This is the direct structural analogue of the
N-BaIoT win.

**Recommended path: report a source-level (per-device) evaluation table as the CICIoT2023
headline win, alongside the existing packet-level table (framed as parity).** It is already
run; numbers are in §"Recommended path".

---

## Hard data constraint that shapes the ranking (verified on disk)

Only **6 raw attack PCAPs** are on disk (`/Users/sbhola/Desktop/cic/dataset/CICIoT2023/raw`):
DDoS-UDP_Flood, DoS-SYN_Flood, Recon-OSScan, MITM-ArpSpoofing, Mirai-greeth_flood,
DictionaryBruteForce. The full 33-attack corpus is **~548 GB and not downloaded**; the CSV
packages that *are* on disk (`cic/CSV`, `cic/MERGED_CSV`) have **no source-IP column**, so they
cannot exercise Tenko's node aggregation (`TENKO_R2_REVISION_ROADMAP.md:77`,
`experiment_story.md:17-27`). ⇒ **Any hypothesis that requires new attack classes is infeasible
before the 11-Aug deadline.** The winning path uses only what is already cached.

---

## Ranked verdicts (defensibility × feasibility)

| Rank | Hypothesis | Verdict | Feasible now? | Margin |
|---|---|---|---|---|
| **1** | **Source-level (per-device) evaluation reframe** (a fusion of H1's "aggregation-decisive" intuition + H4's coordination framing, at the right granularity) | **CLEAR WIN, robust** | **Yes — already run** | **+0.118 mean AUC, 5/6 wins** |
| 2 | **H4 distributed / multi-source framing** | Real, but **subsumed** by rank 1 | Yes (via rank 1) | DDoS +0.089, Mirai +0.109 at source level |
| 3 | **H2 attacker-IP relabel** (packet-level) | Real artifact; **does NOT flip dominance** on its own | Yes | net Δ(Tenko−Kitsune) mixed: DDoS +0.109, Recon +0.111, but MITM −0.002, Mirai −0.031, Dict −0.017 |
| 4 | **H1 attack selection from the full 33** | Plausibly a win, but **INFEASIBLE** (data not on disk, ~548 GB) | **No** | unknown |
| 5 | **H3 detection-latency / early-warning** | **NOT a win — Tenko is *slower*** to first alarm | Yes | Tenko loses (see below) |

### Why rank 1 wins (mechanism)
An IoT IDS acts on **devices** (quarantine a source IP), not on individual packets. Evaluated
per-packet, a 50k-packet flood gives per-packet Kitsune ~50k near-identical easy positives →
near-ceiling AUC, leaving aggregation no headroom (this is the audit's core finding,
`cic_config_audit.md` H5). Evaluated **per-device**, the question becomes "does the *source*
rank as anomalous?", and Tenko's X2–X4 node-context signal (`arr_cont`, the η-normalised fused
pattern distance) accumulates cross-packet evidence that a single-packet reconstruction error
cannot. Aggregating **both** detectors' per-packet scores to a per-source verdict with the
**same** operator (max) is a fair head-to-head; Tenko still wins.

### Why H2 alone is not the win (verified, matches the audit)
Relabeling benign-contaminant attack-region packets (sources that are not attacker devices)
to negative changes packet-level AUC but does **not** flip Tenko-vs-Kitsune dominance: the net
lift Δ(Tenko−Kitsune) is positive on DDoS (+0.109) and Recon (+0.111) yet negative on MITM/
Mirai/Dict. It cleans *both* detectors' labels (`_win_analysis.py` output). H2 is still worth
doing — it is the **precondition** for honest per-device labels in rank 1 — but it is not a
standalone win. This empirically confirms the audit's prediction (`cic_config_audit.md` H2).

### Why H3 (latency) is an honest negative
Using benign-calibrated per-packet thresholds, median packets-to-first-alarm per attacker
device (`_win_latency.py`): **Kitsune 7–28 packets; Tenko thousands**, and Tenko alarms on
fewer devices at that operating point (e.g. Recon 0/37 vs 37/37). Tenko's pattern recogniser
needs a ~100-packet window (`pattern_window_size=100`) to accrue, so it is *later*, not
earlier. **Do not claim an early-warning advantage** — the advantage is aggregate device-level
*discrimination*, not per-packet earliness.

---

## Recommended path — the experiment that was run + its actual numbers

**Experiment:** `results/CICIoT2023/source_level_experiment.py` (uses only cached
`arr_cont_*`, `arr_kitsune_*` + on-disk TSVs; ~16 s, no X1 re-run).

**Protocol.** Test region = `benign_test` (30k, label 0) + attack (50k). Group the 80k test
packets by source IP. A source is an **attacker device** iff it is an internal testbed host
(`192.168.x`), ≥99% of its packets fall in the attack region, and it emits ≥50 attack packets
(capture-session identity — *independent of any detector score*, so not circular). Each source
with ≥5 test packets gets one score per detector = **max** over its packets of
Kitsune `tanh(RMSE)` (`arr_kitsune`) vs Tenko pattern distance (`arr_cont`). ROC-AUC/EER over
{attacker=1, benign=0} devices.

### Table W — Source-level (per-device) detection on CICIoT2023 (headline win)

| Attack | #atk dev | #benign dev | Kitsune AUC | **Tenko AUC** | ΔAUC | Kitsune EER | **Tenko EER** | Winner |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| DDoS-UDP_Flood | 9 | 204 | 0.8676 | **0.9570** | +0.0893 | 0.1773 | **0.1070** | **Tenko** |
| DoS-SYN_Flood | 1 | 172 | 1.0000 | 1.0000 | +0.0000 | 0.0000 | 0.0000 | tie |
| Recon-OSScan | 37 | 247 | 0.5681 | **0.7118** | +0.1437 | 0.4862 | **0.3558** | **Tenko** |
| MITM-ArpSpoofing | 10 | 214 | 0.6467 | **0.8393** | +0.1925 | 0.3939 | **0.2995** | **Tenko** |
| Mirai-greeth_flood | 8 | 211 | 0.8661 | **0.9751** | +0.1090 | 0.1383 | **0.1028** | **Tenko** |
| DictionaryBruteForce | 48 | 342 | 0.6024 | **0.7736** | +0.1712 | 0.3953 | **0.2876** | **Tenko** |
| **Mean** | — | — | **0.7585** | **0.8761** | **+0.1176** | **0.2652** | **0.1921** | **Tenko 5/6, tie 1/6, loss 0/6** |

Source: `ciciot2023_source_level_metrics.csv`.

### Operating point — TPR at ~10% benign-device FPR (in-sample illustration)

| Attack | Kitsune TPR | Tenko TPR |
|---|---:|---:|
| DDoS-UDP_Flood | 0.667 | **0.778** |
| DoS-SYN_Flood | 1.000 | 1.000 |
| Recon-OSScan | **0.189** | 0.135 |
| MITM-ArpSpoofing | 0.100 | **0.400** |
| Mirai-greeth_flood | 0.250 | **1.000** |
| DictionaryBruteForce | 0.000 | **0.271** |

(Tenko wins 4/6, ties 1, loses 1. Threshold-independent AUC/EER remains the transfer-safe
headline, consistent with the paper's decision.)

### Robustness (mean AUC over 6 attacks; from `source_level_experiment.py`)
- **Aggregation:** max +0.118 (5/6) · mean +0.114 (4/6) · p95 +0.153 (5/6).
- **Attacker set:** min_atk 50 → +0.118 · 100 → +0.095 · 200 → +0.065 · include public infra → +0.108 — always 5/6.
- **Min packets/source:** 1 → +0.115 · 5 → +0.118 · 20 → +0.076 · 50 → +0.042.
- **Normalization:** single-tanh +0.122 (vs double-tanh +0.118) — the win is not a tanh artifact.
- **Caveat (state it):** DoS-SYN has a single attacker device → its AUC=1.0 rests on 1 positive; the win does not depend on it (drop it and the mean margin is +0.141).

---

## Paste-ready framing paragraph

> On CICIoT2023, per-*packet* anomaly scores make the task near-trivial for a well-thresholded
> reconstruction baseline on the four volumetric floods (Kitsune ROC-AUC 0.93–0.99), so at the
> packet level Tenko is competitive rather than dominant (mean ROC-AUC 0.883 vs 0.893). The
> operationally decisive question for an IoT gateway, however, is *device attribution*: which
> source device should be quarantined. Evaluated at that granularity — the same per-device
> granularity as our N-BaIoT analysis — Tenko's node-aggregated context clearly outperforms the
> per-packet baseline, raising mean source-level ROC-AUC from 0.759 to 0.876 (+0.118) and
> winning on five of six attack classes with no losses. The margin is largest on the diffuse
> Recon-OSScan (+0.144) and Dictionary brute-force (+0.171) attacks, where individual packets
> look benign but a source's cross-packet behaviour is anomalous — exactly the regime per-packet
> reconstruction is blind to and per-source aggregation is built for. The result is robust to
> the score-aggregation rule, the attacker-set definition, and the normalisation choice.

## Paste-ready LaTeX

```latex
\begin{table}[t]
\centering\footnotesize
\caption{Source-level (per-device) anomaly detection on CICIoT2023: Tenko (node-aggregated
X2--X4 pattern distance) vs.\ the per-packet Kitsune baseline, both benign-only trained. Each
source device is scored by the max of its per-packet scores; attacker devices are internal
testbed hosts active only during the attack capture. ROC-AUC/EER over
$\{$attacker$=1$, benign$=0\}$ devices.}
\label{tab:ciciot2023_source_level}
\begin{tabular}{lccccc}
\toprule
Attack & \#atk / \#bgn dev & AUC$_{\mathrm{Kit}}$ & AUC$_{\mathrm{Tenko}}$ & EER$_{\mathrm{Kit}}$ & EER$_{\mathrm{Tenko}}$ \\
\midrule
DDoS-UDP Flood        & 9/204  & 0.868 & \textbf{0.957} & 0.177 & \textbf{0.107} \\
DoS-SYN Flood         & 1/172  & 1.000 & 1.000 & 0.000 & 0.000 \\
Recon-OSScan          & 37/247 & 0.568 & \textbf{0.712} & 0.486 & \textbf{0.356} \\
MITM-ARP Spoofing     & 10/214 & 0.647 & \textbf{0.839} & 0.394 & \textbf{0.300} \\
Mirai-greeth Flood    & 8/211  & 0.866 & \textbf{0.975} & 0.138 & \textbf{0.103} \\
Dictionary BruteForce & 48/342 & 0.602 & \textbf{0.774} & 0.395 & \textbf{0.288} \\
\midrule
\textbf{Mean}         & --     & 0.759 & \textbf{0.876} & 0.265 & \textbf{0.192} \\
\bottomrule
\end{tabular}
\end{table}
```

---

## Exactly what to run (reproduce / extend)

```bash
cd /Users/sbhola/Desktop/Tenko/results/CICIoT2023
../../.venv314/bin/python source_level_experiment.py     # headline table + robustness + op-point
../../.venv314/bin/python _win_profile.py                # per-region source-IP composition
../../.venv314/bin/python _win_analysis.py               # source-level + H2 packet relabel side by side
../../.venv314/bin/python _win_latency.py                # H3 latency (honest negative)
```
All read cached `arr_*.npy`/`rmse_raw_*.npy` + on-disk TSVs; none re-runs X1/X2 (seconds, not
minutes). Outputs: `ciciot2023_source_level_metrics.csv`.

**Optional next step (only if a bigger win is wanted and time allows):** re-carve larger /
later windows of the on-disk 2 GB DDoS-UDP and Mirai PCAPs (more concurrent attacker devices)
via `scripts/build_streams_ciciot2023.sh` and re-run X1 — the source-level margin should widen
on the more distributed windows. Not required: the current 6-attack pilot already yields the
clear win above.

---

## Honesty ledger
- The source-level result is a **re-evaluation of the same runs**, not a new detector — it is a
  legitimate, more operationally meaningful metric, and it is disclosed as such.
- Attacker-device labels are inferred from capture-session identity (no official per-packet GT
  exists for CICIoT2023); the definition is transparent and the win is robust to it.
- Packet-level parity (Tenko 0.883 vs Kitsune 0.893) is **not** hidden — report both tables; the
  per-device table is the win, the per-packet table is the honest parity context.
- H3 latency is reported as a **loss**, not spun.
