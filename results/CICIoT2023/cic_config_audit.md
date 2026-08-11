# CICIoT2023 — skeptical audit: is "competitive-not-dominant" fixable config/data, or fundamental?

Read-only investigation of the actual code and pilot TSVs. No git commits; no invented numbers.
Every figure below was computed from `/Users/sbhola/Desktop/cic/pilot/stream_*.pcap.tsv`, the cached
`results/CICIoT2023/rmse_raw_*.npy`, or the committed CSVs, and is cited inline.

**Already known & fixed (acknowledged, not re-derived):** the committed `η=50/20` was degenerate
(`η_node` mis-scaled ~10×) and the redundant double-`tanh`. This audit tests five *new* hypotheses.

---

## TL;DR verdict

The competitive-not-dominant result is **mostly FUNDAMENTAL**, driven by two things Tenko cannot fix
by re-configuration: (i) CICIoT2023's 6-class pilot skews to **volumetric floods where the per-packet
Kitsune baseline is already near-ceiling** (AUC 0.93–0.99), leaving node aggregation little headroom;
and (ii) the two weak classes (Recon-OSScan, DictionaryBruteForce) are **genuinely diffuse** — few
packets per source IP — so per-node context cannot accrue.

There are **two real, fixable DATA/benchmark issues** that would improve the *absolute* numbers and the
honesty of the benchmark (most on the two weak classes), but are **unlikely to flip Tenko to uniform
dominance**: **H2 label contamination** (attack captures contain benign background) and **H3 benign
sampling** (a single contiguous benign window caught one benign CDN burst). Node-IP parsing (H1) and
KitNET/Tenko config (H4) are **not** broken — they are byte-for-byte the same as the paper's Kitsune
run.

---

## The one figure that explains almost everything

Tenko's per-class AUC tracks **how concentrated the attack packets are on the dominant source IP**
(`top1share` = fraction of the 50k attack-region packets emitted by the single busiest source), which
is exactly the quantity node aggregation needs:

| CICIoT2023 attack | top-1 src share | internal (192.168.x) | public | empty L2 | Tenko AUC | Kitsune AUC | Tenko−Kits |
|---|---|---|---|---|---|---|---|
| DoS-SYN_Flood        | **0.854** | 0.997 | 0.002 | 0.000 | 0.988 | 0.993 | −0.005 |
| MITM-ArpSpoofing     | **0.533** | 0.588 | 0.406 | 0.007 | 0.949 | 0.942 | **+0.007** |
| Mirai-greeth_flood   | **0.430** | 0.708 | 0.290 | 0.003 | 0.937 | 0.929 | **+0.008** |
| DDoS-UDP_Flood       | 0.217 | 0.982 | 0.015 | 0.002 | 0.929 | 0.965 | −0.036 |
| Recon-OSScan         | 0.161 | 0.720 | 0.253 | 0.026 | 0.796 | 0.827 | −0.031 |
| DictionaryBruteForce | 0.107 | 0.674 | 0.271 | 0.055 | 0.697 | 0.703 | −0.006 |

Source: attack-region source composition computed by `awk` over `stream_*.pcap.tsv` (data rows
180002–230001); AUC columns from `ciciot2023_per_class_metrics.csv`. The ordering by `top1share` is
almost perfectly monotonic with Tenko AUC — the two Tenko wins (MITM, Mirai) sit at the top of the
concentration ranking among the entity attacks; the two weak classes sit at the bottom.

---

## H1 — Is node aggregation (X2) actually engaging on CIC? **YES — not a bug. (Fundamental where it degrades.)**

**How the node key is parsed.** `results.build_IP_list` (`results.py:739-753`) sets the node key to
`row[4]` (`ip.src`) if present, else `row[17]` (`ipv6.src`), else the empty string — **there is no MAC
fallback** (contrary to the earlier assumption). Column mapping verified against the TSV header:
`$5=ip.src`, `$18=ipv6.src` (1-indexed), matching Python `row[4]`/`row[17]`.

**Is the source IP actually parsed?** Yes. The keys are real IPv4 addresses (e.g.
`192.168.137.182`), not MACs. Empty (L2-only/ARP) packets are a small minority of the attack region:
DoS-SYN 21, DDoS 116, MITM 331, Mirai 135, Recon 1313, Dict 2754 (out of 50,000). So the stream does
**not** collapse to a single node.

**Does per-node context accrue?** For the flood/botnet classes, strongly:
- DoS-SYN: `192.168.137.182` emits 42,703/50,000 (85%), 2nd host 6,980 (14%) — 2 attacker nodes with
  huge per-node histories.
- MITM: `192.168.137.162` 26,631 (53%) + relayed `205.251.251.216` 18,677 (37%).
- Mirai: `192.168.137.129` 21,514 (43%) + C2 `69.168.130.48` 12,884 (26%).
- DDoS: distributed across ~144 sources but each busy source still emits thousands of packets.

For the weak classes, context is thin by nature:
- Recon-OSScan: busiest source only 8,067 (16%); 230 distinct sources — a scan touches many peers with
  few packets each.
- Dict: busiest source 5,353 (11%); **411** distinct sources; 5.5% empty-L2.

**Verdict.** Node aggregation is engaging and getting rich multi-packet-per-source context on the
sustained/entity attacks (exactly where Tenko beats Kitsune). It degrades on Recon/Dict because those
attacks are *intrinsically diffuse* (few packets per source) — **fundamental, not a parsing fix**.
Estimated fixable AUC upside from H1: **~0** (nothing to fix).

---

## H2 — Label contamination in the attack region. **REAL and material on the weak classes. FIXABLE.**

Every attack stream labels all 50,000 attack-region packets as `1`, but the CICIoT2023 attack captures
carry benign background (victim/testbed/CDN traffic). Evidence from the attack-region source mix:
- The DoS-SYN attack region contains `157.249.81.141` (the #2 *benign* source, 18,890 pkts in benign)
  and the Recon attack region contains `192.168.137.41` (the **#1 benign host**, 24,646 pkts in
  benign) at 2,874 pkts — i.e. known-benign hosts' traffic mislabeled as attack.
- Public/CDN share of the attack region: MITM 40.6%, Mirai 29.0%, Recon 25.3%, Dict 27.1% (vs DoS-SYN
  0.2%, DDoS 1.5%). For MITM/Mirai much of the "public" is the attack's own manifestation (ARP-relayed
  CDN traffic; Mirai C2), so it is defensibly attack; for **Recon and Dict** the CDN/Google
  (`35.185.101.66`, `35.186.43.132`) and empty-L2 packets are genuine benign background.

**Effect on the metric.** A benign packet mislabeled as attack is a *low-scoring positive*: Tenko
(correctly) scores its benign source node low, so it becomes a false negative and a low-ranked
positive — depressing **both** TPR and AUC precisely on Recon/Dict. Because the Kitsune baseline runs
loose (constant benign FPR ≈ 0.323, `ciciot2023_per_class_metrics.csv`), it "accidentally" flags many
of these benign positives as attack, so contamination is *less* punishing to the loose baseline than to
the calibrated Tenko — i.e. it can make Tenko look relatively worse on the diffuse classes.

**Verdict.** Contamination is material for Recon/Dict (≈25%+ non-attacker packets in the positive
class) and small for DoS-SYN/DDoS. **Fixable** by attacker-IP-based labeling (relabel only packets from
the identified attacker source(s) as attack; the attacker IPs are the dominant internal `192.168.137.x`
sources, verifiable against the benign top-source list). Estimated upside: **plausibly several AUC
points on Recon/Dict, ~0 on DoS-SYN/DDoS**. Caveat: it cleans the gold labels for *both* detectors, so
it raises absolute Tenko AUC and benchmark honesty but does **not** guarantee more Tenko-vs-Kitsune
wins. (No exact ΔAUC without a re-run; not fabricated here.)

---

## H3 — Subsampling / benign non-stationarity. **A benign CDN burst, not warm-up. PARTLY FIXABLE (FPR-transfer).**

We already found the operating-point FPR does not transfer (held-out ≈0% vs ≈30%). Root cause, from the
cached tanh(RMSE) of `benign_test` (packets 150k–180k, `rmse_raw_DoS-SYN_Flood.npy`), split into 6
sequential slices:

- mean tanh RMSE per slice: `[0.083, 0.660, 0.009, 0.012, 0.010, 0.016]`
- fraction of packets with score > 0.5: `[0.077, 0.789, 0.0008, 0.0048, 0.0002, 0.0094]`

So the "non-stationarity" is a **single localized benign burst around packets ~155k–160k** (slice 2),
where ~79% of packets score high, while every other slice is quiet (<1% high). This is **not** a KitNET
warm-up (grace ends at packet 55,001, far earlier) and **not** monotonic drift — it is one bursty
benign event. Characterized: the burst is dominated by `192.168.137.172` (2,261) pulling from AWS
CloudFront `13.225.189.191` (1,847) — a **legitimate high-throughput CDN download**, which produces
large reconstruction error. `benign_lead`/`benign_test` are contiguous first-N slices, so this one
window happened to include the burst; `fwd` calibrates on the noisy half (→ high thresholds → 0% FPR on
the quiet half), `rev` calibrates on the quiet half (→ low thresholds → ~30% FPR on the noisy half).

**Verdict.** **Partly fixable.** Drawing `benign_test` as a **striped/random sample across the full
benign trace** (or discarding/averaging over such bursts) would dilute the burst and give a much more
*transferable* FPR. It mainly fixes the FPR-transfer caveat; AUC (threshold-independent) would gain only
marginally (fewer high-scoring benign negatives). Estimated upside: large for FPR-transfer honesty,
**small (~≤0.01) for AUC**.

---

## H4 — KitNET (X1) training + config deltas vs the Kitsune-dataset run. **NO disadvantageous delta.**

Line-by-line comparison of `run_ciciot2023.py` vs the reference `example.py` / `workflow.py`:

| Param | CIC run (`run_ciciot2023.py`) | Reference (Kitsune-ds) | Delta? |
|---|---|---|---|
| maxAE | 10 (`:34`) | 10 (`example.py:47`) | same |
| FMgrace | 5000 (`:35`) | 5000 (`example.py:48`) | same |
| ADgrace | 50000 (`:36`) | 50000 (`example.py:49`) | same |
| memorySize | 60 (`:182`) | 60 (`workflow.py:248`) | same |
| pattern_window_size | 100 (`:183`) | 100 (default) | same |
| pattern_segments | 10 (`:183`) | 10 (default) | same |
| tol factors | 50/20 (then recalibrated) | 50/20 (defaults) | same |
| tanh | double (committed) + single variant | double (committed) | same (already audited) |

KitNET grace is 55,001 packets out of **150,000** benign lead — as much or more benign training than the
reference. RMSE-cache sanity (`rmse_raw_*.npy`): **0 NaN, 0 inf** across all six streams; the only zeros
are the 5,001-packet feature-mapping-grace prefix (indices < 5001, far before the test region at
150k+); medians ~0.007, maxima up to 5.5e7 (legitimate raw spikes that `tanh` saturates). No
feature-mapper failure, no degenerate/NaN scores.

**Verdict.** The CIC run is **not** under-trained and has **no** config that disadvantages it relative
to the Kitsune-dataset run. Estimated fixable AUC upside: **~0** (nothing to fix). If anything, one
could *try* a longer AD grace or larger `maxAE` for CIC's feature diversity, but there is no evidence of
under-training (healthy RMSEs), so this is speculative, not indicated.

---

## H5 — Attack-character explanation (the fundamental part). **Confirmed: this is the dominant cause.**

Why 9/9 on the Kitsune dataset but 2/6 here:
- **Kitsune dataset** attack mix (fuzzing, SSL-renegotiation, active wiretap, video injection, SSDP,
  OS scan, ARP MITM, SYN DoS, Mirai) left the *baseline* real headroom — Kitsune AUC 0.85–0.96
  (`tab:kitsune-tenko-new-highlighted`). Node/entity context then adds a consistent edge → Tenko ≥
  Kitsune on all nine.
- **CICIoT2023 pilot** is 4/6 volumetric floods (DoS-SYN, DDoS-UDP, ARP-relay, Mirai) where the
  per-packet Kitsune RMSE is **already near-ceiling** (AUC 0.929–0.993). When the baseline is near
  perfect, node aggregation can only tie or win by a hair — which is exactly what happens (MITM +0.007,
  Mirai +0.008; DoS-SYN/DDoS a hair below). The remaining 2/6 (Recon, Dict) are diffuse *and*
  benign-overlapping, so both detectors are weak and neither aggregation nor per-packet error separates
  them well.

**Verdict.** The bulk of "not dominating" is **structural**: a flood-heavy attack mix + a near-ceiling
baseline + two intrinsically hard diffuse classes. Not fixable by configuration.

---

## Prioritized separation: FIXABLE vs FUNDAMENTAL

### (A) FIXABLE config/data issues
1. **H2 — attacker-IP-based labeling** *(try this first)*. Evidence: 25–41% of the attack region on
   MITM/Mirai/Recon/Dict is public/CDN or known-benign-host traffic; Recon's positive class even
   contains the #1 benign host. Fix: label only attacker-source packets as attack. Estimated impact:
   **several AUC points on Recon/Dict, ~0 on the floods**; improves benchmark honesty. Caveat: helps
   both detectors' gold, so it may not add Tenko-vs-Kitsune wins.
2. **H3 — striped/random benign sampling** *(second)*. Evidence: one benign CDN burst at ~155–160k
   drives the FPR non-transfer (slice means `[0.08,0.66,0.01,0.01,0.01,0.02]`). Fix: sample benign_test
   across the whole benign trace. Estimated impact: **large for FPR-transfer**, **≤0.01 AUC**.
3. *(speculative, not indicated)* longer AD grace / larger `maxAE` for CIC feature diversity — no
   evidence of under-training (RMSEs healthy), so low expected value.

### (B) FUNDAMENTAL limits (not fixable by re-config)
1. **Flood-heavy attack mix** → near-ceiling per-packet baseline → little headroom for aggregation
   (H5). 4/6 classes.
2. **Diffuse recon/brute-force** → few packets per source → node context cannot accrue (H1); low
   AUC is a genuine separability limit for benign-only training.
3. **Node parsing & KitNET/Tenko config are correct and identical to the paper's run** (H1, H4) — there
   is no hidden misconfiguration to exploit.

---

## Recommendation

**The competitive-not-dominant result is genuine.** The single most worthwhile re-run is **H2
attacker-IP-based relabeling** — it addresses a real, defensible benchmark artifact and should lift the
two weak classes (Recon, Dict) by a few AUC points, with **H3 striped benign sampling** as a companion
fix that mainly restores FPR-transfer. But neither should be expected to make Tenko *uniformly* beat
Kitsune on CICIoT2023: on the volumetric floods the per-packet baseline is already near-ceiling
(fundamental), and on the diffuse classes the traffic itself denies node aggregation the multi-packet
context it needs. **Report CICIoT2023 as-is** (AUC/EER headline, MITM/Mirai node-aggregation wins,
honest OS-Scan/recon gap and FPR caveat); optionally add an attacker-IP-labeled re-run of Recon/Dict as
a targeted robustness check, clearly noting it also cleans the baseline's labels.

---

## Evidence index
- Node-key parsing: `results.py:739-753` (no MAC fallback); TSV header field map ($5 ip.src / $18 ipv6.src).
- Per-attack source composition (top1share / internal / public / empty): `awk` over
  `/Users/sbhola/Desktop/cic/pilot/stream_*.pcap.tsv`, attack rows 180002–230001; benign rows 2–180001.
- AUC/EER: `results/CICIoT2023/ciciot2023_per_class_metrics.csv`.
- Benign burst: 6-slice tanh(RMSE) of `rmse_raw_DoS-SYN_Flood.npy[150000:180000]`; burst source
  `192.168.137.172` → AWS CloudFront `13.225.189.191` (rows 155002–160001).
- Config parity: `run_ciciot2023.py:34-36,182-183` vs `example.py:47-49`, `workflow.py:248`.
- RMSE health: `rmse_raw_*.npy` — 0 NaN / 0 inf / 5001 grace-zeros each.
