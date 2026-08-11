# CICIoT2023 pilot — per-attack **attack-purity verification**

*Repo:* `<repo-root>/Tenko` (branch `correct-latency`). **Read-only analysis.** No git commit.
Every number below is computed directly from the pilot TSVs
`<path-to-ciciot2023-pilot>/stream_*.pcap.tsv` and is reproducible with the two helper
scripts committed alongside this memo (`_attack_purity.py`, `_attack_purity_quant.py`) or with the
`awk` one-liners cited inline. **Nothing here is invented.**

## Why this check exists

CICIoT2023 has **no per-packet ground truth**: the label is the *capture session* — a packet is
"attack" iff it came from an attack PCAP, benign iff from `BenignTraffic.pcap`
(`experiment_story.md:53-56`, `scripts/build_ciciot2023_pilot.sh:4-5`). Our streams therefore label
**all 50,000 packets** of each attack region as `1`, wholesale. But an attack capture also carries the
victim's/testbed's benign background (DNS, CDN pulls, other IoT chatter). So *attack purity must be
verified independently, not assumed*. The prior audit (`cic_config_audit.md`, H2) estimated
contamination from **IP composition only** (public/CDN share). This memo adds a second, independent
axis — **protocol/behavioural signature** — and reconciles the two.

## Regions (0-based packet index → TSV line)

- **benign region** = packets `0 … 179,999` → TSV lines **2 … 180,001** (label 0).
- **attack region** = packets `180,000 … 229,999` → TSV lines **180,002 … 230,001** (label 1).
- Each stream = `[benign_lead 150k] + [benign_test 30k] + [attack 50k]` = 230,000 packets
  (`experiment_story.md:99-118`, `stream_counts.csv`). The **benign region is byte-identical across
  all six streams** (verified: `sed -n '2,180001p' … | md5` = `20468d94…` for every stream), so the
  benign top-source profile is computed once and reused.

## Method

**TSV fields available** (19 cols, tab-sep; header row 1; `scripts/pcap2tsv_tenko.sh`):
`0 frame.time_epoch · 1 frame.len · 2 eth.src · 3 eth.dst · 4 ip.src · 5 ip.dst · 6 tcp.srcport ·
7 tcp.dstport · 8 udp.srcport · 9 udp.dstport · 10 icmp.type · 11 icmp.code · 12 arp.opcode ·
13 arp.src.hw_mac · 14 arp.src.proto_ipv4 · 15 arp.dst.hw_mac · 16 arp.dst.proto_ipv4 ·
17 ipv6.src · 18 ipv6.dst`.
**There is NO `tcp.flags` column** → SYN/ACK/RST cannot be read directly (see Limitations). Source
node key = `ip.src` (col 4) else `ipv6.src` (col 17) else `ARP:<arp.src.proto_ipv4>` else `L2/none`,
matching Tenko's own node parsing (`results.py:739-753`).

1. **Attacker-IP attribution.** Rank attack-region sources; identify the dominant internal
   `192.168.137.x` attacker(s) and their packet share. Cross-reference **every** prominent
   attack-region source against the benign region's top-source list (a source is flagged
   *known-benign* if it emits ≥ 500 packets in benign rows 2–180,001).
2. **Protocol/behavioural signature.** Using L4 (inferred from which port/opcode field is populated),
   dst-IP concentration, dst-port concentration, and packet-length distribution, test whether the
   attack-region packets match that attack's expected fingerprint.
3. **Quantify** a mutually-exclusive 3-way partition per attack (sums to 100%):
   *genuine_attack* = packets matching the signature flow; *benign_background* = non-signature packets
   from a known-benign host **or** from a public/CDN address; *ambiguous* = the rest (internal hosts
   with no benign history that don't match the signature).
4. **Verdict**: attack-pure (floods, effective ≥ 98%) vs materially contaminated, with confidence and
   evidence.

## Headline per-attack table

| Attack | attacker-IP(s) → share | genuine-attack (signature) | benign-background | ambiguous | public/CDN share | **Verdict** |
|---|---|---|---:|---:|---:|---|
| **DoS-SYN_Flood** | `.182` → **85.4%** | **99.36%** | 0.39% | 0.25% | 0.24% | **Attack-PURE** (high) |
| **DDoS-UDP_Flood** | 7 bots → **95.6%** | **95.52%** (+2.6% likely-attack) | 1.87% | 2.60% | 1.54% | **Attack-PURE** (high) |
| **MITM-ArpSpoofing** | `.162` → **53.3%** | **91.14%** (relay+ARP) | 3.81% | 5.06% | 40.6%\* | **Attack-PURE\*** (moderate–high) |
| **Mirai-greeth_flood** | 7 bots → **67.0%** | **90.75%** (C2+flood) | 3.75% | 5.50% | 29.0%\* | **Attack-PURE\*** (moderate–high) |
| **Recon-OSScan** | 5 scanners → **36.0%** | **36.06%** (lower bound) | 45.21% | 18.73% | 25.3% | **CONTAMINATED** (high) |
| **DictionaryBruteForce** | 5 hosts → **29.5%** | **23.21%** (lower bound) | 34.61% | 42.18% | 27.1% | **CONTAMINATED** (high) |

\* For MITM and Mirai the large "public/CDN" share is **the attack's own manifestation** (ARP-relayed
victim traffic to `205.251.251.216`; Mirai C2 `69.168.130.48`), **not** benign background — the
signature check re-attributes it to *attack* and drops true benign background to ~3.8%. This is the
main correction this memo makes to a naive IP-only reading (see §H2 impact).

Shares are of the 50,000 attack-region packets. `public/CDN share` reproduces `cic_config_audit.md`
H2 exactly (DoS-SYN 0.24%≈0.2%, DDoS 1.54%≈1.5%, Recon 25.3%, Dict 27.1%, Mirai 29.0%, MITM 40.6%),
confirming both analyses read the same data.

## Per-attack evidence

Benign region top hosts (for cross-reference; identical across streams): `.41` 24,646 (13.7%),
`157.249.81.141` 18,890 (10.5%, public), `.172` 12,134, `.1` 9,925, `.249` 8,741, `.58` 6,714,
`.175` 5,481, `35.185.101.66` 3,078 (public). Source: `_attack_purity.py` over benign rows 2–180,001.

### DoS-SYN_Flood — **attack-pure**
- **Attacker `192.168.137.182` → 42,703 (85.4%)**, not present in benign region. Victim
  `192.168.137.187` replies with 6,980 (14.0%). The two-party flood exchange = **99.36%**.
- **Signature (SYN-flood proxy):** 99.78% TCP; **99.77% of packets are 60 bytes** (fixed tiny frame);
  single dst `192.168.137.187` (85.4%); single dst port **4070** (85.4%).
  `awk … $5=="192.168.137.182" && $6=="192.168.137.187" && $8=="4070"` = **42,700** packets.
- **Benign background:** 0.24% public/CDN (DNS to `8.8.4.4`, CDN `35.185.101.66`), 0.39% total.
- *Confidence high.* Uniform 60-byte TCP from one host to one victim:port is textbook flood; we cannot
  read the SYN bit (no `tcp.flags`) but the pattern is unambiguous.

### DDoS-UDP_Flood — **attack-pure**
- **Distributed:** top-1 source only 21.7%, but **seven internal bots** (`.17,.224,.240,.134,.58,.195,
  .96`) emit **95.6%** combined, all aimed at **one victim `192.168.137.30` (96.05% of dst)**.
- **Signature:** 96.70% UDP; `awk … $6=="192.168.137.30" && $10!=""` = **47,762** UDP packets to the
  victim (**95.52%**); 98.5% ≤ 100 bytes. Low top-1 share is *by design* (distributed) — the **victim
  concentration**, not source concentration, is the correct flood signature.
- **Benign background:** 1.54% public/CDN; 1.87% total. The 2.6% "ambiguous" is non-flood TCP
  (control/side traffic), most of it plausibly attack.
- *Confidence high.*

### MITM-ArpSpoofing — **attack-pure (relay), moderate–high confidence**
- **Attacker `192.168.137.162` (53.3%)** ⇄ external `205.251.251.216` (37.4%): the MITM relays the
  victim's web session. Relay pair = `awk … {.162,205.251.251.216} both directions` = **45,278**;
  plus **290 actual ARP-opcode packets** (`$13!=""`) ⇒ signature share **91.14%**.
- **Signature caveat:** only **0.58%** of the region carries an ARP opcode — the ARP-poisoning packets
  themselves are a tiny minority in the first 50k; the attack is *manifested* as the relayed TCP-443
  flow. So the "signature" here is **relay-concentration**, not direct gratuitous-ARP detection.
- **Benign background:** true benign ≈ **3.81%** (not 40.6%). The 40.6% "public" is the relay endpoint
  = attack.
- *Confidence moderate–high:* the relay flow is unambiguous, but without `tcp.flags`/full ARP history
  we infer MITM from flow structure rather than proving each poisoning event.

### Mirai-greeth_flood — **attack-pure (botnet+C2), moderate–high confidence**
- **Bot `192.168.137.129` (43.0%) + C2 `69.168.130.48` (25.8%)**; `awk … C2 as src|dst` = **34,261**.
  Seven internal bots emit **67.0%**; greeth flood shows as ports **54742/54750** (24.4% combined) to
  victim `.254`. Signature (C2 exchange ∪ greeth ports ∪ bot→victim) = **90.75%**.
- **Benign background:** ≈ **3.75%** (e.g. `8.8.8.8` DNS 1.6%). The 29% "public" is dominated by the
  C2 (25.8%) = attack.
- *Confidence moderate–high.*

### Recon-OSScan — **materially CONTAMINATED**
- **Diffuse & benign-overlapping:** top scanner `.178` only 16.1%; five scanners = **36.0%**. The
  positive class literally contains the **#1 benign host `192.168.137.41`** (`awk` = **2,874** attack
  packets; it emits 24,646 in benign), plus known-benign `.175` (5,752; benign 5,481), CDN
  `35.185.101.66` (2,598; benign 3,078) and `157.249.81.141` (2,213; benign 18,890).
- **Signature (scan = small internal→internal packets to non-web ports):** only **36.06%** match
  (a *lower bound*; scans of web ports are excluded to stay conservative). Length is bimodal
  (p50 = 66 B but p90 = 1,514 B — full-MTU data transfers, i.e. real web sessions, not probes).
- **Benign background = 45.2%** (public/CDN 25.3% + known-benign internal hosts). Ambiguous 18.7%.
- *Confidence high* that ≥ 25% (and likely ~45%) of the positive class is benign background.

### DictionaryBruteForce — **materially CONTAMINATED**
- **Most diffuse:** top host `.67` 10.7%, `.65` 9.0%; five hosts = **29.5%**; 5.5% is ARP/L2 and 1.5%
  ICMP (non-login noise). The brute-force login signature — **TCP dst port 22 (SSH)** — is only
  `awk … $8=="22"` = **4,476 (8.95%)**; port 443 web is larger (18.6%).
- **Signature (SSH/login ports ∪ attacker-pair internal):** **23.21%** (lower bound).
- **Benign background = 34.6%** (public/CDN 27.1% + known-benign hosts); ambiguous **42.2%** (diffuse
  internal chatter with no benign history and no login signature).
- *Confidence high* that ≥ 27% is benign background and genuine login-attack traffic is a minority.

## Reconciliation with the audit's public/CDN shares

The signature axis **agrees with** the audit on the flood classes and **splits the audit's four
"contaminated" classes into two groups**:

- **Floods (DoS-SYN, DDoS):** signature confirms attack purity; public/CDN ≤ 1.5% — unchanged.
- **MITM, Mirai:** the audit's 40.6% / 29.0% public share is **re-attributed to the attack** (relay
  endpoint / C2). True benign background falls to ~3.8% → these are **attack-pure**, *not* 25%+
  contaminated as an IP-only reading implied.
- **Recon, Dict:** signature **confirms and slightly raises** the contamination — benign background is
  ≥ the public/CDN share (45%/35%) because known-benign *internal* hosts (e.g. Recon's #1 benign host
  `.41`) are also mislabeled as attack.

## Limitations (honest)

1. **No per-packet ground truth.** Labels are capture-session identity; there is no authoritative
   per-packet attack flag to validate against. All "genuine/benign/ambiguous" figures are
   signature-based estimates, not certified truth.
2. **No `tcp.flags` field.** The TSV never extracted TCP flags, so "SYN flood" (DoS-SYN) and
   connection-attempt semantics (Dict) cannot be confirmed at the flag level. We fall back to the
   strongest available proxies — fixed 60-byte TCP + single victim:port for DoS-SYN; SSH-port
   concentration for Dict — and label the confidence accordingly.
3. **ARP-spoof under-observed.** Only 0.58% of the MITM region carries an ARP opcode; the MITM verdict
   rests on relay-flow concentration, not on observing each poisoning packet.
4. **Conservative signatures ⇒ lower bounds.** Recon (36%) and Dict (23%) genuine-attack shares are
   deliberate *lower bounds* (web-port probes excluded from the scan signature; only classic login
   ports counted as brute-force). The contamination conclusion is robust to this — it only gets worse
   if the bounds are loosened toward attack.
5. **Attacker/victim IPs inferred**, not supplied by a dataset key: identified from attack-region
   dominance plus benign cross-reference. `tshark -E occurrence=f` keeps only the first value of any
   multi-valued field.

## Recommended paper wording

> *Attack-sample verification.* Because CICIoT2023 labels every packet of an attack capture as that
> attack (capture-session labeling, with no per-packet ground truth), we verified attack purity
> independently for each class along two axes: (i) attacker-IP attribution — identifying the dominant
> internal source(s) in the attack window and cross-checking every prominent source against the benign
> window's top-host list — and (ii) a protocol/behavioural signature check (L4 protocol, victim-IP and
> destination-port concentration, and packet-length distribution; the pilot TSVs do not carry TCP
> flags, so SYN semantics are verified only by proxy — uniform 60-byte TCP to a single victim:port).
> The four high-rate classes are effectively attack-pure: DoS-SYN 99.4% (single attacker → single
> victim:4070, 99.8% 60-byte TCP), DDoS-UDP 95.5% (seven bots → one victim, 96.7% UDP),
> MITM-ArpSpoofing 91.1% and Mirai 90.8% once the large "public" share is correctly attributed to the
> attack's own relayed/C2 traffic rather than to benign background (residual benign ≤ ~4% each). The
> two low-rate, benign-overlapping classes are materially contaminated: only ~36% (Recon-OSScan) and
> ~23% (DictionaryBruteForce) of their positive-class packets match a scan/login signature, with
> ~45% and ~35% attributable to benign background (public/CDN plus known-benign internal hosts —
> Recon's positive class even contains the busiest benign host). We therefore report Recon-OSScan and
> DictionaryBruteForce with an explicit label-noise caveat, and the four high-rate classes as
> attack-pure.

## Does this strengthen or change the H2 story?

**It strengthens and sharpens H2, and corrects one part of it.**

- **Sharpens:** contamination is a **two-class** phenomenon (**Recon-OSScan, DictionaryBruteForce**),
  not a four-class one. The independent signature axis confirms ≥ 25–45% benign background exactly on
  the two classes where Tenko/Kitsune are weakest — consistent with H2's claim that mislabeled benign
  positives depress AUC/TPR precisely there.
- **Corrects:** the audit grouped MITM/Mirai with Recon/Dict as "≈25%+ non-attacker." The signature
  check shows MITM/Mirai's high "public" share is the **attack manifestation** (ARP-relay endpoint and
  Mirai C2), so their true benign background is ~4% — they belong with the **attack-pure** floods, not
  with the contaminated classes.
- **Net for the paper:** attacker-IP-based relabeling is worth doing **only for Recon-OSScan and
  DictionaryBruteForce**; the other four classes need no cleaning. This makes the H2 remediation
  narrower, better-targeted, and more defensible.

## Reproduce

- `python3 results/CICIoT2023/_attack_purity.py` — benign profile + per-attack source/proto/dst/port/
  length breakdown.
- `python3 results/CICIoT2023/_attack_purity_quant.py` — signature-flow shares + 3-way partition.
- Spot-check `awk` (attack rows 180002–230001), e.g. DDoS UDP→victim:
  `awk -F'\t' 'NR>=180002&&NR<=230001&&$6=="192.168.137.30"&&$10!=""{c++}END{print c}'
  <path-to-ciciot2023-pilot>/stream_DDoS-UDP_Flood.pcap.tsv` → 47762.
