# Data Location Report — Reviewer Blockers B2 (nine-attack Kitsune) & B3 (N-BaIoT Table V)

_Repo: `<repo>` on branch `public-release`. All dataset paths below are **outside** the
repo; the absolute paths where they were originally located have been replaced with generic
placeholders (`~/dataset/...`, `<external>/...`). Point `--dataset` at your own local copy._

## TL;DR

| Blocker | Table | Data found? | Rebuilt from real data? |
|---|---|---|---|
| **B3** | N-BaIoT per-device / per-attack (Table V) | **YES — full dataset** | **YES** — committed driver reruns it end-to-end |
| **B2** | Nine-attack Kitsune main table | **PARTIAL — only `Mirai`** | **Mirai: YES** (verified vs paper). Other 8 attacks: **data not on this machine** |

---

## 1. N-BaIoT (B3) — FOUND, complete

**Location:** `~/dataset/N-BaIoT/`  (UCI "detection_of_IoT_botnet_attacks_N_BaIoT")

- 90 device/attack CSVs, 115 AfterImage features + header row each, `Jan 18 2020`, ~15 GB total.
- `device_info.csv` maps DeviceID 1–9 → the exact Table V device names:
  1 Danmini_Doorbell, 2 Ecobee_Thermostat, 3 Ennio_Doorbell, 4 Philips_B120N10_Baby_Monitor,
  5 Provision_PT_737E_Security_Camera, 6 Provision_PT_838_Security_Camera,
  7 Samsung_SNH_1011_N_Webcam, 8 SimpleHome_XCS7_1002_WHT, 9 SimpleHome_XCS7_1003_WHT.
- Files per device: `<d>.benign.csv`, `<d>.gafgyt.{combo,junk,scan,tcp,udp}.csv`, and
  `<d>.mirai.{scan,ack,syn,udp,udpplain}.csv`. Devices **3 (Ennio)** and **7 (Samsung)**
  have **gafgyt only** (no mirai) — this matches the authentic N-BaIoT release.
- Also present: `README.md`, `features.csv` (115 feature names), `data_summary.csv`.

**Recovered prior output (provenance):** `<external>/NBAIOT_RESULTS_ALL.csv`
(80 rows: device × attack, with tn/fp/fn/tp/tpr/fpr/precision/f1/accuracy/auc/eer) — the
output of the original external driver. Copied into the repo as
`results/nbaiot/nbaiot_tableV_recovered_original.csv`.
The original driver was `<external>/nbaio_tenko_eval.py`
(it imports `KitNET.KitNET_improved`, which **no longer exists on disk**).

## 2. Kitsune nine-attack (B2) — only Mirai found

The nine attacks are: Active Wiretap, ARP MitM, Fuzzing, **Mirai**, OS Scan, SSDP Flood,
SSL Renegotiation, SYN DoS, Video Injection.

**Found (Mirai only):**
- `<external>/Mirai_dataset.csv` (764,137 rows, 116 cols = index + 115 feats + timestamp).
- `<external>/mirai_labels.csv` (764,137 labels; benign then Mirai).
- `<external>/Mirai_pcap.pcap` and `<external>/Kitsune-py/mirai.pcap` (62 MB).
- **Real Kitsune score stream** (used for the rebuild):
  `<external>/Kitsune-py/tenko_eval/results/kitsune_mirai_scores.npz`
  (`scores`, `labels`, `benign_cal`; 44,999 benign / 664,137 attack post-grace packets),
  produced by `<external>/Kitsune-py/tenko_eval/run_kitsune_mirai.py`.

**NOT found — the other 8 attacks.** No per-attack feature CSVs, pcaps, label files, or
saved RMSE/score artifacts exist for Active Wiretap, ARP MitM, Fuzzing, OS Scan, SSDP Flood,
SSL Renegotiation, SYN DoS, or Video Injection. The only related artifacts are 4 rendered
plots (`active_wiretap.png`, `fuzzing.png`, `ssdp_flood.png`, `mirai.png`) under a local
image folder — images, not data.

The local `Datasets/Kitsune/` folders hold a
different, custom split (`TrainData.csv`, `TestData.csv`, `NewTestData.csv`, `Recurring.csv`),
**not** the nine named Kitsune attacks.

### What the user must supply to fully rebuild the nine-attack table

For **each** of the 8 missing attacks, provide EITHER:
- the original Kitsune per-attack **pcap** (`<Attack>_pcap.pcap`) — then run
  `Kitsune-py/tenko_eval/run_kitsune_*.py` (adapted per attack) to emit `<attack>_scores.npz`; OR
- the pre-extracted **`<Attack>_dataset.csv` (115 AfterImage features) + `<Attack>_labels.csv`**
  (0=benign, 1=attack) — then run the committed driver directly:

```
python results/main9attack/run_kitsune_9attack.py --attack "OS Scan" \
    --dataset-csv <OS_Scan_dataset.csv> --labels-csv <OS_Scan_labels.csv> \
    --has-index-col --drop-last-col --append \
    --output results/main9attack/kitsune_9attack_metrics.csv
```

The original Kitsune attack captures are the public NDSS'18 dataset
(https://github.com/ymirsky/Kitsune-py — "Attack Datasets" on the project's data mirror).

## 3. Search coverage (read-only)

- `~/{Desktop,Documents,Downloads}` recursively (depth ≤ 5) for: `*.benign.csv`,
  `device_info.csv`, `*gafgyt*`, `*nbaiot*`, `*_dataset.csv`, `*_labels.csv`, `RMSE*.pkl`,
  `*scores*.npz`, `*.pcap`, and the attack keywords (Wiretap, OS Scan, SSDP, Renegotiation,
  Video Injection, SYN DoS, Fuzzing, ARP MitM).
- `/Volumes/*` — only `Macintosh HD` symlink (no external drives mounted).
- Spotlight (`mdfind`) returned nothing (index disabled for these paths); results above are
  from direct filesystem traversal.
- `resultsNew.py` was **not** a working-tree file: it is `git show Daksh-Mateen:resultsNew.py`
  (the `:` is git `<branch>:<path>` syntax). Read read-only; its literals are transcribed to
  `results/main9attack/paper_literals_resultsNew.csv`.
