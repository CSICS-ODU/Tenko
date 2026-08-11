# Data Location Report — Reviewer Blockers B2 (nine-attack Kitsune) & B3 (N-BaIoT Table V)

_Repo: `<repo>` on branch `public-release`. All dataset paths below are **outside** the
repo; the absolute paths where they were originally located have been replaced with generic
placeholders (`~/dataset/...`, `<external>/...`). Point `--dataset` at your own local copy._

## TL;DR

| Blocker | Table | Data found? | Rebuilt from real data? |
|---|---|---|---|
| **B3** | N-BaIoT per-device / per-attack (Table V) | **YES — full dataset** | **YES** — committed driver reruns it end-to-end |
| **B2** | Nine-attack Kitsune main table | **YES — public UCI archive (id=516)** | **YES — all 9 attacks** rebuilt end-to-end via `results/main9attack/rebuild_8attacks.sh` |

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
output of the original external driver. Its values are preserved in the repo (as the `*_orig`
columns) in the tracked row-by-row comparison
`results/nbaiot/nbaiot_verification_vs_recovered.csv`, which also carries the `*_rebuilt`
columns from the committed driver.
The original driver was `<external>/nbaio_tenko_eval.py`
(it imports `KitNET.KitNET_improved`, which **no longer exists on disk**).

## 2. Kitsune nine-attack (B2) — all 9 rebuilt from the public UCI archive

The nine attacks are: Active Wiretap, ARP MitM, Fuzzing, **Mirai**, OS Scan, SSDP Flood,
SSL Renegotiation, SYN DoS, Video Injection.

**All nine are now reproducible from public data.** Commit `300e40e` rebuilt the full
nine-attack table end-to-end from the public UCI ML Repository "Kitsune Network Attack"
dataset (id=516):

- Source archive (downloaded once):
  `https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip`
  → `results/main9attack/data/kitsune_uci.zip` (~19 GB, **gitignored**).
- Runner: `results/main9attack/rebuild_8attacks.sh` executes the authentic Kitsune/KitNET
  pipeline (learned corClust feature map) per attack — `gen_scores.py` emits an
  `npz {scores, labels, benign_cal}`, then `run_kitsune_9attack.py` evaluates
  (benign-only thresholds + AUC/EER) and appends to
  `results/main9attack/kitsune_9attack_metrics.csv`.
- Verification: `results/main9attack/verify_vs_paper.py` emits the rebuilt-vs-paper deltas
  (`nineattack_verification_vs_paper.csv`).
- Only the small public artifacts (metrics CSVs, drivers, MEMO) are committed; the raw
  captures / per-attack feature CSVs / score streams live under
  `results/main9attack/data/` and are **gitignored**.

The runner self-locates the repo root (or honours `TENKO_REPO`), so no absolute paths are
baked in.

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
