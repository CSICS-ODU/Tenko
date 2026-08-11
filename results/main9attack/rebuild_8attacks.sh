#!/usr/bin/env bash
# Rebuild the 8 non-Mirai rows of the nine-attack Kitsune table from the public
# NDSS'18 dataset (UCI ML Repository id=516, "Kitsune Network Attack").
#
# Source archive (downloaded once):
#   https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip
#   -> results/main9attack/data/kitsune_uci.zip  (~19 GB, gitignored)
#
# Each attack dir in the zip provides "<Attack>_dataset.csv.gz" (115 AfterImage
# features, no index/header) and "<Attack>_labels.csv.gz" (R-exported: header
# '"","x"' + row-index; label in col 2). Labels are normalized to a plain
# single-column file (data/clean/<name>_labels.csv) beforehand.
#
# Two stages per attack (mirrors how the committed Mirai row was produced, i.e. the
# authentic Kitsune pipeline with a LEARNED corClust feature map):
#   1) gen_scores.py: learn FM (5,000 pkts) + train AD (50,000 pkts) on the benign
#      prefix (55,000 grace pkts, excluded from eval), execute the rest, and emit an
#      npz {scores, labels, benign_cal} where benign_cal = post-grace PRE-ATTACK
#      benign scores.
#   2) run_kitsune_9attack.py --scores-npz: evaluate (benign-only thresholds +
#      AUC/EER) and append to kitsune_9attack_metrics.csv.
set -euo pipefail

ROOT="${TENKO_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
PY="$ROOT/.venv/bin/python"
DIR="$ROOT/results/main9attack"
DATA="$DIR/data"
ZIP="$DATA/kitsune_uci.zip"
OUT="$DIR/kitsune_9attack_metrics.csv"
mkdir -p "$DATA/ds" "$DATA/npz"

# display_name | zip member prefix | clean-label / file basename
ATTACKS=(
  "OS Scan|os_scan/OS Scan|OS Scan"
  "SSL Renegotiation|ssl_renegotiation/SSL Renegotiation|SSL Renegotiation"
  "Fuzzing|fuzzing/Fuzzing|Fuzzing"
  "Active Wiretap|active_wiretap/Active Wiretap|Active Wiretap"
  "SYN DoS|syn_dos/SYN DoS|SYN DoS"
  "Video Injection|video_injection/Video Injection|Video Injection"
  "ARP MitM|arp_mitm/ARP MitM|ARP MitM"
  "SSDP Flood|ssdp_flood/SSDP Flood|SSDP Flood"
)

for row in "${ATTACKS[@]}"; do
  IFS='|' read -r name member base <<< "$row"
  ds_gz="$DATA/ds/${base}_dataset.csv.gz"
  labels="$DATA/clean/${base}_labels.csv"
  npz="$DATA/npz/${base}_scores.npz"
  echo "================ $name ================ $(date)"
  if grep -q "^${name}," "$OUT" 2>/dev/null; then echo "already in metrics — skip"; continue; fi
  if [[ ! -f "$labels" ]]; then echo "MISSING clean labels: $labels — skip"; continue; fi
  if [[ ! -f "$npz" ]]; then
    if [[ ! -f "$ds_gz" ]]; then
      echo "extracting ${member}_dataset.csv.gz ..."
      unzip -p "$ZIP" "${member}_dataset.csv.gz" > "$ds_gz"
    fi
    "$PY" "$DIR/gen_scores.py" --attack "$name" \
        --dataset-csv "$ds_gz" --labels-csv "$labels" \
        --fm-grace 5000 --ad-grace 50000 --out "$npz"
    rm -f "$ds_gz"   # free disk once scores are computed
  fi
  "$PY" "$DIR/run_kitsune_9attack.py" --attack "$name" \
      --scores-npz "$npz" --append --output "$OUT"
  echo "done $name $(date)"
done
echo "ALL DONE $(date)"
