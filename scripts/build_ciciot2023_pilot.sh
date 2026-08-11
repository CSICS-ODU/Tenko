#!/usr/bin/env bash
# Build an ORDERED pilot capture + aligned ground-truth labels for Tenko from
# CICIoT2023 pcap chunks. Order = BENIGN first (calibration lead-in), then each
# attack class. Label source = the pcap file a packet came from (CICIoT2023 has
# NO per-packet ground-truth file; class == capture-session identity).
#
# Prereqs: mergecap + tshark (wireshark), and raw chunks already placed under
#   dataset/CICIoT2023/raw/<ClassName>/*.pcap
# Output:
#   dataset/CICIoT2023/CICIoT2023_pilot.pcap        (ordered merged capture)
#   dataset/CICIoT2023/CICIoT2023_pilot.pcap.tsv    (Tenko TSV; point TSV_FILE here)
#   dataset/CICIoT2023/CICIoT2023_pilot.labels.csv  (per-packet: idx,binary,class)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=dataset/CICIoT2023
RAW=$ROOT/raw
OUT_PCAP=$ROOT/CICIoT2023_pilot.pcap
LABELS=$ROOT/CICIoT2023_pilot.labels.csv

# Order is significant: benign must lead so pkts 0..100k are benign for X1 train
# (55k) + X3/X4 calibration (to 100k). Then attacks form the execution phase.
ORDER=(
  "BenignTraffic:0"
  "DDoS-UDP_Flood:1"
  "DoS-SYN_Flood:1"
  "Recon-OSScan:1"
  "MITM-ArpSpoofing:1"
  "Mirai-greeth_flood:1"
  "DictionaryBruteForce:1"
)

command -v mergecap >/dev/null || { echo "mergecap not found (install wireshark)"; exit 1; }
command -v tshark   >/dev/null || { echo "tshark not found (install wireshark)"; exit 1; }

files=(); 
for entry in "${ORDER[@]}"; do
  cls="${entry%%:*}"
  for f in $(ls "$RAW/$cls"/*.pcap 2>/dev/null | sort); do files+=("$f"); done
done
[ ${#files[@]} -gt 0 ] || { echo "no pcap chunks under $RAW/*/ — download them first"; exit 1; }

echo "Merging ${#files[@]} chunks (order preserved) -> $OUT_PCAP"
mergecap -a -F pcap -w "$OUT_PCAP" "${files[@]}"

echo "idx,binary_label,class_label" > "$LABELS"
idx=0
for entry in "${ORDER[@]}"; do
  cls="${entry%%:*}"; bin="${entry##*:}"
  for f in $(ls "$RAW/$cls"/*.pcap 2>/dev/null | sort); do
    n=$(tshark -r "$f" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
    for ((i=0;i<n;i++)); do echo "$idx,$bin,$cls" >> "$LABELS"; idx=$((idx+1)); done
    echo "  $f -> $n packets [$cls binary=$bin]"
  done
done
echo "Total labeled packets: $idx"

# Tenko TSV (exact field order). This file is what measure_all_latency.py loads.
scripts/pcap2tsv_tenko.sh "$OUT_PCAP" "$OUT_PCAP.tsv"
echo "Done. Set TSV_FILE=$OUT_PCAP.tsv  PCAP_FILE=$OUT_PCAP in measure_all_latency.py"
