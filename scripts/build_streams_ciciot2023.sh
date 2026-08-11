#!/usr/bin/env bash
# Build per-attack benign+attack streams for the CICIoT2023 PCAP pilot.
#
# Stream order per attack (packet order preserved):
#   [benign_lead (label 0, calibration)] + [benign_test (label 0, FPR negatives)] + [attack_sub (label 1, TPR positives)]
#
# benignLimit (train/test split) = len(benign_lead), so the TEST region is
# benign_test (negatives) + attack (positives). FPR is measured only on
# benign_test; benign_lead is the KitNET+pattern calibration lead-in.
#
# "First N packets" is extracted with `tshark -c N -w` (stops early; avoids
# scanning the whole 2 GB file). NOTE: `editcap in out 1-N` WITHOUT -r would
# DELETE that range, so we deliberately avoid that footgun.
set -euo pipefail

RAW=/Users/sbhola/Desktop/cic/dataset/CICIoT2023/raw
OUT=/Users/sbhola/Desktop/cic/pilot                 # big pcaps/tsvs live OUTSIDE the git repo
LAB=/Users/sbhola/Desktop/Tenko/results/CICIoT2023  # small label CSVs live in-repo (not committed)
mkdir -p "$OUT" "$LAB"

N_LEAD=150000
N_TEST=30000
N_ATK=50000

BENIGN_LEAD_SRC="$RAW/BenignTraffic.pcap"
# In-distribution held-out benign: packets (N_LEAD+1 .. N_LEAD+N_TEST) of the SAME
# BenignTraffic.pcap. This is the standard Kitsune protocol (benign train + benign
# test from the same trace) and avoids cross-session distribution shift that would
# artificially inflate FPR. Extracted via the "first N_LEAD+N_TEST then drop first
# N_LEAD" trick (editcap WITHOUT -r deletes the listed range).

ATTACKS=(
  "DDoS-UDP_Flood"
  "DoS-SYN_Flood"
  "Recon-OSScan"
  "MITM-ArpSpoofing"
  "Mirai-greeth_flood"
  "DictionaryBruteForce"
)

count_pkts () { capinfos -c -M "$1" | awk -F': *' '/Number of packets/{print $2}' | tr -d ' '; }

echo "==== [1/4] Extract benign lead-in ($N_LEAD from $(basename "$BENIGN_LEAD_SRC")) ===="
if [ ! -f "$OUT/benign_lead.pcap" ]; then
  tshark -r "$BENIGN_LEAD_SRC" -c "$N_LEAD" -w "$OUT/benign_lead.pcap"
fi
echo "==== [1/4] Extract in-distribution benign test tail (packets $((N_LEAD+1))..$((N_LEAD+N_TEST)) of $(basename "$BENIGN_LEAD_SRC")) ===="
if [ ! -f "$OUT/benign_test.pcap" ]; then
  tshark -r "$BENIGN_LEAD_SRC" -c "$((N_LEAD+N_TEST))" -w "$OUT/benign_first.pcap"
  # editcap WITHOUT -r DELETES packets 1..N_LEAD, leaving N_LEAD+1..N_LEAD+N_TEST
  editcap "$OUT/benign_first.pcap" "$OUT/benign_test.pcap" 1-"$N_LEAD"
  rm -f "$OUT/benign_first.pcap"
fi

N_LEAD_ACT=$(count_pkts "$OUT/benign_lead.pcap")
N_TEST_ACT=$(count_pkts "$OUT/benign_test.pcap")
echo "benign_lead actual packets: $N_LEAD_ACT"
echo "benign_test actual packets: $N_TEST_ACT"

echo "==== [2/4] Extract each attack (first $N_ATK) ===="
for a in "${ATTACKS[@]}"; do
  if [ ! -f "$OUT/${a}_sub.pcap" ]; then
    echo "  -> $a"
    tshark -r "$RAW/${a}.pcap" -c "$N_ATK" -w "$OUT/${a}_sub.pcap"
  fi
done

echo "==== [3/4] Merge streams + write aligned labels ===="
SUMMARY="$LAB/stream_counts.csv"
echo "attack,n_lead,n_test,n_attack,n_total_merged,benignLimit" > "$SUMMARY"
for a in "${ATTACKS[@]}"; do
  stream="$OUT/stream_${a}.pcap"
  echo "  merge -> $(basename "$stream")"
  mergecap -a -F pcap -w "$stream" "$OUT/benign_lead.pcap" "$OUT/benign_test.pcap" "$OUT/${a}_sub.pcap"

  n_lead=$(count_pkts "$OUT/benign_lead.pcap")
  n_test=$(count_pkts "$OUT/benign_test.pcap")
  n_atk=$(count_pkts "$OUT/${a}_sub.pcap")
  n_total=$(count_pkts "$stream")
  n_sum=$((n_lead + n_test + n_atk))
  if [ "$n_total" -ne "$n_sum" ]; then
    echo "  [FATAL] merged count $n_total != sum $n_sum for $a" >&2
    exit 1
  fi

  # Aligned per-packet label CSV: header 'x' so results.build_label_list works.
  labfile="$LAB/labels_${a}.csv"
  {
    echo "x"
    for ((i=0;i<n_lead+n_test;i++)); do echo 0; done
    for ((i=0;i<n_atk;i++)); do echo 1; done
  } > "$labfile"
  n_lab=$(( $(wc -l < "$labfile") - 1 ))
  if [ "$n_lab" -ne "$n_total" ]; then
    echo "  [FATAL] label rows $n_lab != merged packets $n_total for $a" >&2
    exit 1
  fi
  echo "$a,$n_lead,$n_test,$n_atk,$n_total,$n_lead" >> "$SUMMARY"
  echo "    $a: lead=$n_lead test=$n_test attack=$n_atk total=$n_total labels=$n_lab OK"
done

echo "==== [4/4] Convert each stream pcap -> Tenko TSV ===="
for a in "${ATTACKS[@]}"; do
  stream="$OUT/stream_${a}.pcap"
  tsv="$OUT/stream_${a}.pcap.tsv"
  echo "  tshark -> $(basename "$tsv")"
  tshark -r "$stream" -T fields \
    -e frame.time_epoch -e frame.len -e eth.src -e eth.dst \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
    -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code \
    -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
    -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst \
    -E header=y -E separator=/t -E occurrence=f > "$tsv"
  n_rows=$(( $(wc -l < "$tsv") - 1 ))
  n_total=$(count_pkts "$stream")
  if [ "$n_rows" -ne "$n_total" ]; then
    echo "  [FATAL] TSV rows $n_rows != packets $n_total for $a" >&2
    exit 1
  fi
  echo "    $a: tsv_rows=$n_rows == packets=$n_total OK"
done

echo "ALL DONE. Summary:"; cat "$SUMMARY"
