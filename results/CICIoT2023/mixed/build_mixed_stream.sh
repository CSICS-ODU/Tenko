#!/usr/bin/env bash
# Build ONE combined "mixed" CICIoT2023 stream:
#   [shared benign 120,000] + all SIX attack _sub.pcaps (50k each) concatenated
#   back-to-back IN A FIXED ORDER = 120,000 + 300,000 = 420,000 packets.
#
# This is the "one big stream, same benign, different attacks" analog of the
# paper's Kitsune combined-attack regime. Node state carries across the WHOLE
# stream (physically concatenated run, NOT pooled per-attack arrays).
#
# Stream layout (0-indexed packet blocks):
#   benign        [     0 : 120000]  label 0  (train + FPR negatives)
#   DoS-SYN_Flood [120000 : 170000]  label 1
#   DDoS-UDP_Flood[170000 : 220000]  label 1
#   Recon-OSScan  [220000 : 270000]  label 1
#   MITM-ArpSpoofing[270000:320000]  label 1
#   Mirai-greeth_flood[320000:370000] label 1
#   DictionaryBruteForce[370000:420000] label 1
#
# benignLimit = 60000 (KitNET trains [0:55000]; Tenko pattern on [55001:60000]).
# Test region = [60000:420000] = 60k benign negatives + 300k attack positives.
#
# Robustness mirrors scripts/build_streams_ciciot2023.sh: tshark -c N to grab
# first-N packets (never scans the whole 2 GB benign trace), capinfos count
# assertions at every step, header-'x' label CSV, exact 19-field tshark TSV.
# This is a NEW script; the original is untouched.
set -euo pipefail

RAW_BENIGN="${CIC_RAW_ROOT:-./data/ciciot2023/raw}/BenignTraffic.pcap"
PILOT="${CIC_DATA_ROOT:-./data/ciciot2023/pilot}"          # attack _sub.pcaps live here (READ-only)
MIX="${CIC_RESULTS_ROOT:-./results/CICIoT2023}/mixed"   # ALL new outputs go here
mkdir -p "$MIX"

# Keep any tshark/mergecap/editcap temp files inside the workspace sandbox.
export TMPDIR="$MIX/tmp"; mkdir -p "$TMPDIR"

N_BENIGN=120000
N_ATK=50000
# Fixed attack order for concatenation + per-attack breakdown.
ATTACKS=(
  "DoS-SYN_Flood"
  "DDoS-UDP_Flood"
  "Recon-OSScan"
  "MITM-ArpSpoofing"
  "Mirai-greeth_flood"
  "DictionaryBruteForce"
)

count_pkts () { capinfos -c -M "$1" | awk -F': *' '/Number of packets/{print $2}' | tr -d ' '; }

echo "==== [1/5] Extract shared benign lead-in ($N_BENIGN from $(basename "$RAW_BENIGN")) ===="
if [ ! -f "$MIX/benign_shared.pcap" ]; then
  tshark -r "$RAW_BENIGN" -c "$N_BENIGN" -w "$MIX/benign_shared.pcap"
fi
N_BEN_ACT=$(count_pkts "$MIX/benign_shared.pcap")
echo "  benign_shared actual packets: $N_BEN_ACT"
if [ "$N_BEN_ACT" -ne "$N_BENIGN" ]; then
  echo "  [FATAL] benign_shared count $N_BEN_ACT != $N_BENIGN" >&2; exit 1
fi

echo "==== [2/5] Verify attack _sub.pcaps ($N_ATK each) ===="
for a in "${ATTACKS[@]}"; do
  sub="$PILOT/${a}_sub.pcap"
  if [ ! -f "$sub" ]; then echo "  [FATAL] missing $sub" >&2; exit 1; fi
  n=$(count_pkts "$sub")
  echo "  $a: $n packets"
  if [ "$n" -ne "$N_ATK" ]; then
    echo "  [FATAL] $a sub count $n != $N_ATK" >&2; exit 1
  fi
done

echo "==== [3/5] Merge benign + 6 attacks (IN ORDER) -> stream_mixed.pcap ===="
# mergecap -a APPENDS (concatenates) in argument order, preserving packet order
# within each input. This gives the physically concatenated single stream.
mergecap -a -F pcap -w "$MIX/stream_mixed.pcap" \
  "$MIX/benign_shared.pcap" \
  "$PILOT/DoS-SYN_Flood_sub.pcap" \
  "$PILOT/DDoS-UDP_Flood_sub.pcap" \
  "$PILOT/Recon-OSScan_sub.pcap" \
  "$PILOT/MITM-ArpSpoofing_sub.pcap" \
  "$PILOT/Mirai-greeth_flood_sub.pcap" \
  "$PILOT/DictionaryBruteForce_sub.pcap"

N_TOTAL=$(count_pkts "$MIX/stream_mixed.pcap")
N_EXPECT=$(( N_BENIGN + 6 * N_ATK ))
echo "  stream_mixed packets: $N_TOTAL (expected $N_EXPECT)"
if [ "$N_TOTAL" -ne "$N_EXPECT" ]; then
  echo "  [FATAL] merged count $N_TOTAL != expected $N_EXPECT" >&2; exit 1
fi

echo "==== [4/5] Write aligned labels_mixed.csv (header 'x'; 120k zeros + 300k ones) ===="
LAB="$MIX/labels_mixed.csv"
# awk (no pipes) avoids the `yes|head` SIGPIPE that trips `set -o pipefail`.
awk -v nb="$N_BENIGN" -v na="$(( 6 * N_ATK ))" \
  'BEGIN{print "x"; for(i=0;i<nb;i++)print 0; for(i=0;i<na;i++)print 1}' > "$LAB"
N_LAB=$(( $(wc -l < "$LAB") - 1 ))
echo "  label rows: $N_LAB"
if [ "$N_LAB" -ne "$N_TOTAL" ]; then
  echo "  [FATAL] label rows $N_LAB != packets $N_TOTAL" >&2; exit 1
fi

echo "==== [5/5] Convert stream_mixed.pcap -> Tenko TSV (exact 19 fields) ===="
TSV="$MIX/stream_mixed.pcap.tsv"
tshark -r "$MIX/stream_mixed.pcap" -T fields \
  -e frame.time_epoch -e frame.len -e eth.src -e eth.dst \
  -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code \
  -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
  -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst \
  -E header=y -E separator=/t -E occurrence=f > "$TSV"
N_ROWS=$(( $(wc -l < "$TSV") - 1 ))
echo "  TSV rows: $N_ROWS (packets $N_TOTAL)"
if [ "$N_ROWS" -ne "$N_TOTAL" ]; then
  echo "  [FATAL] TSV rows $N_ROWS != packets $N_TOTAL" >&2; exit 1
fi

# Record attack block boundaries for the per-attack breakdown.
BLK="$MIX/attack_blocks.csv"
{
  echo "attack,start_idx,end_idx,n_packets"
  echo "DoS-SYN_Flood,120000,170000,50000"
  echo "DDoS-UDP_Flood,170000,220000,50000"
  echo "Recon-OSScan,220000,270000,50000"
  echo "MITM-ArpSpoofing,270000,320000,50000"
  echo "Mirai-greeth_flood,320000,370000,50000"
  echo "DictionaryBruteForce,370000,420000,50000"
} > "$BLK"

rm -rf "$TMPDIR"
echo "ALL DONE."
echo "  pcap:   $MIX/stream_mixed.pcap  ($N_TOTAL packets)"
echo "  labels: $LAB  ($N_LAB rows)"
echo "  tsv:    $TSV  ($N_ROWS rows)"
echo "  blocks: $BLK"
