#!/usr/bin/env bash
# REDUCED / rationalized CICIoT2023 stream layout (single-tanh experiment).
#
# This is a COPY of scripts/build_streams_ciciot2023.sh with reduced, rationalized
# sizes. The original build script and its streams are left INTACT. It writes to a
# SEPARATE output dir so nothing is overwritten.
#
# Rationalized split (respects KitNET grace: FMgrace 5000 + ADgrace 50000 = 55000
# minimum training). Stream order per attack (packet order preserved):
#   [benign_lead 60000]  = KitNET train 55000 (5000 FM + 50000 AD) + Tenko pattern
#                          training 4999 ([55001:60000]); benignLimit = 60000
#   [benign_test 64000]  = 5000 eta-calibration slice + 59000 FPR-eval negatives
#   [attack      50000]  = TPR positives
# Total per stream = 174000 packets.
#
# Exact 0-based index map (what the driver / analysis assume):
#   [0      : 55000 ] KitNET training  (FM grace 5000 + AD grace 50000); frozen @55001
#   [55001  : 60000 ] Tenko pattern-model training (4999 pkts) ; benignLimit=60000
#   [60000  : 65000 ] eta calibration slice (5000 benign) -- eta selection ONLY
#   [65000  : 124000] benign eval / FPR negatives (59000)
#   [124000 : 174000] attack (50000)
#
# NOTE on grace: KitNET training window CANNOT go below 55000 without changing
# FMGRACE/ADGRACE. We keep 55000. benignLimit must be > 55001 for Tenko pattern
# training to be non-empty, so the lead-in is 60000 (55000 KitNET + 4999 Tenko).
#
# IMPORTANT (how the reported numbers were actually produced): rather than
# physically rebuilding shorter PCAPs, the experiment re-ran Tenko X2-X4 with
# benignLimit=60000 on the CACHED raw KitNET RMSEs (results/CICIoT2023/_rerun_reduced.py).
# That is byte-identical to physically rebuilding this shorter stream because
# KitNET freezes after grace (KitNET/KitNET.py:61) -> a benign packet's RMSE is
# order-independent post-grace, and the Tenko models freeze at benignLimit; a
# shorter rebuild is merely a truncation of the longer cached run. This script is
# provided for provenance / reproducibility if a physical rebuild is preferred.
set -euo pipefail

RAW="${CIC_RAW_ROOT:-./data/ciciot2023/raw}"
OUT="${CIC_PILOT_REDUCED:-./data/ciciot2023/pilot_reduced}"  # SEPARATE dir; originals intact
LAB="${CIC_RESULTS_ROOT:-./results/CICIoT2023}"
mkdir -p "$OUT" "$LAB"

# Reduced, rationalized sizes:
N_LEAD=60000     # KitNET train 55000 + Tenko pattern train 4999 (benignLimit)
N_TEST=64000     # 5000 calib slice + 59000 FPR-eval
N_ATK=50000

BENIGN_LEAD_SRC="$RAW/BenignTraffic.pcap"

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
echo "==== [1/4] Extract benign test tail (packets $((N_LEAD+1))..$((N_LEAD+N_TEST))) ===="
if [ ! -f "$OUT/benign_test.pcap" ]; then
  tshark -r "$BENIGN_LEAD_SRC" -c "$((N_LEAD+N_TEST))" -w "$OUT/benign_first.pcap"
  editcap "$OUT/benign_first.pcap" "$OUT/benign_test.pcap" 1-"$N_LEAD"
  rm -f "$OUT/benign_first.pcap"
fi

echo "==== [2/4] Extract each attack (first $N_ATK) ===="
for a in "${ATTACKS[@]}"; do
  if [ ! -f "$OUT/${a}_sub.pcap" ]; then
    tshark -r "$RAW/${a}.pcap" -c "$N_ATK" -w "$OUT/${a}_sub.pcap"
  fi
done

echo "==== [3/4] Merge streams + write aligned labels ===="
SUMMARY="$LAB/stream_counts_reduced.csv"
echo "attack,n_lead,n_test,n_attack,n_total_merged,benignLimit" > "$SUMMARY"
for a in "${ATTACKS[@]}"; do
  stream="$OUT/stream_${a}.pcap"
  mergecap -a -F pcap -w "$stream" "$OUT/benign_lead.pcap" "$OUT/benign_test.pcap" "$OUT/${a}_sub.pcap"
  n_lead=$(count_pkts "$OUT/benign_lead.pcap")
  n_test=$(count_pkts "$OUT/benign_test.pcap")
  n_atk=$(count_pkts "$OUT/${a}_sub.pcap")
  n_total=$(count_pkts "$stream")
  labfile="$LAB/labels_${a}_reduced.csv"
  {
    echo "x"
    for ((i=0;i<n_lead+n_test;i++)); do echo 0; done
    for ((i=0;i<n_atk;i++)); do echo 1; done
  } > "$labfile"
  echo "$a,$n_lead,$n_test,$n_atk,$n_total,$n_lead" >> "$SUMMARY"
  echo "    $a: lead=$n_lead test=$n_test attack=$n_atk total=$n_total"
done

echo "==== [4/4] Convert each stream pcap -> Tenko TSV ===="
for a in "${ATTACKS[@]}"; do
  stream="$OUT/stream_${a}.pcap"; tsv="$OUT/stream_${a}.pcap.tsv"
  tshark -r "$stream" -T fields \
    -e frame.time_epoch -e frame.len -e eth.src -e eth.dst \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
    -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code \
    -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
    -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst \
    -E header=y -E separator=/t -E occurrence=f > "$tsv"
done
echo "ALL DONE. Summary:"; cat "$SUMMARY"
