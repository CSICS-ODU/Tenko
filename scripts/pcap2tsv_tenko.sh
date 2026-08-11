#!/usr/bin/env bash
# Convert a pcap to the exact TSV field layout Tenko's FeatureExtractor.FE expects.
# Field order MUST match FeatureExtractor.pcap2tsv_with_tshark():
#   col0 frame.time_epoch  col1 frame.len  col2 eth.src  col3 eth.dst
#   col4 ip.src  col5 ip.dst  col6 tcp.srcport col7 tcp.dstport
#   col8 udp.srcport col9 udp.dstport col10 icmp.type col11 icmp.code
#   col12 arp.opcode col13 arp.src.hw_mac col14 arp.src.proto_ipv4
#   col15 arp.dst.hw_mac col16 arp.dst.proto_ipv4  col17 ipv6.src col18 ipv6.dst
# => src IP is col4 (IPv4) or col17 (IPv6). Do NOT reorder.
#
# Usage: scripts/pcap2tsv_tenko.sh input.pcap [output.tsv]
set -euo pipefail
IN="${1:?usage: pcap2tsv_tenko.sh input.pcap [output.tsv]}"
OUT="${2:-${IN}.tsv}"
command -v tshark >/dev/null || { echo "tshark not found; install wireshark/tshark first"; exit 1; }
tshark -r "$IN" -T fields \
  -e frame.time_epoch -e frame.len -e eth.src -e eth.dst \
  -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code \
  -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
  -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst \
  -E header=y -E separator=/t -E occurrence=f > "$OUT"
echo "wrote $OUT ($(wc -l < "$OUT") lines incl. header)"
