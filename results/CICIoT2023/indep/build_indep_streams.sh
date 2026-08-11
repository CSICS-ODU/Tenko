#!/usr/bin/env bash
# Build per-attack INDEPENDENT benign+attack streams for CICIoT2023.
#
# Unlike scripts/build_streams_ciciot2023.sh (which shares ONE benign lead/test
# across all 6 attacks -> byte-identical FPR), this gives each attack its OWN,
# DISTINCT 120,000-packet benign window (a distinct temporal slice / file of the
# benign corpus), to emulate Mirsky/Kitsune's per-attack separate captures.
#
# Per-attack stream layout (packet order preserved):
#   [distinct benign window: 120,000 (label 0)] + [attack _sub: 50,000 (label 1)] = 170,000
#     benign train (KitNET FM5k+AD50k)        : stream [0     : 55000 ]
#     Tenko pattern-model training            : stream [55001 : 60000 ]  benignLimit=60000
#     benign_test (FPR negatives)             : stream [60000 : 120000]  (60,000)
#     attack (TPR positives)                  : stream [120000: 170000]  (50,000)
#
# Window extraction at 0-based offset K (keep packets [K+1 : K+N_BEN]):
#   tshark -r SRC -c (K+N_BEN) -w tmp.pcap ; editcap -r tmp.pcap win.pcap (K+1)-(K+N_BEN)
#   (`editcap -r in out A-B` KEEPS A..B; WITHOUT -r it would DELETE A..B.)
#
# NOTE: macOS default bash is 3.2 (no `declare -A`), so parallel indexed arrays.
set -euo pipefail

RAW=/Users/sbhola/Desktop/cic/dataset/CICIoT2023/raw
ATKDIR=/Users/sbhola/Desktop/cic/pilot                     # attack _sub.pcap live here (READ)
OUT=/Users/sbhola/Desktop/Tenko/results/CICIoT2023/indep   # ALL new outputs INSIDE workspace
mkdir -p "$OUT"

N_BEN=120000
N_ATK=50000
BENIGNLIMIT=60000

# Parallel arrays: attack[i] gets benign window = BSRC[i] packets [BOFF[i]+1 : BOFF[i]+N_BEN].
# 6 DISJOINT windows spread across the 4 benign files (distinct sessions).
ATTACKS=( DDoS-UDP_Flood DoS-SYN_Flood     Recon-OSScan     MITM-ArpSpoofing  Mirai-greeth_flood DictionaryBruteForce )
BSRC=(    BenignTraffic  BenignTraffic      BenignTraffic1   BenignTraffic1    BenignTraffic2     BenignTraffic3       )
BOFF=(    0              600000             0                600000            0                  0                    )

count_pkts () { capinfos -c -M "$1" | awk -F': *' '/Number of packets/{print $2}' | tr -d ' '; }

PROV="$OUT/benign_window_provenance.csv"
echo "attack,benign_src,offset_start_1based,offset_end_1based,n_benign,n_attack,n_total,benignLimit" > "$PROV"

n=${#ATTACKS[@]}
for ((i=0; i<n; i++)); do
  a=${ATTACKS[$i]}
  src="$RAW/${BSRC[$i]}.pcap"
  k=${BOFF[$i]}
  start=$((k + 1))
  end=$((k + N_BEN))
  win="$OUT/benign_${a}.pcap"

  echo "==== [$((i+1))/$n] $a : benign window ${BSRC[$i]}.pcap [$start:$end] ===="
  if [ ! -f "$win" ]; then
    if [ "$k" -eq 0 ]; then
      tshark -r "$src" -c "$N_BEN" -w "$win"
    else
      tmp="$OUT/_tmp_${a}.pcap"
      tshark -r "$src" -c "$end" -w "$tmp"
      editcap -r "$tmp" "$win" "${start}-${end}"
      rm -f "$tmp"
    fi
  fi
  nben=$(count_pkts "$win")
  echo "   benign window packets: $nben"
  if [ "$nben" -ne "$N_BEN" ]; then
    echo "   [FATAL] benign window $a has $nben != $N_BEN packets (source too short?)" >&2
    exit 1
  fi

  # ---- merge benign window + attack sub ----
  stream="$OUT/stream_${a}.pcap"
  sub="$ATKDIR/${a}_sub.pcap"
  natk=$(count_pkts "$sub")
  if [ "$natk" -ne "$N_ATK" ]; then
    echo "   [FATAL] attack sub $a has $natk != $N_ATK packets" >&2
    exit 1
  fi
  mergecap -a -F pcap -w "$stream" "$win" "$sub"
  ntot=$(count_pkts "$stream")
  nsum=$((nben + natk))
  if [ "$ntot" -ne "$nsum" ]; then
    echo "   [FATAL] merged count $ntot != sum $nsum for $a" >&2
    exit 1
  fi

  # ---- aligned per-packet labels: header 'x', N_BEN zeros, N_ATK ones ----
  lab="$OUT/labels_${a}.csv"
  awk -v nb="$N_BEN" -v na="$N_ATK" 'BEGIN{print "x"; for(j=0;j<nb;j++)print 0; for(j=0;j<na;j++)print 1}' > "$lab"
  nlab=$(( $(wc -l < "$lab") - 1 ))
  if [ "$nlab" -ne "$ntot" ]; then
    echo "   [FATAL] label rows $nlab != merged packets $ntot for $a" >&2
    exit 1
  fi

  # ---- convert to Tenko TSV (EXACT 19 fields, same order as original build) ----
  tsv="$OUT/stream_${a}.pcap.tsv"
  tshark -r "$stream" -T fields \
    -e frame.time_epoch -e frame.len -e eth.src -e eth.dst \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
    -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code \
    -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
    -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst \
    -E header=y -E separator=/t -E occurrence=f > "$tsv"
  nrows=$(( $(wc -l < "$tsv") - 1 ))
  if [ "$nrows" -ne "$ntot" ]; then
    echo "   [FATAL] TSV rows $nrows != packets $ntot for $a" >&2
    exit 1
  fi

  echo "$a,${BSRC[$i]}.pcap,$start,$end,$nben,$natk,$ntot,$BENIGNLIMIT" >> "$PROV"
  echo "   $a OK: benign=$nben attack=$natk total=$ntot labels=$nlab tsv_rows=$nrows"
done

echo "ALL DONE. Provenance:"; cat "$PROV"
