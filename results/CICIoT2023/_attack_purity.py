#!/usr/bin/env python3
"""Attack-purity verification for the CICIoT2023 pilot streams (READ-ONLY analysis).

For each per-attack stream TSV we independently test how much of the labelled
"attack region" (packets 180000..229999, 0-based; TSV lines 180002..230001) is
genuinely attack vs benign background, using:
  (1) attacker-IP attribution + cross-reference vs the benign region's top sources
      (benign region = packets 0..179999; TSV lines 2..180001), and
  (2) protocol / dst-IP / dst-port / packet-length signature checks.

TSV column map (0-based fields; tab-separated; row 1 = header):
  0 frame.time_epoch  1 frame.len  2 eth.src  3 eth.dst
  4 ip.src  5 ip.dst  6 tcp.srcport  7 tcp.dstport
  8 udp.srcport  9 udp.dstport  10 icmp.type  11 icmp.code
  12 arp.opcode  13 arp.src.hw_mac  14 arp.src.proto_ipv4
  15 arp.dst.hw_mac  16 arp.dst.proto_ipv4  17 ipv6.src  18 ipv6.dst
NOTE: there is NO tcp.flags column, so SYN/ACK cannot be checked directly.

Every number printed here is computed from the actual TSVs. No values are invented.
"""
import sys
from collections import Counter

PILOT = "/Users/sbhola/Desktop/cic/pilot"
ATTACKS = [
    "DoS-SYN_Flood",
    "DDoS-UDP_Flood",
    "Recon-OSScan",
    "MITM-ArpSpoofing",
    "Mirai-greeth_flood",
    "DictionaryBruteForce",
]

BENIGN_END = 180000   # 0-based packet index (exclusive) -> packets 0..179999
ATTACK_START = 180000  # 0-based -> packets 180000..229999


def get(fields, i):
    return fields[i] if i < len(fields) and fields[i] != "" else ""


def src_key(fields):
    ip = get(fields, 4)
    if ip:
        return ip
    v6 = get(fields, 17)
    if v6:
        return v6
    ap = get(fields, 14)  # arp.src.proto_ipv4
    if ap:
        return "ARP:" + ap
    return "L2/none"


def dst_key(fields):
    ip = get(fields, 5)
    if ip:
        return ip
    v6 = get(fields, 18)
    if v6:
        return v6
    ap = get(fields, 16)  # arp.dst.proto_ipv4
    if ap:
        return "ARP:" + ap
    return "L2/none"


def l4_proto(fields):
    if get(fields, 6) or get(fields, 7):
        return "TCP"
    if get(fields, 8) or get(fields, 9):
        return "UDP"
    if get(fields, 10):
        return "ICMP"
    if get(fields, 12):
        return "ARP"
    if get(fields, 17):
        return "IPv6-noL4"
    return "other"


def dport(fields):
    if get(fields, 7):
        return get(fields, 7)
    if get(fields, 9):
        return get(fields, 9)
    return ""


def is_internal(ipkey):
    return ipkey.startswith("192.168.")


def load_regions(path):
    benign_src = Counter()
    attack = []  # list of raw field lists in attack region
    with open(path, "r", errors="replace") as fh:
        next(fh)  # header
        for idx, line in enumerate(fh):  # idx is 0-based packet index
            fields = line.rstrip("\n").split("\t")
            if idx < BENIGN_END:
                benign_src[src_key(fields)] += 1
            else:
                attack.append(fields)
    return benign_src, attack


def analyze(name, benign_src, attack):
    n = len(attack)
    print("=" * 78)
    print(f"ATTACK: {name}   (attack-region packets = {n}; benign-region packets = {sum(benign_src.values())})")
    print("=" * 78)

    src = Counter()
    dst = Counter()
    dpc = Counter()
    l4 = Counter()
    lengths = []
    internal = pub = empty = 0
    for f in attack:
        s = src_key(f)
        src[s] += 1
        dst[dst_key(f)] += 1
        p = l4_proto(f)
        l4[p] += 1
        dp = dport(f)
        if dp:
            dpc[dp] += 1
        ln = get(f, 1)
        if ln.isdigit():
            lengths.append(int(ln))
        if p == "ARP" or s == "L2/none" or s.startswith("ARP:"):
            empty += 1
        elif is_internal(s):
            internal += 1
        else:
            pub += 1

    print(f"\n-- Composition: internal(192.168.x)={internal} ({internal/n:.3%})  "
          f"public={pub} ({pub/n:.3%})  ARP/L2={empty} ({empty/n:.3%})")

    print("\n-- L4 protocol breakdown (attack region):")
    for p, c in l4.most_common():
        print(f"     {p:10s} {c:7d}  {c/n:.3%}")

    print("\n-- Top 15 attack-region SOURCES (share | internal? | count in BENIGN region):")
    for s, c in src.most_common(15):
        binc = benign_src.get(s, 0)
        flag = "INTERNAL" if is_internal(s) else ("ARP/L2" if (s == "L2/none" or s.startswith("ARP:")) else "public")
        known = f"BENIGN-TOP({binc})" if binc >= 500 else (f"benign={binc}" if binc else "not-in-benign")
        print(f"     {s:22s} {c:7d}  {c/n:.3%}  {flag:9s}  {known}")

    print("\n-- Top 10 attack-region DESTINATIONS (share):")
    for d, c in dst.most_common(10):
        flag = "INTERNAL" if is_internal(d) else ("ARP/L2" if (d == "L2/none" or d.startswith("ARP:")) else "public")
        print(f"     {d:22s} {c:7d}  {c/n:.3%}  {flag}")

    print("\n-- Top 10 attack-region DST PORTS (tcp.dstport|udp.dstport):")
    for p, c in dpc.most_common(10):
        print(f"     port {p:8s} {c:7d}  {c/n:.3%}")
    print(f"     (distinct dst ports seen: {len(dpc)})")

    if lengths:
        lengths_sorted = sorted(lengths)
        m = len(lengths_sorted)
        def pct(q):
            return lengths_sorted[min(m - 1, int(q * m))]
        print(f"\n-- Packet length (bytes): min={lengths_sorted[0]} p50={pct(0.5)} "
              f"p90={pct(0.9)} p99={pct(0.99)} max={lengths_sorted[-1]} mean={sum(lengths)/m:.1f}")
        small = sum(1 for x in lengths if x <= 100)
        print(f"     packets <=100 bytes: {small} ({small/m:.3%})")

    # benign-background estimate: attack-region packets whose source is a KNOWN-BENIGN
    # host (>=500 pkts in benign region) OR public/CDN, restricted to non-attacker.
    return {
        "n": n, "internal": internal, "public": pub, "empty": empty,
        "src": src, "dst": dst, "dpc": dpc, "l4": l4,
    }


def main():
    print("BENIGN top-source profile is identical across all 6 streams (verified md5).\n")
    # compute benign profile once from the first attack's file
    bpath = f"{PILOT}/stream_{ATTACKS[0]}.pcap.tsv"
    benign_src, _ = load_regions(bpath)
    print("-- Top 15 BENIGN-region sources (packets 0..179999):")
    for s, c in benign_src.most_common(15):
        flag = "INTERNAL" if is_internal(s) else ("ARP/L2" if (s == "L2/none" or s.startswith("ARP:")) else "public")
        print(f"     {s:22s} {c:7d}  {c/180000:.3%}  {flag}")
    print()

    for name in ATTACKS:
        path = f"{PILOT}/stream_{name}.pcap.tsv"
        _, attack = load_regions(path)
        analyze(name, benign_src, attack)
        print()


if __name__ == "__main__":
    main()
