#!/usr/bin/env python3
"""Profile per-source-IP composition of each CICIoT2023 pilot stream.

Read-only. Uses the on-disk TSVs (source IP = col 4) and the cached per-test
arrays. Splits every 230k-packet stream into benign_lead [0:150000],
benign_test [150000:180000], attack [180000:230000] and reports, per attack,
the dominant source IPs in each region so attacker vs benign sources can be
identified defensibly (no invented numbers)."""
import csv, os, sys
from collections import Counter, defaultdict

PILOT = "/Users/sbhola/Desktop/cic/pilot"
ATTACKS = ["DDoS-UDP_Flood","DoS-SYN_Flood","Recon-OSScan",
           "MITM-ArpSpoofing","Mirai-greeth_flood","DictionaryBruteForce"]
N_LEAD, N_TEST, N_ATK = 150000, 30000, 50000

def read_src(tsv):
    src = []
    with open(tsv, "rt", encoding="utf8") as f:
        r = csv.reader(f, delimiter="\t"); next(r)
        for row in r:
            s = ""
            if len(row) > 5 and row[4] and row[5]:
                s = row[4]
            elif len(row) > 18 and row[17] and row[18]:
                s = row[17]
            src.append(s)
    return src

def is_internal(ip):
    return ip.startswith("192.168.")

for a in ATTACKS:
    tsv = os.path.join(PILOT, f"stream_{a}.pcap.tsv")
    src = read_src(tsv)
    assert len(src) == N_LEAD+N_TEST+N_ATK, (a, len(src))
    lead = src[:N_LEAD]; test = src[N_LEAD:N_LEAD+N_TEST]; atk = src[N_LEAD+N_TEST:]
    c_lead, c_test, c_atk = Counter(lead), Counter(test), Counter(atk)
    benign_all = c_lead + c_test  # all benign-region packets
    print("="*90)
    print(f"{a}")
    print(f"  distinct sources: lead={len(c_lead)} test={len(c_test)} attack={len(c_atk)}")
    empty_atk = c_atk.get("", 0)
    print(f"  empty-src (L2/ARP-only) in attack region: {empty_atk} ({100*empty_atk/N_ATK:.1f}%)")
    # top sources in attack region + their benign presence
    print(f"  --- top 12 attack-region sources (share | benign_lead+test count | internal) ---")
    for ip, cnt in c_atk.most_common(12):
        b = benign_all.get(ip, 0)
        tag = "INTERNAL" if is_internal(ip) else ("empty" if ip=="" else "public")
        print(f"    {ip:20s} atk={cnt:6d} ({100*cnt/N_ATK:5.1f}%)  benign={b:6d}  {tag}")
    # top benign_test sources (negatives)
    print(f"  --- top 6 benign_test sources ---")
    for ip, cnt in c_test.most_common(6):
        tag = "INTERNAL" if is_internal(ip) else ("empty" if ip=="" else "public")
        print(f"    {ip:20s} test={cnt:6d} ({100*cnt/N_TEST:5.1f}%)  {tag}")
    # Candidate attacker set: internal, attack-dominant (>=99% of its packets in attack region), >=50 pkts
    attacker = []
    for ip, cnt in c_atk.items():
        if ip == "" or not is_internal(ip):
            continue
        tot = cnt + benign_all.get(ip, 0)
        if cnt >= 50 and cnt/tot >= 0.99:
            attacker.append((ip, cnt))
    attacker.sort(key=lambda x: -x[1])
    atk_pkts = sum(c for _, c in attacker)
    print(f"  ==> candidate ATTACKER sources (internal, >=99% in attack, >=50 pkts): "
          f"{len(attacker)} sources, {atk_pkts} pkts = {100*atk_pkts/N_ATK:.1f}% of attack region")
    print(f"      {[ip for ip,_ in attacker][:8]}")
