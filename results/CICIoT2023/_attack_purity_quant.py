#!/usr/bin/env python3
"""Second pass: per-attack signature-consistent flow quantification (READ-ONLY).

Builds on _attack_purity.py. For each attack we define an explicit signature
flow (attacker<->victim, protocol, port) and count the fraction of attack-region
packets (0-based 180000..229999) that match it, plus a benign-background share.
All counts come from the actual TSVs.
"""
from collections import Counter

PILOT = "/Users/sbhola/Desktop/cic/pilot"
BENIGN_END = 180000


def get(f, i):
    return f[i] if i < len(f) and f[i] != "" else ""


def src_key(f):
    return get(f, 4) or get(f, 17) or ("ARP:" + get(f, 14) if get(f, 14) else "L2/none")


def dst_key(f):
    return get(f, 5) or get(f, 18) or ("ARP:" + get(f, 16) if get(f, 16) else "L2/none")


def l4(f):
    if get(f, 6) or get(f, 7):
        return "TCP"
    if get(f, 8) or get(f, 9):
        return "UDP"
    if get(f, 10):
        return "ICMP"
    if get(f, 12):
        return "ARP"
    if get(f, 17):
        return "IPv6"
    return "other"


def dport(f):
    return get(f, 7) or get(f, 9) or ""


def load(name):
    benign = Counter()
    atk = []
    with open(f"{PILOT}/stream_{name}.pcap.tsv", errors="replace") as fh:
        next(fh)
        for idx, line in enumerate(fh):
            f = line.rstrip("\n").split("\t")
            if idx < BENIGN_END:
                benign[src_key(f)] += 1
            else:
                atk.append(f)
    return benign, atk


def known_benign_hosts(benign, thresh=500):
    return {s for s, c in benign.items() if c >= thresh}


def report(name, benign, atk, attackers, victims, sig_fn):
    n = len(atk)
    kb = known_benign_hosts(benign)
    attacker_share = sum(1 for f in atk if src_key(f) in attackers)
    victim_flow = sum(1 for f in atk if sig_fn(f))
    # benign-background: source is a known-benign host AND not part of the signature
    # flow AND not an identified attacker -> most defensible "contamination"
    benign_bg = 0
    public_nonatk = 0
    for f in atk:
        s = src_key(f)
        if sig_fn(f):
            continue
        if s in attackers or s in victims:
            continue
        if s in kb:
            benign_bg += 1
        if not s.startswith("192.168.") and not s.startswith("ARP:") and s != "L2/none":
            public_nonatk += 1
    print(f"### {name}")
    print(f"    attack-region packets: {n}")
    print(f"    attacker-source share (identified attacker IPs {sorted(attackers)}): "
          f"{attacker_share} ({attacker_share/n:.3%})")
    print(f"    signature-consistent flow share: {victim_flow} ({victim_flow/n:.3%})")
    print(f"    benign-background (known-benign src, non-signature, non-attacker): "
          f"{benign_bg} ({benign_bg/n:.3%})")
    print(f"    public/CDN non-signature share: {public_nonatk} ({public_nonatk/n:.3%})")

    # ---- mutually-exclusive 3-way partition (sums to 100%) ----
    genuine = benign = ambig = 0
    for f in atk:
        s = src_key(f)
        if sig_fn(f):
            genuine += 1
        elif (s in kb) or (not s.startswith("192.168.") and not s.startswith("ARP:") and s != "L2/none"):
            benign += 1  # known-benign internal host OR public/CDN, non-signature
        else:
            ambig += 1
    print(f"    PARTITION -> genuine_attack={genuine} ({genuine/n:.3%})  "
          f"benign_background={benign} ({benign/n:.3%})  ambiguous={ambig} ({ambig/n:.3%})")
    print()


def main():
    # ---- DoS-SYN: attacker .182 floods victim .187 on TCP port 4070; victim replies ----
    b, a = load("DoS-SYN_Flood")
    A = {"192.168.137.182"}
    V = {"192.168.137.187"}
    def sig(f):
        return (l4(f) == "TCP" and
                {src_key(f), dst_key(f)} <= {"192.168.137.182", "192.168.137.187"})
    report("DoS-SYN_Flood", b, a, A, V, sig)

    # ---- DDoS-UDP: many bots flood victim .30 with UDP ----
    b, a = load("DDoS-UDP_Flood")
    A = {"192.168.137.17", "192.168.137.224", "192.168.137.240", "192.168.137.134",
         "192.168.137.58", "192.168.137.195", "192.168.137.96"}
    V = {"192.168.137.30"}
    def sig(f):
        return l4(f) == "UDP" and dst_key(f) == "192.168.137.30"
    report("DDoS-UDP_Flood", b, a, A, V, sig)

    # ---- Recon-OSScan: scan = small packets to internal victims, NOT web/CDN 443 ----
    b, a = load("Recon-OSScan")
    A = {"192.168.137.178", "192.168.137.206", "192.168.137.196", "192.168.137.59",
         "192.168.137.81"}
    V = set()
    def sig(f):
        # scan signature: internal->internal, small (<=100B), dst port not 443/80 web
        s, d = src_key(f), dst_key(f)
        ln = get(f, 1)
        small = ln.isdigit() and int(ln) <= 100
        return (s.startswith("192.168.") and d.startswith("192.168.") and small and
                dport(f) not in ("443", "80"))
    report("Recon-OSScan", b, a, A, V, sig)

    # ---- MITM: attacker .162 relays victim traffic to/from 205.251.251.216 ----
    b, a = load("MITM-ArpSpoofing")
    A = {"192.168.137.162"}
    V = {"205.251.251.216"}
    def sig(f):
        return {src_key(f), dst_key(f)} <= {"192.168.137.162", "205.251.251.216"} or l4(f) == "ARP"
    report("MITM-ArpSpoofing", b, a, A, V, sig)

    # ---- Mirai: bot .129 + C2 69.168.130.48 + greeth flood ports 54742/54750 to .254 ----
    b, a = load("Mirai-greeth_flood")
    A = {"192.168.137.129", "192.168.137.128", "192.168.137.238", "192.168.137.207",
         "192.168.137.147", "192.168.137.106", "192.168.137.120"}
    V = {"69.168.130.48", "192.168.137.254", "192.168.137.129"}
    C2 = "69.168.130.48"
    def sig(f):
        s, d = src_key(f), dst_key(f)
        # C2 exchange with .129, or greeth flood ports, or bot->.254 victim
        if C2 in (s, d):
            return True
        if dport(f) in ("54742", "54750", "54639"):
            return True
        if s in A and d.startswith("192.168.") and d in {"192.168.137.254", "192.168.137.129"}:
            return True
        return False
    report("Mirai-greeth_flood", b, a, A, V, sig)

    # ---- Dictionary BruteForce: repeated login attempts, SSH port 22 + .67<->.65 pair ----
    b, a = load("DictionaryBruteForce")
    A = {"192.168.137.67", "192.168.137.65", "192.168.137.137", "192.168.137.147",
         "192.168.137.174"}
    V = {"192.168.137.65", "192.168.137.67"}
    def sig(f):
        # brute-force signature: dst port 22 (SSH) or common login ports, internal<->internal
        s, d = src_key(f), dst_key(f)
        if dport(f) in ("22", "23", "21", "3389", "8728"):
            return True
        if s.startswith("192.168.") and d.startswith("192.168.") and \
           {s, d} <= {"192.168.137.65", "192.168.137.67", "192.168.137.137",
                      "192.168.137.174", "192.168.137.51", "192.168.137.210",
                      "192.168.137.206", "192.168.137.242"}:
            return True
        return False
    report("DictionaryBruteForce", b, a, A, V, sig)


if __name__ == "__main__":
    main()
