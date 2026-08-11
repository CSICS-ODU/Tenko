#!/usr/bin/env python3
"""Test the two strongest 'clear-win' hypotheses from CACHED scores only.

(A) SOURCE-LEVEL (per-device) detection: aggregate each detector's per-packet
    score to a per-source verdict and ask 'do the attacker DEVICES rank above
    benign devices?'  This is the structural analogue of the N-BaIoT per-device
    Tenko-vs-Hermes win, and matches the operational IoT question (which device
    to quarantine).  Tenko signal = X2 node score / X2-X4 pattern distance;
    Kitsune signal = per-packet tanh(RMSE).  Same aggregation applied to both.

(B) H2 attacker-IP relabel (packet-level): relabel benign-contaminant packets
    in the attack region (sources that are NOT attacker devices) to negative,
    and recompute packet-level AUC.  Does cleaning contamination lift Tenko
    MORE than Kitsune (net win) or both equally (no win)?

Attacker devices are identified from testbed structure (internal 192.168.x
source, >=99% of its packets in the attack region, >=MIN_ATK pkts) -- this uses
capture-session identity, NOT any detector score, so it is not circular w.r.t.
the Tenko-vs-Kitsune comparison. All numbers computed from on-disk TSVs and
cached npy arrays; nothing invented."""
import csv, os
import numpy as np
from collections import Counter
from sklearn.metrics import roc_auc_score

PILOT = "/Users/sbhola/Desktop/cic/pilot"
OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DDoS-UDP_Flood","DoS-SYN_Flood","Recon-OSScan",
           "MITM-ArpSpoofing","Mirai-greeth_flood","DictionaryBruteForce"]
N_LEAD, N_TEST, N_ATK = 150000, 30000, 50000
MIN_ATK = 50          # min attack packets for an internal IP to count as an attacker device
MIN_SRC_PKTS = 5      # min test-region packets for a source to be scored at source level

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

def auc_safe(y, s):
    y = np.asarray(y); s = np.asarray(s)
    if len(set(y.tolist())) < 2:
        return float("nan")
    return float(roc_auc_score(y, s))

print(f"{'attack':22s} | {'#atkDev':>7s} {'#bgnDev':>7s} | "
      f"{'src_AUC_KIT_max':>15s} {'src_AUC_TEN_max':>15s} {'src_AUC_TENcont_max':>19s} | "
      f"{'src_AUC_KIT_mean':>16s} {'src_AUC_TEN_mean':>16s}")

rows_src = []
rows_h2 = []
for a in ATTACKS:
    src_all = read_src(os.path.join(PILOT, f"stream_{a}.pcap.tsv"))
    src_test = src_all[N_LEAD:]                       # 80000 test-region sources
    lead = src_all[:N_LEAD]; test = src_all[N_LEAD:N_LEAD+N_TEST]; atk = src_all[N_LEAD+N_TEST:]
    c_lead, c_test, c_atk = Counter(lead), Counter(test), Counter(atk)
    benign_all = c_lead + c_test

    # attacker device set (internal, attack-dominant)
    attacker = set()
    for ip, cnt in c_atk.items():
        if ip == "" or not is_internal(ip):
            continue
        tot = cnt + benign_all.get(ip, 0)
        if cnt >= MIN_ATK and cnt / tot >= 0.99:
            attacker.add(ip)

    # cached per-test-packet scores
    gold = np.load(os.path.join(OUT, f"arr_gold_{a}.npy"))            # 1 in attack region
    kit  = np.load(os.path.join(OUT, f"arr_kitsune_{a}.npy"))          # tanh(RMSE)
    node = np.load(os.path.join(OUT, f"arr_node_{a}_double.npy"))      # X2 node score
    cont = np.load(os.path.join(OUT, f"arr_cont_{a}_double.npy"))      # X2-X4 pattern dist
    assert len(gold) == len(src_test) == N_TEST + N_ATK

    # ---------- (A) SOURCE-LEVEL ----------
    idx_by_src = {}
    for i, s in enumerate(src_test):
        idx_by_src.setdefault(s, []).append(i)
    ys, kit_max, kit_mean, ten_max, ten_mean, ten_c_max, ten_c_mean = [], [], [], [], [], [], []
    n_atk_dev = n_bgn_dev = 0
    for s, idxs in idx_by_src.items():
        if s == "" or len(idxs) < MIN_SRC_PKTS:
            continue
        idxs = np.array(idxs)
        y = 1 if s in attacker else 0
        ys.append(y)
        kit_max.append(float(kit[idxs].max()));  kit_mean.append(float(kit[idxs].mean()))
        ten_max.append(float(node[idxs].max()));  ten_mean.append(float(node[idxs].mean()))
        ten_c_max.append(float(cont[idxs].max())); ten_c_mean.append(float(cont[idxs].mean()))
        n_atk_dev += y; n_bgn_dev += (1 - y)
    a_kit_max = auc_safe(ys, kit_max); a_ten_max = auc_safe(ys, ten_max); a_tc_max = auc_safe(ys, ten_c_max)
    a_kit_mean = auc_safe(ys, kit_mean); a_ten_mean = auc_safe(ys, ten_mean); a_tc_mean = auc_safe(ys, ten_c_mean)
    rows_src.append((a, n_atk_dev, n_bgn_dev, a_kit_max, a_ten_max, a_tc_max, a_kit_mean, a_ten_mean, a_tc_mean))
    print(f"{a:22s} | {n_atk_dev:7d} {n_bgn_dev:7d} | "
          f"{a_kit_max:15.4f} {a_ten_max:15.4f} {a_tc_max:19.4f} | "
          f"{a_kit_mean:16.4f} {a_ten_mean:16.4f}")

    # ---------- (B) H2 packet-level relabel ----------
    # original packet-level AUC (all attack-region = positive)
    kit_auc_orig = auc_safe(gold, kit)
    ten_auc_orig = auc_safe(gold, cont)
    # H2: attack-region packet is positive ONLY if its source is an attacker device;
    # benign-contaminant attack-region packets -> negative. benign_test stays negative.
    y_h2 = np.zeros(len(gold), dtype=int)
    for i in range(N_TEST, len(gold)):   # attack region
        if src_test[i] in attacker:
            y_h2[i] = 1
    kit_auc_h2 = auc_safe(y_h2, kit)
    ten_auc_h2 = auc_safe(y_h2, cont)
    n_pos_h2 = int(y_h2.sum())
    rows_h2.append((a, kit_auc_orig, kit_auc_h2, ten_auc_orig, ten_auc_h2, n_pos_h2))

print()
print("H2 attacker-IP relabel (packet-level AUC): does cleaning lift Tenko more than Kitsune?")
print(f"{'attack':22s} | {'KIT_orig':>8s} {'KIT_h2':>8s} {'dKIT':>7s} | "
      f"{'TEN_orig':>8s} {'TEN_h2':>8s} {'dTEN':>7s} | {'net(dTEN-dKIT)':>14s} | {'n_pos_h2':>8s}")
for a, ko, kh, to, th, npos in rows_h2:
    dk = kh - ko; dt = th - to
    print(f"{a:22s} | {ko:8.4f} {kh:8.4f} {dk:+7.4f} | "
          f"{to:8.4f} {th:8.4f} {dt:+7.4f} | {dt-dk:+14.4f} | {npos:8d}")

# means
import statistics as st
def col(rows, i):
    v = [r[i] for r in rows if not (isinstance(r[i], float) and np.isnan(r[i]))]
    return sum(v)/len(v) if v else float("nan")
print()
print("SOURCE-LEVEL mean AUC across 6 attacks:")
print(f"  KIT max ={col(rows_src,3):.4f}  TEN(node) max ={col(rows_src,4):.4f}  TEN(cont) max ={col(rows_src,5):.4f}")
print(f"  KIT mean={col(rows_src,6):.4f}  TEN(node) mean={col(rows_src,7):.4f}")
