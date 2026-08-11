#!/usr/bin/env python3
"""Source-level (per-device) detection experiment on CICIoT2023 pilot.

HEADLINE HYPOTHESIS: the operationally meaningful IoT-IDS question is device
attribution -- 'which SOURCE device is malicious?' (you quarantine devices, not
packets). This is the same granularity as the paper's N-BaIoT per-device
Tenko-vs-Hermes table. We aggregate each detector's per-packet score to a
per-source verdict (same aggregation for both) and compute source-level ROC-AUC
over {attacker device = 1, benign device = 0}.

  Kitsune per-source signal = aggregate of per-packet tanh(RMSE)   [cached arr_kitsune]
  Tenko   per-source signal = aggregate of X2-X4 pattern distance  [cached arr_cont]

Attacker devices = internal 192.168.x source, >=99% of its packets in the attack
region, >= MIN_ATK packets (testbed capture-session identity; independent of any
detector score -> not circular). Everything from on-disk TSVs + cached npy.
Nothing invented. Threshold-independent AUC is the headline; a benign-device
calibrated operating point is also reported.
"""
import csv, os
import numpy as np
from collections import Counter
from sklearn.metrics import roc_auc_score, roc_curve

PILOT = os.environ.get("CIC_DATA_ROOT", "./data/ciciot2023/pilot")
OUT = os.environ.get("CIC_RESULTS_ROOT", "./results/CICIoT2023")
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

def auc_eer(y, s):
    y = np.asarray(y); s = np.asarray(s)
    if len(set(y.tolist())) < 2:
        return float("nan"), float("nan")
    fpr, tpr, _ = roc_curve(y, s)
    a = roc_auc_score(y, s)
    fnr = 1 - tpr
    i = int(np.nanargmin(np.abs(fpr - fnr)))
    return float(a), float((fpr[i] + fnr[i]) / 2)

def agg(vals, how):
    if how == "max":  return float(np.max(vals))
    if how == "mean": return float(np.mean(vals))
    if how == "p95":  return float(np.percentile(vals, 95))
    raise ValueError(how)

def attacker_set(c_atk, benign_all, min_atk, include_public):
    s = set()
    for ip, cnt in c_atk.items():
        if ip == "":
            continue
        if not include_public and not is_internal(ip):
            continue
        tot = cnt + benign_all.get(ip, 0)
        if cnt >= min_atk and cnt / tot >= 0.99:
            s.add(ip)
    return s

def build(attack):
    src_all = read_src(os.path.join(PILOT, f"stream_{attack}.pcap.tsv"))
    src_test = src_all[N_LEAD:]
    c = dict(lead=Counter(src_all[:N_LEAD]), test=Counter(src_all[N_LEAD:N_LEAD+N_TEST]),
             atk=Counter(src_all[N_LEAD+N_TEST:]))
    c["benign_all"] = c["lead"] + c["test"]
    kit  = np.load(os.path.join(OUT, f"arr_kitsune_{attack}.npy"))
    cont = np.load(os.path.join(OUT, f"arr_cont_{attack}_double.npy"))
    return src_test, c, kit, cont

def source_table(attack, min_atk=50, include_public=False, min_src_pkts=5, how="max"):
    src_test, c, kit, cont = build(attack)
    atk = attacker_set(c["atk"], c["benign_all"], min_atk, include_public)
    idx_by_src = {}
    for i, s in enumerate(src_test):
        idx_by_src.setdefault(s, []).append(i)
    ys, sk, sc = [], [], []
    for s, idxs in idx_by_src.items():
        if s == "" or len(idxs) < min_src_pkts:
            continue
        idxs = np.array(idxs)
        ys.append(1 if s in atk else 0)
        sk.append(agg(kit[idxs], how)); sc.append(agg(cont[idxs], how))
    ak, ek = auc_eer(ys, sk); ac, ec = auc_eer(ys, sc)
    return dict(n_atk=sum(ys), n_bgn=len(ys)-sum(ys),
                kit_auc=ak, kit_eer=ek, ten_auc=ac, ten_eer=ec,
                ys=np.array(ys), sk=np.array(sk), sc=np.array(sc))

# ---------------- HEADLINE TABLE (max aggregation, internal attackers, >=50 pkts) ----------------
print("="*100)
print("HEADLINE: source-level (per-device) ROC-AUC/EER -- max aggregation, internal attacker devices")
print("="*100)
hdr = f"{'attack':22s} {'#atkDev':>7s} {'#bgnDev':>7s} | {'KIT AUC':>8s} {'KIT EER':>8s} | {'TEN AUC':>8s} {'TEN EER':>8s} | {'dAUC':>7s} winner"
print(hdr)
rows = []
for a in ATTACKS:
    r = source_table(a, how="max")
    d = r["ten_auc"] - r["kit_auc"]
    w = "TENKO" if d > 1e-4 else ("Kitsune" if d < -1e-4 else "tie")
    print(f"{a:22s} {r['n_atk']:7d} {r['n_bgn']:7d} | {r['kit_auc']:8.4f} {r['kit_eer']:8.4f} | "
          f"{r['ten_auc']:8.4f} {r['ten_eer']:8.4f} | {d:+7.4f} {w}")
    rows.append((a, r))
mk = np.nanmean([r["kit_auc"] for _, r in rows]); mt = np.nanmean([r["ten_auc"] for _, r in rows])
ek = np.nanmean([r["kit_eer"] for _, r in rows]); et = np.nanmean([r["ten_eer"] for _, r in rows])
wins = sum(1 for _, r in rows if r["ten_auc"]-r["kit_auc"] > 1e-4)
ties = sum(1 for _, r in rows if abs(r["ten_auc"]-r["kit_auc"]) <= 1e-4)
print("-"*100)
print(f"{'MEAN':22s} {'':7s} {'':7s} | {mk:8.4f} {ek:8.4f} | {mt:8.4f} {et:8.4f} | {mt-mk:+7.4f}  "
      f"Tenko wins {wins}/6, ties {ties}/6, losses {6-wins-ties}/6")

# write paste-ready CSV
with open(os.path.join(OUT, "ciciot2023_source_level_metrics.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["attack","n_attacker_dev","n_benign_dev","kitsune_src_AUC","kitsune_src_EER",
                "tenko_src_AUC","tenko_src_EER","delta_AUC"])
    for a, r in rows:
        w.writerow([a, r["n_atk"], r["n_bgn"], f"{r['kit_auc']:.6f}", f"{r['kit_eer']:.6f}",
                    f"{r['ten_auc']:.6f}", f"{r['ten_eer']:.6f}", f"{r['ten_auc']-r['kit_auc']:.6f}"])
    w.writerow(["MEAN","","",f"{mk:.6f}",f"{ek:.6f}",f"{mt:.6f}",f"{et:.6f}",f"{mt-mk:.6f}"])
print(f"\n[wrote] ciciot2023_source_level_metrics.csv")

# ---------------- ROBUSTNESS ----------------
print("\n" + "="*100)
print("ROBUSTNESS 1: aggregation choice (mean over 6 attacks, internal attackers >=50)")
print("="*100)
for how in ["max","mean","p95"]:
    rr = [source_table(a, how=how) for a in ATTACKS]
    mk = np.nanmean([r["kit_auc"] for r in rr]); mt = np.nanmean([r["ten_auc"] for r in rr])
    wins = sum(1 for r in rr if r["ten_auc"]-r["kit_auc"] > 1e-4)
    print(f"  agg={how:5s}: Kitsune meanAUC={mk:.4f}  Tenko meanAUC={mt:.4f}  dAUC={mt-mk:+.4f}  Tenko wins {wins}/6")

print("\nROBUSTNESS 2: attacker-set definition (max aggregation, mean over 6 attacks)")
for min_atk, inc in [(50,False),(100,False),(200,False),(50,True)]:
    rr = [source_table(a, min_atk=min_atk, include_public=inc, how="max") for a in ATTACKS]
    mk = np.nanmean([r["kit_auc"] for r in rr]); mt = np.nanmean([r["ten_auc"] for r in rr])
    wins = sum(1 for r in rr if r["ten_auc"]-r["kit_auc"] > 1e-4)
    lab = f"min_atk={min_atk}, include_public={inc}"
    print(f"  {lab:34s}: Kitsune={mk:.4f}  Tenko={mt:.4f}  dAUC={mt-mk:+.4f}  Tenko wins {wins}/6")

print("\nROBUSTNESS 3: min packets/source (max aggregation, mean over 6 attacks)")
for mp in [1,5,20,50]:
    rr = [source_table(a, min_src_pkts=mp, how="max") for a in ATTACKS]
    mk = np.nanmean([r["kit_auc"] for r in rr]); mt = np.nanmean([r["ten_auc"] for r in rr])
    wins = sum(1 for r in rr if r["ten_auc"]-r["kit_auc"] > 1e-4)
    print(f"  min_src_pkts={mp:3d}: Kitsune={mk:.4f}  Tenko={mt:.4f}  dAUC={mt-mk:+.4f}  Tenko wins {wins}/6")

# ---------------- SOURCE-LEVEL OPERATING POINT (benign-device calibrated) ----------------
print("\n" + "="*100)
print("OPERATING POINT: per-source threshold at ~10% benign-DEVICE FPR")
print("="*100)
print(f"{'attack':22s} | {'KIT TPR@10%FPR':>14s} | {'TEN TPR@10%FPR':>14s}")
for a in ATTACKS:
    r = source_table(a, how="max")
    ys = r["ys"]
    def tpr_at(scores):
        neg = scores[ys==0]; pos = scores[ys==1]
        if len(pos)==0 or len(neg)==0: return float("nan")
        thr = np.quantile(neg, 0.90)   # ~10% benign-device FPR
        return float((pos > thr).mean())
    print(f"{a:22s} | {tpr_at(r['sk']):14.3f} | {tpr_at(r['sc']):14.3f}")
