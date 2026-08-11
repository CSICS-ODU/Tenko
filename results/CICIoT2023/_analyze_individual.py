#!/usr/bin/env python3
"""Per-attack INDIVIDUAL-stream metrics: give each attack its OWN disjoint benign
test slice (instead of the shared benign trace) so FPR can vary per attack.

Cached arrays (benignLimit=60000), test_idx = stream-60000, len 170000.
Post-calibration benign pool = stream [100000:180000] = test_idx [40000:120000] (80000).
We carve that pool into 6 disjoint contiguous windows, one per attack (in list order),
and evaluate committed eta=50/20 on each attack's own window + its own attack region.

ALSO: a control where each attack's benign test is a RANDOM sample (seeded per attack)
drawn across the whole pool -- shows contiguous vs representative sampling.
"""
from __future__ import annotations
import csv, numpy as np
from sklearn.metrics import roc_curve, auc as sk_auc

OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
POOL0, POOL1 = 40000, 120000           # benign pool test_idx (stream 100k..180k)
ATK = slice(120000, 170000)
N_ATK = 50000
POOL_N = POOL1 - POOL0                  # 80000
WIN = POOL_N // len(ATTACKS)            # 13333 per attack
EG, ES = 50.0, 20.0
# burst is stream [140k:160k] = test_idx [80000:100000]


def load(a):
    g = np.load(f"{OUT}/arr_gold_{a}_s60k.npy")
    ndg = np.load(f"{OUT}/arr_ndg_{a}_s60k.npy")
    nds = np.load(f"{OUT}/arr_nds_{a}_s60k.npy")
    cont = np.load(f"{OUT}/arr_cont_{a}_s60k.npy")
    return g, ndg, nds, cont


def metrics(atk_flag, ben_flag):
    tp = int(atk_flag.sum()); fn = int((~atk_flag).sum())
    fp = int(ben_flag.sum()); tn = int((~ben_flag).sum())
    tpr = tp/(tp+fn) if (tp+fn) else float('nan')
    fpr = fp/(fp+tn) if (fp+tn) else float('nan')
    prec = tp/(tp+fp) if (tp+fp) else float('nan')
    f1 = 2*tp/(2*tp+fp+fn) if (2*tp+fp+fn) else float('nan')
    acc = (tp+tn)/(tp+tn+fp+fn)
    return dict(TPR=tpr, FPR=fpr, Precision=prec, F1=f1, Accuracy=acc, n_ben=fp+tn)


def auc_on(cont, ben_idx):
    sc = np.concatenate([cont[ben_idx], cont[ATK]])
    lab = np.concatenate([np.zeros(len(ben_idx), int), np.ones(N_ATK, int)])
    fpr, tpr, _ = roc_curve(lab, sc); return sk_auc(fpr, tpr)


def main():
    rows = []
    print("\n===== INDIVIDUAL STREAMS: each attack gets its OWN disjoint benign window (committed 50/20) =====")
    W = [22, 16, 8, 8, 8, 8, 8, 8]
    def line(v):
        return " ".join(str(x).ljust(w) if i < 2 else str(x).rjust(w) for i,(x,w) in enumerate(zip(v,W)))
    print(line(["attack", "benign_win(stream)", "TPR", "FPR", "Prec", "F1", "Acc", "AUC"]))
    for k, a in enumerate(ATTACKS):
        g, ndg, nds, cont = load(a)
        s = POOL0 + k*WIN
        e = POOL0 + (k+1)*WIN if k < len(ATTACKS)-1 else POOL1
        ben_idx = np.arange(s, e)
        ben_flag = (ndg[ben_idx] > EG) | (nds[ben_idx] > ES)
        atk_flag = (ndg[ATK] > EG) | (nds[ATK] > ES)
        m = metrics(atk_flag, ben_flag)
        A = auc_on(cont, ben_idx)
        rows.append(dict(attack=a, mode="contiguous", win_lo=60000+s, win_hi=60000+e, AUC=A, **m))
        print(line([a, f"[{60000+s//1000*1000//1000}k:{(60000+e)//1000}k]",
                    f"{m['TPR']:.4f}", f"{m['FPR']:.4f}", f"{m['Precision']:.4f}",
                    f"{m['F1']:.4f}", f"{m['Accuracy']:.4f}", f"{A:.4f}"]))

    print("\n===== CONTROL: each attack's benign = RANDOM 13333-sample across whole pool (seed per attack) =====")
    print(line(["attack", "benign(random)", "TPR", "FPR", "Prec", "F1", "Acc", "AUC"]))
    for k, a in enumerate(ATTACKS):
        g, ndg, nds, cont = load(a)
        rng = np.random.default_rng(1000 + k)
        ben_idx = np.sort(rng.choice(np.arange(POOL0, POOL1), size=WIN, replace=False))
        ben_flag = (ndg[ben_idx] > EG) | (nds[ben_idx] > ES)
        atk_flag = (ndg[ATK] > EG) | (nds[ATK] > ES)
        m = metrics(atk_flag, ben_flag)
        A = auc_on(cont, ben_idx)
        rows.append(dict(attack=a, mode="random", win_lo=-1, win_hi=-1, AUC=A, **m))
        print(line([a, "rand-13333", f"{m['TPR']:.4f}", f"{m['FPR']:.4f}", f"{m['Precision']:.4f}",
                    f"{m['F1']:.4f}", f"{m['Accuracy']:.4f}", f"{A:.4f}"]))

    with open(f"{OUT}/ciciot2023_individual_streams_metrics.csv", "w", newline="") as f:
        fields = ["attack","mode","win_lo","win_hi","TPR","FPR","Precision","F1","Accuracy","AUC","n_ben"]
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows:
            w.writerow({k:(f"{r[k]:.6f}" if isinstance(r.get(k),float) else r.get(k,"")) for k in fields})
    print(f"\nWrote {OUT}/ciciot2023_individual_streams_metrics.csv")


if __name__ == "__main__":
    main()
