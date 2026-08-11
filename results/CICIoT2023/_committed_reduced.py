#!/usr/bin/env python3
"""Committed eta=50/20 under the reduced split (s60k): does it fire, and FPR by window."""
import numpy as np
OUT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
EG, ES = 50.0, 20.0
CALIB=slice(0,5000); EVAL=slice(5000,64000); EXTRA=slice(64000,120000); ATK=slice(120000,170000)
print(f"{'attack':<22}{'TPR':>8}{'FPR_calib':>10}{'FPR_eval':>10}{'FPR_extra':>10}{'FPR_full':>10}")
for a in ATTACKS:
    ndg=np.load(f"{OUT}/arr_ndg_{a}_s60k.npy"); nds=np.load(f"{OUT}/arr_nds_{a}_s60k.npy")
    g=np.load(f"{OUT}/arr_gold_{a}_s60k.npy")
    def fpr(sl): return float(np.mean((ndg[sl]>EG)|(nds[sl]>ES)))
    tpr=float(np.mean((ndg[ATK]>EG)|(nds[ATK]>ES)))
    ben=(g==0)
    full=float(np.mean((ndg[ben]>EG)|(nds[ben]>ES)))
    print(f"{a:<22}{tpr:>8.4f}{fpr(CALIB):>10.4f}{fpr(EVAL):>10.4f}{fpr(EXTRA):>10.4f}{full:>10.4f}")
