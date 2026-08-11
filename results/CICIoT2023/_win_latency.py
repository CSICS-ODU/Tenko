#!/usr/bin/env python3
"""Detection-latency / early-warning check (H3, secondary).

Per attacker DEVICE: using each detector's benign-calibrated threshold, how many
of that device's own attack-region packets elapse before its FIRST alarm?
Lower = earlier warning. Thresholds are benign-only, in-sample illustrations.
  Kitsune thr = median + 3*1.4826*MAD on tanh(RMSE) calib region [55001:150000].
  Tenko   thr = 99th percentile of cont over benign_test (label-0) region.
"""
import csv, os
import numpy as np
from collections import Counter

PILOT="/Users/sbhola/Desktop/cic/pilot"; OUT="."
ATT=["DDoS-UDP_Flood","DoS-SYN_Flood","Recon-OSScan","MITM-ArpSpoofing","Mirai-greeth_flood","DictionaryBruteForce"]
NL,NT,NA=150000,30000,50000
TRAIN_START=55001

def rs(t):
    o=[]
    with open(t,encoding="utf8") as f:
        r=csv.reader(f,delimiter="\t");next(r)
        for row in r:
            s=""
            if len(row)>5 and row[4] and row[5]:s=row[4]
            elif len(row)>18 and row[17] and row[18]:s=row[17]
            o.append(s)
    return o
def ai(ip):return ip.startswith("192.168.")

print(f"{'attack':22s} | {'KIT med pkts-to-detect':>22s} | {'TEN med pkts-to-detect':>22s} | {'KIT devsDetected':>16s} {'TEN devsDetected':>16s}")
for a in ATT:
    full=rs(f"{PILOT}/stream_{a}.pcap.tsv"); src_test=full[NL:]
    ca=Counter(full[NL+NT:]); ba=Counter(full[:NL])+Counter(full[NL:NL+NT])
    atk=set(ip for ip,c in ca.items() if ip and ai(ip) and c>=50 and c/(c+ba.get(ip,0))>=0.99)
    rmse=np.load(f"rmse_raw_{a}.npy"); ktanh=np.tanh(rmse)
    cal=ktanh[TRAIN_START:NL]; med=np.median(cal); mad=np.median(np.abs(cal-med)); kthr=med+3.0*1.4826*mad
    cont=np.load(f"arr_cont_{a}_double.npy"); kit=np.load(f"arr_kitsune_{a}.npy")
    tthr=np.quantile(cont[:NT],0.99)  # benign_test cont 99th pctile
    # per attacker device: packets-to-first-alarm within attack region (its own packet order)
    dev_idx={}
    for i in range(NT,len(src_test)):  # attack region within test arrays
        s=src_test[i]
        if s in atk: dev_idx.setdefault(s,[]).append(i)
    k_lat=[]; t_lat=[]
    for s,ix in dev_idx.items():
        ix=np.array(ix)
        kk=np.where(kit[ix]>kthr)[0]; tt=np.where(cont[ix]>tthr)[0]
        k_lat.append(int(kk[0])+1 if len(kk) else np.nan)
        t_lat.append(int(tt[0])+1 if len(tt) else np.nan)
    k_lat=np.array(k_lat,float); t_lat=np.array(t_lat,float)
    kd=np.sum(~np.isnan(k_lat)); td=np.sum(~np.isnan(t_lat)); nd=len(dev_idx)
    print(f"{a:22s} | {np.nanmedian(k_lat):22.1f} | {np.nanmedian(t_lat):22.1f} | {f'{kd}/{nd}':>16s} {f'{td}/{nd}':>16s}")
