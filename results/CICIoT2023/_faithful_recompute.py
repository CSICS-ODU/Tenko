#!/usr/bin/env python3
"""Faithful per-device recompute, aligned to the PAPER's tolerance-layer semantics.

Paper (manuscript_drafts.md A.3, verbatim from Overleaf):
  tau_n     = eta_node   * max_t || z_{n,t} - mu_n ||_2      (per-node envelope)
  tau_global= eta_global * max benign global deviations       (global envelope)
  node score S(n) in [0,1] is a running trust estimate (Layer II/III).
A node is flagged when its current windowed pattern deviation ||z-mu|| exceeds
tau  <=>  normalized distance nd = ||z-mu|| / (max benign dev) > eta.
There is NO patience / consecutive-N counter: it is a static envelope, flag on
first breach. Hence the faithful threshold-free per-device statistic is the
MAX over the node's packets of nd  (== 'did this node ever leave the benign
envelope', swept over eta by the ROC).

Cached arrays (per test packet, stream idx [150000:230000]):
  arr_ndg  = nd_g   per-node  normalized pattern distance   (paper tau_n statistic)
  arr_nds  = nd_s   global    normalized pattern distance   (paper tau_global statistic)
  arr_cont = 0.5*nd_g + 0.5*nd_s  = Tenko's FUSED tolerance statistic (what run_ciciot2023
             reports as Tenko's official AUC score; results.py:956, :189/204)
  arr_node = S(n)   raw running node score                  (Layer II/III trust estimate)
  arr_kitsune = tanh(RMSE) per packet                       (Kitsune, no node concept)

Kitsune has no node state, so lifting it to device level REQUIRES a reduction
(max, disclosed). We apply the SAME 'ever-fired = max of decision statistic'
rule to both detectors -> symmetric and fair.
"""
import csv, os
import numpy as np
from collections import Counter
from sklearn.metrics import roc_auc_score, roc_curve

PILOT="/Users/sbhola/Desktop/cic/pilot"; OUT="."
ATT=["DDoS-UDP_Flood","DoS-SYN_Flood","Recon-OSScan","MITM-ArpSpoofing","Mirai-greeth_flood","DictionaryBruteForce"]
NL,NT=150000,30000; TRAIN_START=55001
ETA_G5,ETA_N5=35.833533385528064,2.206741470895003   # recalibrated @5% benign FPR
ETA_G1,ETA_N1=40.698774879819176,2.85443407451282     # recalibrated @1%

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
def A(y,s):
    return float(roc_auc_score(y,s)) if len(set(y))>1 else float("nan")
def eer(y,s):
    if len(set(y))<2:return float("nan")
    fpr,tpr,_=roc_curve(y,s);fnr=1-tpr;i=int(np.nanargmin(np.abs(fpr-fnr)));return float((fpr[i]+fnr[i])/2)

hdr=(f"{'attack':22s}|{'KITmax':>7s}|{'TENcont_max(FAITHFUL)':>21s}|{'TENndg_max':>10s}|"
     f"{'TENnds_max':>10s}|{'TENnode_max':>11s}|{'KITmean':>7s}|{'TENcont_mean':>12s}")
print(hdr); print("-"*len(hdr))
res={}
for a in ATT:
    full=rs(f"{PILOT}/stream_{a}.pcap.tsv"); src=full[NL:]
    ca=Counter(full[NL+NT:]); ba=Counter(full[:NL])+Counter(full[NL:NL+NT])
    atk=set(ip for ip,c in ca.items() if ip and ai(ip) and c>=50 and c/(c+ba.get(ip,0))>=0.99)
    kit=np.load(f"arr_kitsune_{a}.npy"); cont=np.load(f"arr_cont_{a}_double.npy")
    ndg=np.load(f"arr_ndg_{a}_double.npy"); nds=np.load(f"arr_nds_{a}_double.npy"); node=np.load(f"arr_node_{a}_double.npy")
    d={}
    for i,s in enumerate(src): d.setdefault(s,[]).append(i)
    ys=[];K=[];Km=[];Cx=[];Cm=[];G=[];S=[];No=[]
    Gmax=[];Smax=[]  # per-device max nd_g / nd_s for native operating point
    for s,ix in d.items():
        if s=="" or len(ix)<5: continue
        ix=np.array(ix); ys.append(1 if s in atk else 0)
        K.append(kit[ix].max()); Km.append(kit[ix].mean())
        Cx.append(cont[ix].max()); Cm.append(cont[ix].mean())
        G.append(ndg[ix].max()); S.append(nds[ix].max()); No.append(node[ix].max())
        Gmax.append(ndg[ix].max()); Smax.append(nds[ix].max())
    ys=np.array(ys)
    res[a]=dict(ys=ys,K=np.array(K),Cx=np.array(Cx),Gmax=np.array(Gmax),Smax=np.array(Smax),
                kit=kit,rmse_calib=None)
    print(f"{a:22s}|{A(ys,K):7.4f}|{A(ys,Cx):21.4f}|{A(ys,G):10.4f}|{A(ys,S):10.4f}|"
          f"{A(ys,No):11.4f}|{A(ys,Km):7.4f}|{A(ys,Cm):12.4f}")

# means
def mean_over(col_fn):
    return np.nanmean([col_fn(a) for a in ATT])
print("-"*len(hdr))
mk =np.nanmean([A(res[a]['ys'],res[a]['K'])  for a in ATT])
mc =np.nanmean([A(res[a]['ys'],res[a]['Cx']) for a in ATT])
print(f"{'MEAN':22s}|{mk:7.4f}|{mc:21.4f}|  (faithful fused Tenko vs Kitsune, max reduction)")

# -------- Native 'ever-flagged at eta' operating point (device-level TPR/FPR) --------
print("\nNATIVE operating point: device flagged if it EVER breaches the tolerance envelope")
print("Tenko: max nd_g > eta_global  OR  max nd_s > eta_node   (matches pred_weighted 0.5/0.5, T=0.5)")
print("Kitsune: max tanh(RMSE) > benign Median+3*1.4826*MAD threshold")
print(f"{'attack':22s}|{'eta':>5s}|{'TEN TPR':>7s} {'TEN FPR':>7s}|{'KIT TPR':>7s} {'KIT FPR':>7s}")
for a in ATT:
    full=rs(f"{PILOT}/stream_{a}.pcap.tsv"); src=full[NL:]
    ca=Counter(full[NL+NT:]); ba=Counter(full[:NL])+Counter(full[NL:NL+NT])
    atk=set(ip for ip,c in ca.items() if ip and ai(ip) and c>=50 and c/(c+ba.get(ip,0))>=0.99)
    ndg=np.load(f"arr_ndg_{a}_double.npy"); nds=np.load(f"arr_nds_{a}_double.npy")
    kit=np.load(f"arr_kitsune_{a}.npy"); rmse=np.load(f"rmse_raw_{a}.npy"); kt=np.tanh(rmse)
    cal=kt[TRAIN_START:NL]; med=np.median(cal); mad=np.median(np.abs(cal-med)); kthr=med+3.0*1.4826*mad
    d={}
    for i,s in enumerate(src): d.setdefault(s,[]).append(i)
    for (eg,en,tag) in [(ETA_G5,ETA_N5,"@5%"),(ETA_G1,ETA_N1,"@1%")]:
        tp=fp=tn=fn=ktp=kfp=ktn=kfn=0
        for s,ix in d.items():
            if s=="" or len(ix)<5: continue
            ix=np.array(ix); y=1 if s in atk else 0
            ten_flag = (ndg[ix].max()>eg) or (nds[ix].max()>en)
            kit_flag = (kit[ix].max()>kthr)
            if y==1:
                tp+=ten_flag; fn+=(not ten_flag); ktp+=kit_flag; kfn+=(not kit_flag)
            else:
                fp+=ten_flag; tn+=(not ten_flag); kfp+=kit_flag; ktn+=(not kit_flag)
        ttpr=tp/(tp+fn) if tp+fn else float('nan'); tfpr=fp/(fp+tn) if fp+tn else float('nan')
        ktpr=ktp/(ktp+kfn) if ktp+kfn else float('nan'); kfpr=kfp/(kfp+ktn) if kfp+ktn else float('nan')
        print(f"{a:22s}|{tag:>5s}|{ttpr:7.3f} {tfpr:7.3f}|{ktpr:7.3f} {kfpr:7.3f}")
