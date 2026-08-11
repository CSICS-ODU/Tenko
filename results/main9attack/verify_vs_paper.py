#!/usr/bin/env python3
"""Compare the rebuilt nine-attack metrics against the paper's literals and write
a per-attack, per-method verification table (deltas).

Inputs:
  results/main9attack/kitsune_9attack_metrics.csv   (rebuilt: real data)
  results/main9attack/paper_literals_resultsNew.csv (paper literals, Daksh-Mateen:resultsNew.py)
Output:
  results/main9attack/nineattack_verification_vs_paper.csv
"""
from pathlib import Path
import pandas as pd

DIR = Path(__file__).resolve().parent

# rebuilt attack name -> paper literal attack name
ATTACK_MAP = {
    "Mirai": "Mirai",
    "OS Scan": "OS Scan",
    "SSL Renegotiation": "SSL Reneg.",
    "Fuzzing": "Fuzzing",
    "Active Wiretap": "Wiretap",
    "SYN DoS": "Syn DOS",
    "Video Injection": "Video Injection",
    "ARP MitM": "ARP MITM",
    "SSDP Flood": "SSDP Flood",
}
# rebuilt threshold_method -> paper threshold_method
METHOD_MAP = {
    "max+std": "Highest (max+std)",
    "mean": "Medium (mean)",
    "min": "Lowest (min)",
    "max": "Max",
    "mean+3sigma": "3-sigma",
    "median+1.5MAD": "Med+1.5xMAD",
}
# stable order for the 9 attacks
ATTACK_ORDER = ["Mirai", "OS Scan", "Fuzzing", "SSDP Flood", "Active Wiretap",
                "SSL Renegotiation", "Video Injection", "ARP MitM", "SYN DoS"]
METHOD_ORDER = ["max+std", "mean", "min", "max", "mean+3sigma", "median+1.5MAD"]


def main() -> None:
    reb = pd.read_csv(DIR / "kitsune_9attack_metrics.csv")
    pap = pd.read_csv(DIR / "paper_literals_resultsNew.csv")

    rows = []
    for atk in ATTACK_ORDER:
        pap_atk = ATTACK_MAP[atk]
        sub_r = reb[reb["attack"] == atk]
        if sub_r.empty:
            continue
        auc = float(sub_r["auc"].iloc[0])
        eer = float(sub_r["eer"].iloc[0])
        for m in METHOD_ORDER:
            pap_m = METHOD_MAP[m]
            r = sub_r[sub_r["threshold_method"] == m]
            p = pap[(pap["attack"] == pap_atk) & (pap["threshold_method"] == pap_m)]
            if r.empty or p.empty:
                continue
            r = r.iloc[0]; p = p.iloc[0]
            rows.append({
                "attack": atk,
                "threshold_method": m,
                "tpr_paper": round(float(p["tpr"]), 4),
                "tpr_rebuilt": round(float(r["tpr"]), 4),
                "dtpr": round(float(r["tpr"]) - float(p["tpr"]), 4),
                "fpr_paper": round(float(p["fpr"]), 4),
                "fpr_rebuilt": round(float(r["fpr"]), 4),
                "dfpr": round(float(r["fpr"]) - float(p["fpr"]), 4),
                "fnr_paper": round(float(p["fnr"]), 4),
                "fnr_rebuilt": round(float(r["fnr"]), 4),
                "dfnr": round(float(r["fnr"]) - float(p["fnr"]), 4),
                "prec_paper": round(float(p["precision"]), 4),
                "prec_rebuilt": round(float(r["precision"]), 4),
                "dprec": round(float(r["precision"]) - float(p["precision"]), 4),
                "auc_rebuilt": round(auc, 4),
                "eer_rebuilt": round(eer, 4),
            })
    out = pd.DataFrame(rows)
    out_path = DIR / "nineattack_verification_vs_paper.csv"
    out.to_csv(out_path, index=False)
    print(f"Wrote {len(out)} rows -> {out_path}")
    if not out.empty:
        print(out.to_string(index=False))
        print("\nPer-attack max |ΔTPR|, |ΔFPR|:")
        for atk in ATTACK_ORDER:
            s = out[out["attack"] == atk]
            if s.empty:
                continue
            print(f"  {atk:20s} max|dTPR|={s['dtpr'].abs().max():.3f}  "
                  f"max|dFPR|={s['dfpr'].abs().max():.3f}  "
                  f"AUC={s['auc_rebuilt'].iloc[0]:.3f} EER={s['eer_rebuilt'].iloc[0]:.3f}")


if __name__ == "__main__":
    main()
