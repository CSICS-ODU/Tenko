#!/usr/bin/env python3
"""Re-pick the Tenko operating point on CICIoT2023 (SINGLE-tanh, benignLimit=60000).

PURE ANALYTICAL RECOMPUTE from cached score arrays. No pipeline re-run, no stream
rebuild. We calibrate benign-FPR-targeted operating points on the cached scores.

Operating points (per stream, per detector):
  Tenko:
    committed   -- flag if (nd_g > 50) OR (nd_s > 20)                [baseline row]
    cont@2%     -- single thr on arr_cont: thr = quantile(cont[ben], 1-0.02)
    cont@5%     -- single thr on arr_cont: thr = quantile(cont[ben], 1-0.05)
    orrule@2%   -- OR-rule (eta_g,eta_s) jointly calibrated to benign OR-rate ~= 2%
    orrule@5%   -- OR-rule (eta_g,eta_s) jointly calibrated to benign OR-rate ~= 5%
  Kitsune:
    kitsune_medmad -- benign Median+MAD: thr = median + 3*1.4826*MAD  [reference row]
    kitsune@2%     -- thr = quantile(kit[ben], 1-0.02)
    kitsune@5%     -- thr = quantile(kit[ben], 1-0.05)

CALIBRATION CAVEAT: benign FPR is calibrated in-sample on the test benign region
(no dedicated held-out benign-calibration array exists in the cache). Thresholds are
picked from benign quantiles and then applied to the same benign region for FPR and
to the attack region for TPR. This is the standard benign-only calibration used
across this repo; see memo for discussion.
"""
import json
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

ROOT = "/Users/sbhola/Desktop/Tenko/results/CICIoT2023"
MIX = f"{ROOT}/mixed"
IND = f"{ROOT}/indep"

ATTACKS = ["DoS-SYN_Flood", "DDoS-UDP_Flood", "Recon-OSScan",
           "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]
N_BEN = 60000          # benign packets in every stream
BLK = 50000            # attack block size (combined) / attack size (indep)
TARGETS = [0.02, 0.05]

# ------------------------------------------------------------------
# metric helpers
# ------------------------------------------------------------------

def confusion(pred, y):
    pred = pred.astype(bool)
    y = y.astype(bool)
    TP = int(np.sum(pred & y))
    FP = int(np.sum(pred & ~y))
    FN = int(np.sum(~pred & y))
    TN = int(np.sum(~pred & ~y))
    return TP, FP, FN, TN


def rates(TP, FP, FN, TN):
    P = TP + FN
    N = FP + TN
    tpr = TP / P if P else float("nan")
    fpr = FP / N if N else float("nan")
    prec = TP / (TP + FP) if (TP + FP) else float("nan")
    f1 = 2 * TP / (2 * TP + FP + FN) if (2 * TP + FP + FN) else float("nan")
    acc = (TP + TN) / (TP + FP + FN + TN)
    return tpr, fpr, prec, f1, acc


def auc_roc(neg, pos):
    y = np.concatenate([np.zeros(len(neg), int), np.ones(len(pos), int)])
    s = np.concatenate([neg, pos])
    return roc_auc_score(y, s)


def auc_pr_at_prevalence(neg, pos, pi):
    """Analytic average-precision at target attack prevalence pi (matches
    prevalence_sweep_experiment.md)."""
    yy = np.concatenate([np.zeros(len(neg), int), np.ones(len(pos), int)])
    ss = np.concatenate([neg, pos])
    fpr, tpr, _ = roc_curve(yy, ss)
    denom = pi * tpr + (1 - pi) * fpr
    with np.errstate(divide="ignore", invalid="ignore"):
        prec = np.where(denom > 0, pi * tpr / denom, 1.0)
    return float(np.sum(np.diff(tpr) * prec[1:]))


def prev_adjusted_acc(tpr, fpr, pi, n_neg=N_BEN):
    """Accuracy holding within-class TPR/FPR fixed, reweighting positives to pi."""
    P = round(n_neg * pi / (1 - pi))
    TP = tpr * P
    FN = P - TP
    FP = fpr * n_neg
    TN = n_neg - FP
    return (TP + TN) / (TP + TN + FP + FN)


# ------------------------------------------------------------------
# OR-rule joint benign calibration
# ------------------------------------------------------------------

def calibrate_orrule(ndg_ben, nds_ben, target, iters=60):
    """Pick per-signal tail probability p so that the benign OR-flag rate
    (nd_g > eta_g) OR (nd_s > eta_s), with eta_* = quantile(., 1-p), is ~= target.

    Because a union of two tail events is larger than a single tail, we start from
    p = target and shrink p (bisection) until the benign OR-rate matches target.
    OR-rate is monotone increasing in p, so bisection is exact."""
    lo, hi = 0.0, target  # p in [0, target]; p=target overshoots, p=0 -> rate 0

    def or_rate(p):
        if p <= 0:
            return 0.0
        eg = np.quantile(ndg_ben, 1 - p)
        es = np.quantile(nds_ben, 1 - p)
        return float(np.mean((ndg_ben > eg) | (nds_ben > es))), eg, es

    best = None
    for _ in range(iters):
        mid = 0.5 * (lo + hi)
        r, eg, es = or_rate(mid)
        best = (mid, r, eg, es)
        if r < target:
            lo = mid
        else:
            hi = mid
    p, r, eg, es = best
    return eg, es, r, p


# ------------------------------------------------------------------
# per-stream evaluation
# ------------------------------------------------------------------

def eval_stream(stream, gold, ndg, nds, cont, kit, per_attack=False):
    """Return list of metric-rows (dicts) for every operating point on one stream."""
    ben = slice(0, N_BEN)
    atk = slice(N_BEN, len(gold))
    y = gold
    n_pos = len(gold) - N_BEN
    pi_native = n_pos / len(gold)

    cont_neg, cont_pos = cont[ben], cont[atk]
    kit_neg, kit_pos = kit[ben], kit[atk]

    auc_roc_tenko = auc_roc(cont_neg, cont_pos)
    auc_roc_kit = auc_roc(kit_neg, kit_pos)
    auc_pr_tenko = auc_pr_at_prevalence(cont_neg, cont_pos, pi_native)
    auc_pr_kit = auc_pr_at_prevalence(kit_neg, kit_pos, pi_native)

    rows = []

    def per_attack_tpr(pred):
        if not per_attack:
            return {}
        d = {}
        ap = pred[atk]
        for i, a in enumerate(ATTACKS):
            d[a] = float(ap[i * BLK:(i + 1) * BLK].mean())
        return d

    def add(detector, op, target_fpr, pred, auc_r, auc_p, extra=None):
        TP, FP, FN, TN = confusion(pred, y)
        tpr, fpr, prec, f1, acc = rates(TP, FP, FN, TN)
        row = dict(stream=stream, detector=detector, operating_point=op,
                   target_fpr=target_fpr, TPR=tpr, FPR=fpr, Precision=prec,
                   microF1=f1, Accuracy=acc, AUC_ROC=auc_r, AUC_PR=auc_p,
                   TP=TP, FP=FP, FN=FN, TN=TN,
                   per_attack=per_attack_tpr(pred))
        if extra:
            row.update(extra)
        rows.append(row)
        return row

    # ---- Tenko committed eta(50,20) ----
    pred = (ndg > 50) | (nds > 20)
    add("Tenko", "committed", "", pred, auc_roc_tenko, auc_pr_tenko)

    # ---- Tenko single-threshold on cont ----
    for tgt in TARGETS:
        thr = float(np.quantile(cont_neg, 1 - tgt))
        pred = cont > thr
        add("Tenko", f"cont@{int(tgt*100)}%", tgt, pred, auc_roc_tenko, auc_pr_tenko,
            extra=dict(thr_cont=thr))

    # ---- Tenko OR-rule recalibrated ----
    for tgt in TARGETS:
        eg, es, ach, p = calibrate_orrule(ndg[ben], nds[ben], tgt)
        pred = (ndg > eg) | (nds > es)
        add("Tenko", f"orrule@{int(tgt*100)}%", tgt, pred, auc_roc_tenko, auc_pr_tenko,
            extra=dict(eta_g=eg, eta_s=es, benign_orrate=ach, per_signal_p=p))

    # ---- Kitsune Median+MAD ----
    med = float(np.median(kit_neg))
    mad = float(np.median(np.abs(kit_neg - med)))
    kthr = med + 3 * 1.4826 * mad
    pred = kit > kthr
    add("Kitsune", "kitsune_medmad", "", pred, auc_roc_kit, auc_pr_kit,
        extra=dict(kit_med=med, kit_mad=mad, kit_thr=kthr))

    # ---- Kitsune calibrated ----
    for tgt in TARGETS:
        thr = float(np.quantile(kit_neg, 1 - tgt))
        pred = kit > thr
        add("Kitsune", f"kitsune@{int(tgt*100)}%", tgt, pred, auc_roc_kit, auc_pr_kit,
            extra=dict(kit_thr=thr))

    return rows, pi_native


# ------------------------------------------------------------------
# COMBINED stream
# ------------------------------------------------------------------

def load_mix():
    return (np.load(f"{MIX}/arr_gold_mixed.npy"),
            np.load(f"{MIX}/arr_ndg_mixed.npy"),
            np.load(f"{MIX}/arr_nds_mixed.npy"),
            np.load(f"{MIX}/arr_cont_mixed.npy"),
            np.load(f"{MIX}/kitsune_testscores_mixed.npy"))


def load_indep(a):
    return (np.load(f"{IND}/arr_gold_{a}_indep.npy"),
            np.load(f"{IND}/arr_ndg_{a}_indep.npy"),
            np.load(f"{IND}/arr_nds_{a}_indep.npy"),
            np.load(f"{IND}/arr_cont_{a}_indep.npy"),
            np.load(f"{IND}/arr_kitsune_{a}_indep.npy"))


def main():
    all_rows = []

    # -------- combined --------
    g, ndg, nds, cont, kit = load_mix()
    assert len(g) == 360000
    combined_rows, pi_c = eval_stream("combined", g, ndg, nds, cont, kit, per_attack=True)
    # prevalence-adjusted accuracy at 30% and 50%
    for r in combined_rows:
        r["Accuracy@30"] = prev_adjusted_acc(r["TPR"], r["FPR"], 0.30)
        r["Accuracy@50"] = prev_adjusted_acc(r["TPR"], r["FPR"], 0.50)
    all_rows += combined_rows

    # -------- individual --------
    indep_rows_by_attack = {}
    for a in ATTACKS:
        gi, ndgi, ndsi, conti, kiti = load_indep(a)
        assert len(gi) == 110000
        rws, _ = eval_stream(a, gi, ndgi, ndsi, conti, kiti, per_attack=False)
        for r in rws:
            r["Accuracy@30"] = ""
            r["Accuracy@50"] = ""
        indep_rows_by_attack[a] = rws
        all_rows += rws

    # ---------------- CSV ----------------
    cols = ["stream", "detector", "operating_point", "target_fpr", "TPR", "FPR",
            "Precision", "microF1", "Accuracy", "AUC_ROC", "AUC_PR",
            "Accuracy@30", "Accuracy@50"]
    csv_path = f"{MIX}/ciciot2023_calibrated_operating_point_metrics.csv"

    def fmt(v):
        if isinstance(v, float):
            return f"{v:.6f}"
        return str(v)

    with open(csv_path, "w") as f:
        f.write(",".join(cols) + "\n")
        for r in all_rows:
            f.write(",".join(fmt(r.get(c, "")) for c in cols) + "\n")
    print(f"Wrote {csv_path}  ({len(all_rows)} rows)")

    # ---------------- JSON dump ----------------
    dump = dict(combined=combined_rows, indep=indep_rows_by_attack, pi_combined=pi_c)
    with open(f"{MIX}/_calibrated_operating_point_dump.json", "w") as f:
        json.dump(dump, f, indent=2, default=lambda o: (float(o) if isinstance(o, (np.floating, np.integer)) else o))
    print(f"Wrote {MIX}/_calibrated_operating_point_dump.json")

    # ---------------- Sanity checks ----------------
    def find(rows, det, op):
        return next(r for r in rows if r["detector"] == det and r["operating_point"] == op)

    print("\n" + "=" * 70)
    print("SANITY CHECKS (combined stream)")
    print("=" * 70)
    committed = find(combined_rows, "Tenko", "committed")
    kmm = find(combined_rows, "Kitsune", "kitsune_medmad")
    c5 = find(combined_rows, "Tenko", "cont@5%")
    c2 = find(combined_rows, "Tenko", "cont@2%")
    print(f"committed eta(50,20): FPR={committed['FPR']:.4f} (exp 0.0069), "
          f"TPR={committed['TPR']:.4f} (exp 0.879), ACC(83%)={committed['Accuracy']:.4f} (exp 0.898)")
    print(f"Kitsune medmad     : FPR={kmm['FPR']:.4f} (exp 0.197), "
          f"TPR={kmm['TPR']:.4f} (exp 0.964), ACC(83%)={kmm['Accuracy']:.4f} (exp 0.937)")
    print(f"cont@5%            : TPR={c5['TPR']:.4f} (exp 0.965), "
          f"ACC(83%)={c5['Accuracy']:.4f} (exp 0.963), ACC@30={c5['Accuracy@30']:.4f} (exp 0.955)")
    print(f"cont@2%            : TPR={c2['TPR']:.4f} (exp 0.922), "
          f"ACC(83%)={c2['Accuracy']:.4f} (exp 0.931), ACC@30={c2['Accuracy@30']:.4f} (exp 0.963)")

    print("\nCombined operating-point summary:")
    hdr = f"{'detector':8s} {'op':16s} {'TPR':>7s} {'FPR':>7s} {'Prec':>7s} {'F1':>7s} {'Acc':>7s} {'Acc@30':>7s} {'Acc@50':>7s} {'AUCROC':>7s} {'AUCPR':>7s}"
    print(hdr)
    for r in combined_rows:
        print(f"{r['detector']:8s} {r['operating_point']:16s} {r['TPR']:7.4f} {r['FPR']:7.4f} "
              f"{r['Precision']:7.4f} {r['microF1']:7.4f} {r['Accuracy']:7.4f} "
              f"{r['Accuracy@30']:7.4f} {r['Accuracy@50']:7.4f} {r['AUC_ROC']:7.4f} {r['AUC_PR']:7.4f}")

    # OR-rule achieved benign FPR
    print("\nOR-rule joint calibration (combined benign region):")
    for op in ("orrule@2%", "orrule@5%"):
        r = find(combined_rows, "Tenko", op)
        print(f"  {op}: eta_g={r['eta_g']:.4f} eta_s={r['eta_s']:.4f} "
              f"benign OR-rate(achieved FPR)={r['benign_orrate']:.4f} per_signal_p={r['per_signal_p']:.4f}")

    print("\nPer-attack TPR on combined stream (prevalence-invariant):")
    ops = [("Tenko", "committed"), ("Tenko", "cont@2%"), ("Tenko", "cont@5%"),
           ("Tenko", "orrule@2%"), ("Tenko", "orrule@5%"),
           ("Kitsune", "kitsune_medmad"), ("Kitsune", "kitsune@2%"), ("Kitsune", "kitsune@5%")]
    head = f"{'attack':24s}" + "".join(f"{op[1][:10]:>11s}" for op in ops)
    print(head)
    for a in ATTACKS:
        line = f"{a:24s}"
        for det, op in ops:
            r = find(combined_rows, det, op)
            line += f"{r['per_attack'][a]:11.4f}"
        print(line)

    # ---------------- individual streams summary ----------------
    print("\n" + "=" * 70)
    print("INDIVIDUAL STREAMS (means across 6 attacks)")
    print("=" * 70)
    op_order = ["committed", "cont@2%", "cont@5%", "orrule@2%", "orrule@5%",
                "kitsune_medmad", "kitsune@2%", "kitsune@5%"]
    print(f"{'op':16s} {'TPR':>7s} {'FPR':>7s} {'Prec':>7s} {'F1':>7s} {'Acc':>7s} {'AUCROC':>7s} {'AUCPR':>7s}")
    for op in op_order:
        vals = {k: [] for k in ("TPR", "FPR", "Precision", "microF1", "Accuracy", "AUC_ROC", "AUC_PR")}
        for a in ATTACKS:
            r = find(indep_rows_by_attack[a], "Kitsune" if op.startswith("kitsune") else "Tenko", op)
            for k in vals:
                vals[k].append(r[k])
        m = {k: np.nanmean(v) for k, v in vals.items()}
        print(f"{op:16s} {m['TPR']:7.4f} {m['FPR']:7.4f} {m['Precision']:7.4f} "
              f"{m['microF1']:7.4f} {m['Accuracy']:7.4f} {m['AUC_ROC']:7.4f} {m['AUC_PR']:7.4f}")

    return dump


if __name__ == "__main__":
    main()
