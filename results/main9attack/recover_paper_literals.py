#!/usr/bin/env python3
"""Transcribe the hard-coded nine-attack literals into a committed CSV.

Source of truth: ``resultsNew.py`` on branch ``Daksh-Mateen`` (lines ~142-190),
the only place the manuscript's per-attack TPR/FPR/FNR/Precision matrix survived.
Read read-only with:  ``git show Daksh-Mateen:resultsNew.py``.

This script hard-copies those arrays verbatim (no recomputation) and writes a
tidy long-format CSV so the paper table is version-controlled and diffable against
the rebuilt metrics from ``run_kitsune_9attack.py``. AUC/EER were never stored in
the literals, so they are absent here (the rebuilt CSV supplies them).
"""

from pathlib import Path
import numpy as np
import pandas as pd

ATTACKS = ["Mirai", "Fuzzing", "SSDP Flood", "Wiretap", "SSL Reneg.",
           "Video Injection", "ARP MITM", "OS Scan", "Syn DOS"]

METHODS = ["Highest (max+std)", "Medium (mean)", "Lowest (min)", "Max",
           "3-sigma", "Med+1.5xMAD", "Logarithmic"]

TPR = np.array([
    [0.881, 1.000, 0.000, 1.000, 0.848, 0.000, 1.000, 1.000, 0.001],
    [0.910, 1.000, 1.000, 1.000, 0.996, 0.000, 1.000, 1.000, 1.000],
    [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 1.000],
    [0.881, 1.000, 0.000, 1.000, 0.848, 0.000, 1.000, 1.000, 0.001],
    [0.883, 1.000, 0.000, 1.000, 0.849, 0.000, 1.000, 1.000, 0.001],
    [0.910, 1.000, 1.000, 1.000, 0.994, 1.000, 1.000, 1.000, 1.000],
    [0.883, 1.000, 1.000, 0.815, 0.849, 0.095, 0.734, 1.000, 0.001],
])
FPR = np.array([
    [0.000, 0.749, 0.000, 0.813, 0.019, 0.000, 0.851, 0.218, 0.000],
    [0.251, 0.985, 0.773, 0.973, 0.983, 0.000, 0.981, 0.983, 0.974],
    [1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 1.000, 1.000],
    [0.000, 0.775, 0.000, 0.829, 0.019, 0.000, 0.922, 0.272, 0.000],
    [0.006, 0.944, 0.001, 0.891, 0.020, 0.000, 0.942, 0.862, 0.001],
    [0.246, 0.976, 0.983, 0.942, 0.977, 0.981, 0.969, 0.957, 0.978],
    [0.010, 0.817, 0.307, 0.616, 0.020, 0.395, 0.435, 0.488, 0.012],
])
FNR = np.array([
    [0.119, 0.000, 1.000, 0.000, 0.152, 1.000, 0.000, 0.000, 0.999],
    [0.090, 0.000, 0.000, 0.000, 0.004, 1.000, 0.000, 0.000, 0.000],
    [0.000, 0.000, 0.000, 0.000, 0.000, 0.000, 0.000, 0.000, 0.000],
    [0.119, 0.000, 1.000, 0.000, 0.152, 1.000, 0.000, 0.000, 0.999],
    [0.117, 0.000, 1.000, 0.000, 0.151, 1.000, 0.000, 0.000, 0.999],
    [0.090, 0.000, 0.000, 0.000, 0.006, 0.000, 0.000, 0.000, 0.000],
    [0.117, 0.000, 0.000, 0.185, 0.151, 0.905, 0.266, 0.000, 0.999],
])
PRECISION = np.array([
    [1.000, 0.248, 0.219, 0.466, 0.668, 0.000, 0.508, 0.161, 0.013],
    [0.972, 0.200, 0.419, 0.422, 0.044, 0.008, 0.472, 0.041, 0.003],
    [0.906, 0.198, 0.358, 0.415, 0.043, 0.042, 0.468, 0.040, 0.003],
    [1.000, 0.241, 0.217, 0.461, 0.667, 0.000, 0.488, 0.133, 0.012],
    [0.999, 0.207, 0.053, 0.444, 0.658, 0.004, 0.482, 0.046, 0.002],
    [0.973, 0.202, 0.362, 0.430, 0.044, 0.043, 0.475, 0.042, 0.003],
    [0.999, 0.232, 0.645, 0.484, 0.657, 0.011, 0.597, 0.079, 0.000],
])


def main() -> None:
    rows = []
    for mi, method in enumerate(METHODS):
        for ai, attack in enumerate(ATTACKS):
            rows.append({
                "attack": attack,
                "threshold_method": method,
                "tpr": TPR[mi, ai],
                "fpr": FPR[mi, ai],
                "fnr": FNR[mi, ai],
                "precision": PRECISION[mi, ai],
                "source": "Daksh-Mateen:resultsNew.py",
            })
    out = Path(__file__).resolve().parent / "paper_literals_resultsNew.csv"
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"Wrote {len(rows)} literal rows -> {out}")


if __name__ == "__main__":
    main()
