#!/usr/bin/env python3
"""Entrypoint for CICIoT2023 RMSE timelines from CSV.

Delegates to results/CICIoT2023/figs/plot_rmse_from_csv.py.
Outputs stay under results/CICIoT2023/figs/.

  python reproducibility/plots/plot_rmse_from_csv_ciciot.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TARGET = REPO / "results" / "CICIoT2023" / "figs" / "plot_rmse_from_csv.py"
os.execv(sys.executable, [sys.executable, str(TARGET), *sys.argv[1:]])
