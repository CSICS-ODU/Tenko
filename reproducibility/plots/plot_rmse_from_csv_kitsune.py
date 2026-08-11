#!/usr/bin/env python3
"""Entrypoint for Kitsune-dataset (OS Scan / SSDP) RMSE timelines from CSV.

Delegates to results/main9attack/figs/plot_rmse_from_csv.py.
Outputs stay under results/main9attack/figs/.

  python reproducibility/plots/plot_rmse_from_csv_kitsune.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TARGET = REPO / "results" / "main9attack" / "figs" / "plot_rmse_from_csv.py"
os.execv(sys.executable, [sys.executable, str(TARGET), *sys.argv[1:]])
