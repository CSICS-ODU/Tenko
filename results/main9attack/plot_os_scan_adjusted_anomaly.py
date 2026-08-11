#!/usr/bin/env python3
"""Shim: forwards to reproducibility/plots/plot_os_scan_adjusted_anomaly.py."""
from __future__ import annotations

import os
import sys
from pathlib import Path

TARGET = (
    Path(__file__).resolve().parents[2]
    / "reproducibility"
    / "plots"
    / "plot_os_scan_adjusted_anomaly.py"
)
os.execv(sys.executable, [sys.executable, str(TARGET), *sys.argv[1:]])
