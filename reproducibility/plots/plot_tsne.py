#!/usr/bin/env python3
"""Entrypoint for CICIoT2023 t-SNE (delegates to results/CICIoT2023/figs/plot_tsne.py).

Outputs stay under results/CICIoT2023/figs/. Requires committed feature matrices
under results/CICIoT2023/baselines/features/.

  MPLBACKEND=Agg python reproducibility/plots/plot_tsne.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TARGET = REPO / "results" / "CICIoT2023" / "figs" / "plot_tsne.py"
os.execv(sys.executable, [sys.executable, str(TARGET), *sys.argv[1:]])
