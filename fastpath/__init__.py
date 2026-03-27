"""Cython-accelerated helpers for KitNET / Tenko hot paths."""

try:
    from fastpath.da_fast import da_execute_rmse
    CYTHON_DA_AVAILABLE = True
except ImportError:
    da_execute_rmse = None  # type: ignore
    CYTHON_DA_AVAILABLE = False
