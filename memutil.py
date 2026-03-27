"""
Utility for measuring the actual memory footprint of Python objects,
with special handling for numpy arrays and PyTorch tensors/modules.
"""
import sys

def deep_sizeof(obj, _seen=None):
    """Recursively measure total memory (bytes) of an object graph.

    Handles numpy arrays (.nbytes), PyTorch tensors (.numel * element_size),
    dicts, lists, tuples, and arbitrary objects via __dict__.
    """
    if _seen is None:
        _seen = set()
    obj_id = id(obj)
    if obj_id in _seen:
        return 0
    _seen.add(obj_id)

    try:
        import numpy as np
        if isinstance(obj, np.ndarray):
            return obj.nbytes + 128
    except ImportError:
        pass

    try:
        import torch
        if isinstance(obj, torch.Tensor):
            return obj.numel() * obj.element_size() + 128
        if isinstance(obj, torch.nn.Module):
            size = sys.getsizeof(obj)
            for p in obj.parameters():
                size += p.numel() * p.element_size()
                if p.grad is not None:
                    size += p.grad.numel() * p.grad.element_size()
            for b in obj.buffers():
                size += b.numel() * b.element_size()
            return size
    except ImportError:
        pass

    size = sys.getsizeof(obj)

    if isinstance(obj, dict):
        size += sum(deep_sizeof(k, _seen) + deep_sizeof(v, _seen)
                    for k, v in obj.items())
    elif isinstance(obj, (list, tuple, set, frozenset)):
        size += sum(deep_sizeof(i, _seen) for i in obj)
    elif hasattr(obj, '__dict__') and not isinstance(obj, type):
        size += deep_sizeof(vars(obj), _seen)

    return size


def aggregate_deep_sizeof(*roots):
    """Sum sizes of multiple object graphs with shared reference deduplication.

    Use when measuring total logical footprint (e.g. several nn.Modules + numpy
    buffers + threshold lists) so aliased objects are counted once.
    """
    _seen = set()
    return sum(deep_sizeof(obj, _seen) for obj in roots)
