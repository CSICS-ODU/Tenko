# cython: language_level=3
"""Lock-free scalar updates for scoreClass-style node scoring (single-threaded)."""
cimport cython

@cython.boundscheck(False)
@cython.wraparound(False)
def benign_step(double numerator, double denominator, double history_epoch):
    """Mirror scoreClass.update_benign core (no timestamp side)."""
    denominator += 1.0
    if denominator > history_epoch:
        denominator *= 0.8
        numerator *= 0.8
    return numerator, denominator

@cython.boundscheck(False)
@cython.wraparound(False)
def anomaly_step(double numerator, double denominator, double n_val, double history_epoch):
    """Mirror update_anamoly: add n to numerator then benign decay."""
    numerator += n_val
    denominator += 1.0
    if denominator > history_epoch:
        denominator *= 0.8
        numerator *= 0.8
    return numerator, denominator

@cython.boundscheck(False)
@cython.wraparound(False)
def decay_fraction_step(double numerator, double denominator, double n):
    """Return (new_num, new_den, is_zero)."""
    cdef double k
    if numerator == 0:
        return 0.0, denominator, 1
    k = 1.0 - (n / numerator)
    numerator *= k
    denominator *= k
    if denominator < 1.0:
        numerator = 0.0
        denominator = 1.0
    elif numerator < 0.0:
        numerator = 0.0
    return numerator, denominator, int(numerator == 0.0)
