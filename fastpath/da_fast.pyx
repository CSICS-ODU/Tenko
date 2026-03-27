# cython: language_level=3
# KitNET numpy dA — fast execute() path (matches KitNET/dA.py numerics).
import numpy as np
cimport numpy as cnp
cimport cython
from libc.math cimport exp, sqrt

cdef inline double sigmoid(double v) nogil:
    return 1.0 / (1.0 + exp(-v))

@cython.boundscheck(False)
@cython.wraparound(False)
def da_execute_rmse(
    cnp.ndarray[double, ndim=1] x,
    cnp.ndarray[double, ndim=1] norm_min,
    cnp.ndarray[double, ndim=1] norm_max,
    cnp.ndarray[double, ndim=2] W,
    cnp.ndarray[double, ndim=1] hbias,
    cnp.ndarray[double, ndim=1] vbias,
):
    """Return RMSE reconstruction error (same as dA.execute after grace)."""
    cdef int n_vis = <int>x.shape[0]
    cdef int n_hid = <int>W.shape[1]
    cdef double eps = 1e-16
    cdef int i, j
    cdef double s, t
    cdef double acc

    # workspace
    cdef cnp.ndarray[double, ndim=1] xn = np.empty(n_vis, dtype=np.float64)
    cdef cnp.ndarray[double, ndim=1] y = np.empty(n_hid, dtype=np.float64)
    cdef cnp.ndarray[double, ndim=1] z = np.empty(n_vis, dtype=np.float64)

    for i in range(n_vis):
        xn[i] = (x[i] - norm_min[i]) / (norm_max[i] - norm_min[i] + eps)

    # y = sigmoid(xn @ W + hbias)
    for j in range(n_hid):
        acc = hbias[j]
        for i in range(n_vis):
            acc += xn[i] * W[i, j]
        y[j] = sigmoid(acc)

    # z = sigmoid(y @ W.T + vbias)  => for each output i: sum_j W[i,j]*y[j]
    for i in range(n_vis):
        acc = vbias[i]
        for j in range(n_hid):
            acc += W[i, j] * y[j]
        z[i] = sigmoid(acc)

    # RMSE
    acc = 0.0
    for i in range(n_vis):
        t = xn[i] - z[i]
        acc += t * t
    return sqrt(acc / <double>n_vis)
