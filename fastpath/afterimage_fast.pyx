# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
"""
Cython port of AfterImage.py — typed cdef classes for maximum speed.

Key differences vs pure-Python AfterImage.py:
  - All numeric fields are C doubles (no Python object boxing)
  - math functions use libc.math (pow, sqrt, fabs, isnan) — no Python call overhead
  - Inner methods are cdef (C-level, not callable from Python directly)
  - Public methods delegate to cdef equivalents
  - Forward declaration of incStat_cov so incStat can reference it
"""

from libc.math cimport pow, sqrt, fabs, isnan
import numpy as np

_NAN = float('nan')
_INF = float('inf')

# ── Forward declaration so incStat can reference incStat_cov ─────────────────
cdef class incStat_cov


# ═══════════════════════════════════════════════════════════════════════════════
# incStat — exponentially-weighted online statistics for a single stream
# ═══════════════════════════════════════════════════════════════════════════════
cdef class incStat:
    cdef public str ID
    cdef public double CF1
    cdef public double CF2
    cdef public double w
    cdef public int isTypeDiff
    cdef public double Lambda
    cdef public double lastTimestamp
    cdef public double cur_mean
    cdef public double cur_var
    cdef public double cur_std
    cdef public list covs

    def __init__(self, double Lambda, str ID, double init_time=0, int isTypeDiff=0):
        self.ID = ID
        self.CF1 = 0.0
        self.CF2 = 0.0
        self.w = 1e-20
        self.isTypeDiff = isTypeDiff
        self.Lambda = Lambda
        self.lastTimestamp = init_time
        self.cur_mean = _NAN
        self.cur_var = _NAN
        self.cur_std = _NAN
        self.covs = []

    cdef void _insert(self, double v, double t):
        cdef double dif
        cdef incStat_cov cov
        if self.isTypeDiff:
            dif = t - self.lastTimestamp
            v = dif if dif > 0 else 0.0
        self._processDecay(t)
        self.CF1 += v
        self.CF2 += v * v
        self.w += 1.0
        self.cur_mean = _NAN
        self.cur_var = _NAN
        self.cur_std = _NAN
        for c in self.covs:
            cov = <incStat_cov>c
            cov._update_cov(self.ID, v, t)

    cdef double _processDecay(self, double timestamp):
        cdef double factor, timeDiff
        factor = 1.0
        timeDiff = timestamp - self.lastTimestamp
        if timeDiff > 0:
            factor = pow(2.0, -self.Lambda * timeDiff)
            self.CF1 *= factor
            self.CF2 *= factor
            self.w *= factor
            self.lastTimestamp = timestamp
        return factor

    cdef double _mean(self):
        if isnan(self.cur_mean):
            self.cur_mean = self.CF1 / self.w
        return self.cur_mean

    cdef double _var(self):
        cdef double m
        if isnan(self.cur_var):
            m = self._mean()
            self.cur_var = fabs(self.CF2 / self.w - m * m)
        return self.cur_var

    cdef double _std(self):
        if isnan(self.cur_std):
            self.cur_std = sqrt(self._var())
        return self.cur_std

    cdef list _allstats_1D(self):
        cdef double m
        m = self.CF1 / self.w
        self.cur_mean = m
        self.cur_var = fabs(self.CF2 / self.w - m * m)
        return [self.w, m, self.cur_var]

    cdef list _allstats_2D(self, str ID2):
        cdef list stats1D, stats2D
        cdef incStat_cov cov
        stats1D = self._allstats_1D()
        stats2D = [_NAN, _NAN, _NAN, _NAN]
        for c in self.covs:
            cov = <incStat_cov>c
            if cov.incS1.ID == ID2 or cov.incS2.ID == ID2:
                stats2D = cov._get_stats2()
                break
        return stats1D + stats2D

    cdef list _cov_pcc(self, str ID2):
        cdef incStat_cov cov
        for c in self.covs:
            cov = <incStat_cov>c
            if cov.incS1.ID == ID2 or cov.incS2.ID == ID2:
                return cov._get_stats1()
        return [_NAN, _NAN]

    cdef double _radius(self, list other_incStats):
        cdef double A, vi
        cdef incStat s
        vi = self._var()
        A = vi * vi          # matches Python: self.var()**2
        for o in other_incStats:
            s = <incStat>o
            vi = s._var()
            A += vi * vi     # matches Python: incS.var()**2
        return sqrt(A)

    cdef double _magnitude(self, list other_incStats):
        cdef double A, m
        cdef incStat s
        m = self._mean()
        A = m * m
        for o in other_incStats:
            s = <incStat>o
            m = s._mean()
            A += m * m
        return sqrt(A)

    # ── Public Python-accessible interface (matches AfterImage.py API) ────────

    def insert(self, double v, double t=0):
        self._insert(v, t)

    def processDecay(self, double timestamp):
        return self._processDecay(timestamp)

    def weight(self):
        return self.w

    def mean(self):
        return self._mean()

    def var(self):
        return self._var()

    def std(self):
        return self._std()

    def cov(self, str ID2):
        return [self._cov_pcc(ID2)[0]]

    def pcc(self, str ID2):
        return [self._cov_pcc(ID2)[1]]

    def cov_pcc(self, str ID2):
        return self._cov_pcc(ID2)

    def allstats_1D(self):
        return self._allstats_1D()

    def allstats_2D(self, str ID2):
        return self._allstats_2D(ID2)

    def radius(self, other_incStats):
        return self._radius(list(other_incStats))

    def magnitude(self, other_incStats):
        return self._magnitude(list(other_incStats))

    def getHeaders_1D(self, suffix=True):
        s0 = ("_" + self.ID) if (suffix and self.ID) else ""
        return ["weight" + s0, "mean" + s0, "std" + s0]

    def getHeaders_2D(self, ID2, suffix=True):
        hdrs1D = self.getHeaders_1D(suffix)
        s0 = ("_" + self.ID) if (suffix and self.ID) else "_0"
        s1 = ("_" + ID2)    if (suffix and ID2)    else "_1"
        return hdrs1D + [
            "radius_" + s0 + "_" + s1,
            "magnitude_" + s0 + "_" + s1,
            "covariance_" + s0 + "_" + s1,
            "pcc_" + s0 + "_" + s1,
        ]

    def get_stats1(self):
        return self._allstats_1D()[:2]


# ═══════════════════════════════════════════════════════════════════════════════
# incStat_cov — covariance tracker between two streams
# ═══════════════════════════════════════════════════════════════════════════════
cdef class incStat_cov:
    cdef public double CF3
    cdef public double w3
    cdef public double lastTimestamp_cf3
    cdef public incStat incS1
    cdef public incStat incS2
    cdef double _lastRes0   # last residual for stream 0
    cdef double _lastRes1   # last residual for stream 1

    def __init__(self, incStat incS1, incStat incS2, double init_time=0):
        self.incS1 = incS1
        self.incS2 = incS2
        self.CF3 = 0.0
        self.w3 = 1e-20
        self.lastTimestamp_cf3 = init_time
        self._lastRes0 = 0.0
        self._lastRes1 = 0.0

    cdef void _update_cov(self, str ID, double v, double t):
        cdef int inc
        cdef double res, resid
        inc = 0 if ID == self.incS1.ID else 1
        # Decay the OTHER stream to current time
        if inc == 0:
            self.incS2._processDecay(t)
        else:
            self.incS1._processDecay(t)
        # Decay covariance residuals
        self._processDecay_cov(t, inc)
        # Compute lagged cross-residual
        if inc == 0:
            res = v - self.incS1._mean()
            resid = res * self._lastRes1
            self._lastRes0 = res
        else:
            res = v - self.incS2._mean()
            resid = res * self._lastRes0
            self._lastRes1 = res
        self.CF3 += resid
        self.w3 += 1.0

    cdef void _processDecay_cov(self, double t, int inc):
        cdef double timeDiff, factor, lam
        timeDiff = t - self.lastTimestamp_cf3
        if timeDiff > 0:
            lam = self.incS1.Lambda if inc == 0 else self.incS2.Lambda
            factor = pow(2.0, -lam * timeDiff)
            self.CF3 *= factor
            self.w3 *= factor
            self.lastTimestamp_cf3 = t
            if inc == 0:
                self._lastRes0 *= factor
            else:
                self._lastRes1 *= factor

    cdef double _cov(self):
        return self.CF3 / self.w3

    cdef double _pcc(self):
        cdef double ss
        ss = self.incS1._std() * self.incS2._std()
        return self._cov() / ss if ss != 0.0 else 0.0

    cdef list _get_stats1(self):
        return [self._cov(), self._pcc()]

    cdef list _get_stats2(self):
        return [
            self.incS1._radius([self.incS2]),
            self.incS1._magnitude([self.incS2]),
            self._cov(),
            self._pcc(),
        ]

    # ── Public API ────────────────────────────────────────────────────────────

    def update_cov(self, str ID, double v, double t):
        self._update_cov(ID, v, t)

    def processDecay(self, double t, int micro_inc_indx):
        self._processDecay_cov(t, micro_inc_indx)

    def cov(self):
        return self._cov()

    def pcc(self):
        return self._pcc()

    def get_stats1(self):
        return self._get_stats1()

    def get_stats2(self):
        return self._get_stats2()

    def get_stats3(self):
        return [
            self.incS1.w, self.incS1._mean(), self.incS1._std(),
            self.incS2.w, self.incS2._mean(), self.incS2._std(),
            self._cov(), self._pcc(),
        ]

    def get_stats4(self):
        return [
            self.incS1.w, self.incS1._mean(), self.incS1._std(),
            self.incS2.w, self.incS2._mean(), self.incS2._std(),
            self.incS1._radius([self.incS2]),
            self.incS1._magnitude([self.incS2]),
            self._cov(), self._pcc(),
        ]

    def isRelated(self, str ID):
        return self.incS1.ID == ID or self.incS2.ID == ID

    def getHeaders(self, int ver, int suffix=1):
        s0 = self.incS1.ID if suffix else "0"
        s1 = self.incS2.ID if suffix else "1"
        if ver == 1:
            return ["covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        if ver == 2:
            return ["radius_" + s0 + "_" + s1, "magnitude_" + s0 + "_" + s1,
                    "covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        if ver == 3:
            return ["weight_" + s0, "mean_" + s0, "std_" + s0,
                    "weight_" + s1, "mean_" + s1, "std_" + s1,
                    "covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        if ver == 4:
            return ["weight_" + s0, "mean_" + s0, "std_" + s0,
                    "covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        if ver == 5:
            return ["weight_" + s0, "mean_" + s0, "std_" + s0,
                    "weight_" + s1, "mean_" + s1, "std_" + s1,
                    "radius_" + s0 + "_" + s1, "magnitude_" + s0 + "_" + s1,
                    "covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        return []

    # Compatibility: Python AfterImage.py stores streams as incStats list
    @property
    def incStats(self):
        return [self.incS1, self.incS2]

    @property
    def lastRes(self):
        return [self._lastRes0, self._lastRes1]


# ═══════════════════════════════════════════════════════════════════════════════
# incStatDB — hash-table of incStat streams, keyed by "ID_lambda"
# ═══════════════════════════════════════════════════════════════════════════════
cdef class incStatDB:
    cdef public double limit
    cdef public double df_lambda
    cdef public dict HT

    def __init__(self, double limit=_INF, double default_lambda=_NAN):
        self.HT = {}
        self.limit = limit
        self.df_lambda = default_lambda

    cdef double _get_lambda(self, double Lambda):
        if not isnan(self.df_lambda):
            Lambda = self.df_lambda
        return Lambda

    def get_lambda(self, Lambda):
        return self._get_lambda(float(Lambda))

    def register(self, str ID, double Lambda=1.0, double init_time=0.0, int isTypeDiff=0):
        cdef str key
        cdef incStat incS
        Lambda = self._get_lambda(Lambda)
        key = ID + "_" + str(Lambda)
        incS = self.HT.get(key)
        if incS is None:
            if len(self.HT) + 1 > self.limit:
                raise LookupError(
                    f'Adding Entry:\n{key}\nwould exceed incStatHT 1D limit of '
                    f'{self.limit}.\nObservation Rejected.')
            incS = incStat(Lambda, ID, init_time, isTypeDiff)
            self.HT[key] = incS
        return incS

    def register_cov(self, str ID1, str ID2, double Lambda=1.0,
                     double init_time=0.0, int isTypeDiff=0):
        cdef incStat incS1, incS2
        cdef incStat_cov cov, inc_cov
        Lambda = self._get_lambda(Lambda)
        incS1 = self.register(ID1, Lambda, init_time, isTypeDiff)
        incS2 = self.register(ID2, Lambda, init_time, isTypeDiff)
        for c in incS1.covs:
            cov = <incStat_cov>c
            if cov.incS1.ID == ID2 or cov.incS2.ID == ID2:
                return cov
        inc_cov = incStat_cov(incS1, incS2, init_time)
        incS1.covs.append(inc_cov)
        incS2.covs.append(inc_cov)
        return inc_cov

    def update(self, str ID, double t, double v, double Lambda=1.0, int isTypeDiff=0):
        cdef incStat incS
        incS = self.register(ID, Lambda, t, isTypeDiff)
        incS._insert(v, t)
        return incS

    def update_get_1D_Stats(self, str ID, double t, double v,
                            double Lambda=1.0, int isTypeDiff=0):
        cdef incStat incS
        incS = self.update(ID, t, v, Lambda, isTypeDiff)
        return incS._allstats_1D()

    def update_get_2D_Stats(self, str ID1, str ID2, double t1, double v1,
                            double Lambda=1.0, int level=1):
        cdef incStat_cov inc_cov
        inc_cov = self.register_cov(ID1, ID2, Lambda, t1)
        inc_cov._update_cov(ID1, v1, t1)
        return inc_cov._get_stats1() if level == 1 else inc_cov._get_stats2()

    def update_get_1D2D_Stats(self, str ID1, str ID2, double t1, double v1,
                              double Lambda=1.0):
        return (self.update_get_1D_Stats(ID1, t1, v1, Lambda) +
                self.update_get_2D_Stats(ID1, ID2, t1, v1, Lambda, level=2))

    def get_1D_Stats(self, str ID, double Lambda=1.0):
        cdef incStat incS
        Lambda = self._get_lambda(Lambda)
        incS = self.HT.get(ID + "_" + str(Lambda))
        return incS._allstats_1D() if incS is not None else [_NAN, _NAN, _NAN]

    def get_2D_Stats(self, str ID1, str ID2, double Lambda=1.0):
        cdef incStat incS
        Lambda = self._get_lambda(Lambda)
        incS = self.HT.get(ID1 + "_" + str(Lambda))
        return incS._cov_pcc(ID2) if incS is not None else [_NAN, _NAN]

    def get_all_2D_Stats(self, str ID, double Lambda=1.0):
        cdef incStat incS1
        cdef incStat_cov cov
        Lambda = self._get_lambda(Lambda)
        incS1 = self.HT.get(ID + "_" + str(Lambda))
        if incS1 is None:
            return ([], [])
        stats, IDs = [], []
        for c in incS1.covs:
            cov = <incStat_cov>c
            stats.append(cov._get_stats1())
            IDs.append([cov.incS1.ID, cov.incS2.ID])
        return stats, IDs

    def get_nD_Stats(self, IDs, double Lambda=1.0):
        cdef incStat incS
        cdef double rad = 0.0, mag = 0.0, m
        Lambda = self._get_lambda(Lambda)
        incStats = []
        for ID in IDs:
            incS = self.HT.get(ID + "_" + str(Lambda))
            if incS is not None:
                incStats.append(incS)
        for o in incStats:
            incS = <incStat>o
            rad += incS._var()
            m = incS._mean()
            mag += m * m
        return [sqrt(rad), sqrt(mag)]

    def getHeaders_1D(self, Lambda=1, ID=None):
        Lambda = self._get_lambda(float(Lambda))
        hdrs = incStat(Lambda, ID if ID is not None else '').getHeaders_1D(suffix=False)
        return [str(Lambda) + "_" + s for s in hdrs]

    def getHeaders_2D(self, Lambda=1, IDs=None, ver=1):
        Lambda = self._get_lambda(float(Lambda))
        if IDs is None:
            IDs = ['0', '1']
        cdef incStat_cov dummy
        dummy = incStat_cov(incStat(Lambda, IDs[0]), incStat(Lambda, IDs[1]), 0.0)
        hdrs = dummy.getHeaders(ver, suffix=0)
        return [str(Lambda) + "_" + s for s in hdrs]

    def getHeaders_1D2D(self, Lambda=1, IDs=None, ver=1):
        Lambda = self._get_lambda(float(Lambda))
        if IDs is None:
            IDs = ['0', '1']
        return self.getHeaders_1D(Lambda, IDs[0]) + self.getHeaders_2D(Lambda, IDs, ver)

    def getHeaders_nD(self, Lambda=1, IDs=[]):
        Lambda = self._get_lambda(float(Lambda))
        ID = ":" + "_".join(str(s) for s in IDs)
        return [str(Lambda) + "_radius" + ID, str(Lambda) + "_magnitude" + ID]

    def cleanOutOldRecords(self, double cutoffWeight, double curTime):
        cdef int n = 0
        cdef incStat incS
        cdef double W
        to_delete = []
        for key, obj in sorted(self.HT.items(), key=lambda t: t[1].w):
            incS = <incStat>obj
            incS._processDecay(curTime)
            W = incS.w
            if W <= cutoffWeight:
                to_delete.append(key)
                n += 1
            else:
                break
        for k in to_delete:
            del self.HT[k]
        return n
