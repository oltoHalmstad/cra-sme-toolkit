"""Inter-rater agreement statistics for blinded risk-assessment studies (RQ3).

Implemented without heavy dependencies so results are reproducible and
auditable; unit tests cross-check against published worked examples
(Shrout & Fleiss 1979; Krippendorff 2011).
"""
from __future__ import annotations

from typing import Sequence

import numpy as np


def weighted_kappa(r1: Sequence[int], r2: Sequence[int], categories: Sequence[int] | None = None,
                   weights: str = "quadratic") -> float:
    """Cohen's weighted kappa for two raters on an ordinal scale."""
    r1, r2 = np.asarray(r1), np.asarray(r2)
    if r1.shape != r2.shape:
        raise ValueError("raters must rate the same items")
    cats = list(categories) if categories is not None else sorted(set(r1) | set(r2))
    k = len(cats)
    idx = {c: i for i, c in enumerate(cats)}
    obs = np.zeros((k, k))
    for a, b in zip(r1, r2):
        obs[idx[a], idx[b]] += 1
    obs /= obs.sum()
    exp = np.outer(obs.sum(1), obs.sum(0))
    i, j = np.indices((k, k))
    if weights == "quadratic":
        w = (i - j) ** 2 / (k - 1) ** 2
    elif weights == "linear":
        w = np.abs(i - j) / (k - 1)
    elif weights in ("none", "unweighted", None):
        w = (i != j).astype(float)
    else:
        raise ValueError(weights)
    denom = (w * exp).sum()
    return float(1 - (w * obs).sum() / denom) if denom else 1.0


def icc(ratings: np.ndarray, kind: str = "ICC2_1") -> float:
    """Shrout & Fleiss intraclass correlations. ratings: targets x raters, complete."""
    x = np.asarray(ratings, dtype=float)
    n, k = x.shape
    gm = x.mean()
    ss_rows = k * ((x.mean(1) - gm) ** 2).sum()
    ss_cols = n * ((x.mean(0) - gm) ** 2).sum()
    ss_tot = ((x - gm) ** 2).sum()
    ss_err = ss_tot - ss_rows - ss_cols
    bms = ss_rows / (n - 1)
    jms = ss_cols / (k - 1)
    ems = ss_err / ((n - 1) * (k - 1))
    wms = (ss_cols + ss_err) / (n * (k - 1))
    if kind == "ICC1_1":
        return float((bms - wms) / (bms + (k - 1) * wms))
    if kind == "ICC2_1":   # two-way random, absolute agreement, single rater
        return float((bms - ems) / (bms + (k - 1) * ems + k * (jms - ems) / n))
    if kind == "ICC3_1":   # two-way mixed, consistency, single rater
        return float((bms - ems) / (bms + (k - 1) * ems))
    if kind == "ICC2_k":
        return float((bms - ems) / (bms + (jms - ems) / n))
    raise ValueError(kind)


def krippendorff_alpha(data: np.ndarray, level: str = "ordinal") -> float:
    """Krippendorff's alpha. data: raters x units, np.nan for missing.

    Supports nominal, ordinal, interval and ratio metrics.
    """
    d = np.asarray(data, dtype=float)
    values = np.unique(d[~np.isnan(d)])
    vidx = {v: i for i, v in enumerate(values)}
    V = len(values)
    o = np.zeros((V, V))
    for u in range(d.shape[1]):
        col = d[:, u]
        col = col[~np.isnan(col)]
        m = len(col)
        if m < 2:
            continue
        for a in range(m):
            for b in range(m):
                if a != b:
                    o[vidx[col[a]], vidx[col[b]]] += 1 / (m - 1)
    nc = o.sum(1)
    n = nc.sum()
    if level == "nominal":
        delta = 1 - np.eye(V)
    elif level == "interval":
        delta = (values[:, None] - values[None, :]) ** 2
    elif level == "ratio":
        s = values[:, None] + values[None, :]
        with np.errstate(divide="ignore", invalid="ignore"):
            delta = np.where(s == 0, 0, ((values[:, None] - values[None, :]) / s) ** 2)
    elif level == "ordinal":
        delta = np.zeros((V, V))
        for c in range(V):
            for k in range(V):
                lo, hi = min(c, k), max(c, k)
                delta[c, k] = (nc[lo:hi + 1].sum() - (nc[c] + nc[k]) / 2) ** 2
    else:
        raise ValueError(level)
    do = (o * delta).sum()
    de = (np.outer(nc, nc) * delta).sum() / (n - 1)
    return float(1 - do / de) if de else 1.0


def bootstrap_ci(stat_fn, data: np.ndarray, n_boot: int = 2000, alpha: float = 0.05,
                 axis: int = 0, seed: int = 0) -> tuple[float, float, float]:
    """Percentile bootstrap over items (rows by default). Returns (est, lo, hi)."""
    rng = np.random.default_rng(seed)
    data = np.asarray(data)
    est = stat_fn(data)
    n = data.shape[axis]
    boots = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        sample = np.take(data, idx, axis=axis)
        try:
            boots.append(stat_fn(sample))
        except (ZeroDivisionError, FloatingPointError, ValueError):
            continue
    boots = np.array([b for b in boots if np.isfinite(b)])
    return float(est), float(np.quantile(boots, alpha / 2)), float(np.quantile(boots, 1 - alpha / 2))


def interpret_icc(v: float) -> str:
    """Koo & Li (2016) guideline bands."""
    return "poor" if v < 0.5 else "moderate" if v < 0.75 else "good" if v < 0.9 else "excellent"
