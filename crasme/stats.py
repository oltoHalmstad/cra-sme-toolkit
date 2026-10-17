"""Small-sample evaluation statistics for the SME pilot (Phase 4, O5).

Emphasis on effect sizes with bootstrap CIs and case-wise reporting, as the
concept note requires; significance tests are reported only as secondary.
"""
from __future__ import annotations

import math
from typing import Sequence

import numpy as np
from scipy import stats as st


def paired_summary(before: Sequence[float], after: Sequence[float], n_boot: int = 5000,
                   seed: int = 0, better: str = "lower") -> dict:
    """Paired effect summary. ``better`` says which direction is an improvement."""
    b, a = np.asarray(before, float), np.asarray(after, float)
    if b.shape != a.shape:
        raise ValueError("paired samples must have equal length")
    d = a - b
    n = len(d)
    rng = np.random.default_rng(seed)
    boot_med = [np.median(rng.choice(d, n, replace=True)) for _ in range(n_boot)]
    sd = d.std(ddof=1) if n > 1 else float("nan")
    dz = d.mean() / sd if sd and not math.isnan(sd) else float("nan")
    j = 1 - 3 / (4 * (n - 1) - 1) if n > 2 else 1.0   # Hedges small-sample correction
    try:
        w = st.wilcoxon(a, b, zero_method="zsplit")
        p = float(w.pvalue)
    except ValueError:
        p = float("nan")
    return {"n": n, "median_diff": float(np.median(d)),
            "median_diff_ci95": (float(np.quantile(boot_med, .025)), float(np.quantile(boot_med, .975))),
            "mean_diff": float(d.mean()), "hedges_gz": float(dz * j), "wilcoxon_p": p,
            "improved_cases": int((d < 0).sum() if better == "lower" else (d > 0).sum()),
            "worse_cases": int((d > 0).sum() if better == "lower" else (d < 0).sum())}


def cliffs_delta(x: Sequence[float], y: Sequence[float]) -> float:
    """P(X>Y) - P(X<Y); robust ordinal effect size for independent groups."""
    x, y = np.asarray(x), np.asarray(y)
    gt = (x[:, None] > y[None, :]).sum()
    lt = (x[:, None] < y[None, :]).sum()
    return float((gt - lt) / (len(x) * len(y)))


def power_paired_wilcoxon(n: int, effect_dz: float, alpha: float = 0.05, n_sim: int = 4000,
                          seed: int = 0) -> float:
    """Simulated power of a two-sided Wilcoxon signed-rank test with normal differences."""
    rng = np.random.default_rng(seed)
    hits = 0
    for _ in range(n_sim):
        d = rng.normal(effect_dz, 1.0, n)
        try:
            if st.wilcoxon(d).pvalue < alpha:
                hits += 1
        except ValueError:
            pass
    return hits / n_sim


def staggered_did(df, outcome: str, unit: str = "sme", period: str = "period",
                  treated: str = "treated") -> dict:
    """Two-way fixed-effects estimate for a staggered roll-out (descriptive with tiny n).

    df: pandas DataFrame with one row per unit-period and a 0/1 treated column.
    """
    import pandas as pd
    X = pd.get_dummies(df[[unit, period]].astype(str), drop_first=True, dtype=float)
    X.insert(0, "treated", df[treated].astype(float))
    X.insert(0, "const", 1.0)
    y = df[outcome].astype(float).to_numpy()
    beta, *_ = np.linalg.lstsq(X.to_numpy(), y, rcond=None)
    resid = y - X.to_numpy() @ beta
    dof = max(len(y) - X.shape[1], 1)
    sigma2 = resid @ resid / dof
    cov = sigma2 * np.linalg.pinv(X.to_numpy().T @ X.to_numpy())
    se = float(math.sqrt(cov[1, 1]))
    return {"effect": float(beta[1]), "se": se, "dof": dof,
            "note": "TWFE can be biased with heterogeneous effects in staggered designs; report case-wise too."}
