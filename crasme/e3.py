"""E3 blinded rater study: allocation and pre-registered analysis (rec. P2-02).

Design: within-subject, 3 conditions (A qualitative v1.0 sheet · B anchored ranges + evidence ·
C probabilistic/Monte Carlo). Scenarios are split into 3 blocks; rater groups rotate the
condition->block mapping (Latin square), so each rater sees every condition exactly once per block,
each scenario is rated under every condition by different raters, and no rater sees a scenario twice.
Block order is randomised per rater (seeded, recorded).

Estimands (pre-register):
  E3-1 (primary)  Δα = α_ord(B) − α_ord(A) on the likelihood rating, 95% bootstrap CI over scenarios
  E3-2            Δα = α_ord(C) − α_ord(B)
  E3-3            condition effect on |rating − reference| from a crossed random-effects model
                  (rater and scenario as variance components)
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .agreement import krippendorff_alpha

CONDITIONS = ("A", "B", "C")
LATIN = [(0, 1, 2), (1, 2, 0), (2, 0, 1)]   # condition index per block for rater groups 0..2


def allocate(raters: list[str], scenarios: list[str], seed: int = 2026) -> pd.DataFrame:
    if len(raters) % 3 or len(scenarios) % 3:
        raise ValueError("number of raters and scenarios must each be a multiple of 3")
    rng = np.random.default_rng(seed)
    scen = list(scenarios)
    rng.shuffle(scen)
    blocks = [scen[i::3] for i in range(3)]
    rows = []
    for k, r in enumerate(raters):
        square = LATIN[k % 3]
        order = rng.permutation(3)
        pos = 0
        for b in order:
            items = list(blocks[b])
            rng.shuffle(items)
            for s in items:
                pos += 1
                rows.append({"rater_id": r, "scenario_id": s, "block": int(b),
                             "condition": CONDITIONS[square[b]], "position": pos})
    return pd.DataFrame(rows)


def check_balance(alloc: pd.DataFrame) -> dict:
    per_rater = alloc.groupby(["rater_id", "condition"]).size().unstack()
    per_scen = alloc.groupby(["scenario_id", "condition"]).size().unstack()
    return {"rater_condition_counts_equal": bool((per_rater.nunique(axis=1) == 1).all()),
            "every_scenario_in_every_condition": bool(per_scen.notna().all().all() and (per_scen > 0).all().all()),
            "no_repeat_ratings": bool(not alloc.duplicated(["rater_id", "scenario_id"]).any())}


def alpha_by_condition(df: pd.DataFrame, dimension: str = "likelihood") -> dict[str, float]:
    out = {}
    d = df[df.dimension == dimension]
    for c, g in d.groupby("condition"):
        m = g.pivot_table(index="rater_id", columns="scenario_id", values="rating").to_numpy(float)
        out[c] = krippendorff_alpha(m, "ordinal")
    return out


def delta_alpha(df: pd.DataFrame, a: str = "B", b: str = "A", dimension: str = "likelihood",
                n_boot: int = 1000, seed: int = 0) -> dict:
    """Δα = α(a) − α(b) with a percentile bootstrap over scenarios."""
    d = df[df.dimension == dimension]
    scen = d.scenario_id.unique()
    rng = np.random.default_rng(seed)

    def est(sub):
        mats = {}
        for c in (a, b):
            g = sub[sub.condition == c]
            mats[c] = g.pivot_table(index="rater_id", columns="sid", values="rating").to_numpy(float)
        return krippendorff_alpha(mats[a], "ordinal") - krippendorff_alpha(mats[b], "ordinal")

    base = d.assign(sid=d.scenario_id)
    point = est(base)
    boots = []
    for _ in range(n_boot):
        pick = rng.choice(scen, len(scen), replace=True)
        parts = [d[d.scenario_id == s].assign(sid=f"{s}#{i}") for i, s in enumerate(pick)]
        try:
            boots.append(est(pd.concat(parts)))
        except (ValueError, ZeroDivisionError):
            continue
    lo, hi = np.quantile(boots, [0.025, 0.975])
    return {"estimand": f"alpha({a}) - alpha({b})", "point": float(point), "ci95": (float(lo), float(hi)),
            "supported": bool(lo > 0)}


def deviation_model(df: pd.DataFrame, reference: pd.Series, dimension: str = "likelihood") -> dict:
    """|rating − reference| ~ condition + (1|rater) + (1|scenario) via statsmodels MixedLM."""
    import statsmodels.formula.api as smf
    d = df[df.dimension == dimension].copy()
    d["absdev"] = (d.rating - d.scenario_id.map(reference)).abs()
    d["one"] = 1
    md = smf.mixedlm("absdev ~ C(condition, Treatment('A'))", d, groups="one",
                     vc_formula={"rater": "0 + C(rater_id)", "scenario": "0 + C(scenario_id)"})
    fit = md.fit(reml=True, method=["lbfgs", "powell", "nm"])
    coefs = {k: float(v) for k, v in fit.params.items() if k.startswith("C(condition")}
    ci = fit.conf_int()
    return {"coef": coefs,
            "ci95": {k: (float(ci.loc[k, 0]), float(ci.loc[k, 1])) for k in coefs},
            "n_obs": int(fit.nobs), "converged": bool(fit.converged)}


def simulate(alloc: pd.DataFrame, noise: dict[str, float] | None = None, seed: int = 1) -> tuple[pd.DataFrame, pd.Series]:
    """Synthetic ratings for planning/tests: reference truth + rater bias + condition-specific noise."""
    noise = noise or {"A": 0.95, "B": 0.6, "C": 0.6}
    rng = np.random.default_rng(seed)
    scen = sorted(alloc.scenario_id.unique())
    truth = pd.Series(np.clip(np.rint(rng.normal(3, 1.1, len(scen))), 1, 5), index=scen)
    bias = {r: rng.normal(0, 0.3) for r in alloc.rater_id.unique()}
    out = alloc.copy()
    out["dimension"] = "likelihood"
    out["rating"] = [int(np.clip(np.rint(truth[s] + bias[r] + rng.normal(0, noise[c])), 1, 5))
                     for r, s, c in zip(out.rater_id, out.scenario_id, out.condition)]
    return out, truth
