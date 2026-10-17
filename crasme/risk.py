"""Risk scoring models for CRA-SME.

Two families are implemented so they can be compared experimentally (RQ3):

1. The v1.0 ordinal model (parity with the Excel workbook):
       inherent = L x I x E            (each 1-5, range 1-125)
       residual = round(inherent * (1 - verified_effectiveness))
       ALE      = p_annual * loss_eur
2. An uncertainty-aware, FAIR-inspired Monte Carlo model using ranges
   (min / most-likely / max frequency, 90% CI for loss).

None of these scores is a CRA criterion. Mandatory obligations and release
blockers are handled separately in ``crasme.traceability`` and can never be
waived by a score.
"""
from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from typing import Iterable, Sequence

import numpy as np

BANDS = ((75, "Critical"), (40, "High"), (15, "Medium"), (1, "Low"))


# ---------------------------------------------------------------------------
# v1.0 ordinal model (must stay in parity with the workbook formulas)
# ---------------------------------------------------------------------------
def _check_scale(name: str, v: int) -> None:
    if not isinstance(v, (int, np.integer)) or isinstance(v, bool) or not 1 <= v <= 5:
        raise ValueError(f"{name} must be an integer 1-5, got {v!r}")


def inherent_score(likelihood: int, impact: int, exposure: int) -> int:
    for n, v in (("likelihood", likelihood), ("impact", impact), ("exposure", exposure)):
        _check_scale(n, v)
    return int(likelihood * impact * exposure)


def band(score: float | None) -> str:
    """Workbook banding: Low 1-14, Medium 15-39, High 40-74, Critical 75-125."""
    if score is None:
        return ""
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "Low"


def excel_round(x: float, ndigits: int = 0) -> float:
    """Excel ROUND() rounds half away from zero (Python's round() is banker's)."""
    m = 10 ** ndigits
    return math.floor(abs(x) * m + 0.5) / m * (1 if x >= 0 else -1)


def residual_score(inherent: int, effectiveness: float | None) -> int | None:
    if effectiveness is None:
        return None
    if not 0 <= effectiveness <= 1:
        raise ValueError("effectiveness must be within 0-1")
    return int(excel_round(inherent * (1 - effectiveness)))


def ale(p_annual: float | None, loss_eur: float | None) -> float | None:
    if p_annual is None or loss_eur is None:
        return None
    if not 0 <= p_annual <= 1:
        raise ValueError("annual probability must be within 0-1")
    if loss_eur < 0:
        raise ValueError("loss must be non-negative")
    return p_annual * loss_eur


@dataclass
class RiskRow:
    """One Risk Register row, mirroring workbook columns A-S."""

    risk_id: str
    product_id: str
    scenario: str
    likelihood: int
    impact: int
    exposure: int
    effectiveness: float | None = None
    p_annual: float | None = None
    loss_eur: float | None = None
    # v1.1 additions (research fields)
    mandatory_blocker: bool = False
    exploited_in_wild: bool = False
    epss: float | None = None
    cvss: float | None = None

    @property
    def inherent(self) -> int:
        return inherent_score(self.likelihood, self.impact, self.exposure)

    @property
    def inherent_band(self) -> str:
        return band(self.inherent)

    @property
    def residual(self) -> int | None:
        return residual_score(self.inherent, self.effectiveness)

    @property
    def residual_band(self) -> str:
        return band(self.residual)

    @property
    def inherent_ale(self) -> float | None:
        return ale(self.p_annual, self.loss_eur)

    @property
    def residual_p(self) -> float | None:
        if self.p_annual is None or self.effectiveness is None:
            return None
        return self.p_annual * (1 - self.effectiveness)

    @property
    def residual_ale(self) -> float | None:
        return ale(self.residual_p, self.loss_eur)

    @property
    def expected_reduction(self) -> float | None:
        a, b = self.inherent_ale, self.residual_ale
        return None if a is None or b is None else a - b


def distinct_lie_scores() -> list[int]:
    """All distinct values reachable by L x I x E on 1-5 scales (only 30 of 125)."""
    return sorted({a * b * c for a, b, c in itertools.product(range(1, 6), repeat=3)})


def band_distribution() -> dict[str, float]:
    """Share of the 125 equally-likely (L,I,E) cells falling in each band."""
    counts: dict[str, int] = {}
    for a, b, c in itertools.product(range(1, 6), repeat=3):
        lbl = band(a * b * c)
        counts[lbl] = counts.get(lbl, 0) + 1
    return {k: v / 125 for k, v in counts.items()}


# Alternative aggregations for the RQ3 comparison
AGGREGATORS = {
    "product": lambda l, i, e: l * i * e,
    "sum": lambda l, i, e: l + i + e,
    "geomean": lambda l, i, e: (l * i * e) ** (1 / 3),
    "max": lambda l, i, e: max(l, i, e),
    "weighted_sum": lambda l, i, e: 0.4 * l + 0.4 * i + 0.2 * e,
}


# ---------------------------------------------------------------------------
# Uncertainty-aware Monte Carlo model
# ---------------------------------------------------------------------------
def pert_sample(rng: np.random.Generator, low: float, mode: float, high: float,
                size: int, lamb: float = 4.0) -> np.ndarray:
    """Beta-PERT samples. Degenerate ranges return a constant."""
    if not low <= mode <= high:
        raise ValueError("require low <= mode <= high")
    if high == low:
        return np.full(size, float(low))
    a = 1 + lamb * (mode - low) / (high - low)
    b = 1 + lamb * (high - mode) / (high - low)
    return low + rng.beta(a, b, size) * (high - low)


def lognormal_from_ci(rng: np.random.Generator, p05: float, p95: float, size: int) -> np.ndarray:
    """Lognormal samples whose 5th/95th percentiles match an elicited 90% CI."""
    if not 0 < p05 <= p95:
        raise ValueError("require 0 < p05 <= p95")
    if p05 == p95:
        return np.full(size, float(p05))
    z = 1.6448536269514722
    mu = (math.log(p05) + math.log(p95)) / 2
    sigma = (math.log(p95) - math.log(p05)) / (2 * z)
    return rng.lognormal(mu, sigma, size)


@dataclass
class UncertainScenario:
    risk_id: str
    freq_low: float      # events / year
    freq_mode: float
    freq_high: float
    loss_p05: float      # EUR per event, 90% CI
    loss_p95: float
    control_reduction_low: float = 0.0   # fraction of frequency removed by controls
    control_reduction_high: float = 0.0
    notes: str = ""


@dataclass
class MCResult:
    risk_id: str
    samples: np.ndarray = field(repr=False)

    @property
    def mean(self) -> float:
        return float(self.samples.mean())

    def quantile(self, q: float) -> float:
        return float(np.quantile(self.samples, q))

    def prob_exceed(self, threshold: float) -> float:
        return float((self.samples > threshold).mean())


def simulate_annual_loss(s: UncertainScenario, n: int = 20_000, seed: int | None = 0,
                         residual: bool = False) -> MCResult:
    """Annual loss = sum over Poisson(freq) events of lognormal losses."""
    rng = np.random.default_rng(seed)
    freq = pert_sample(rng, s.freq_low, s.freq_mode, s.freq_high, n)
    if residual:
        red = rng.uniform(s.control_reduction_low, s.control_reduction_high, n)
        freq = freq * (1 - red)
    events = rng.poisson(freq)
    total = np.zeros(n)
    nz = np.nonzero(events)[0]
    if nz.size:
        k = int(events[nz].sum())
        losses = lognormal_from_ci(rng, s.loss_p05, s.loss_p95, k)
        idx = np.repeat(nz, events[nz])
        np.add.at(total, idx, losses)
    return MCResult(s.risk_id, total)


def rank_probability(results: Sequence[MCResult], top_k: int = 1) -> dict[str, float]:
    """P(risk is in the top-k by annual loss), computed draw-by-draw."""
    mat = np.vstack([r.samples for r in results])          # risks x draws
    order = np.argsort(-mat, axis=0)                        # descending per draw
    top = order[:top_k, :]
    return {r.risk_id: float((top == i).any(axis=0).mean()) for i, r in enumerate(results)}


# ---------------------------------------------------------------------------
# Ranking stability under assessor noise (RQ3)
# ---------------------------------------------------------------------------
def perturb_ordinal(rng: np.random.Generator, values: np.ndarray, p_shift: float) -> np.ndarray:
    """With probability p_shift move each 1-5 rating by +/-1 (clipped)."""
    shift = rng.choice([-1, 1], size=values.shape) * (rng.random(values.shape) < p_shift)
    return np.clip(values + shift, 1, 5)


def kendall_tau_b(x: Sequence[float], y: Sequence[float]) -> float:
    from scipy.stats import kendalltau
    t = kendalltau(x, y).statistic
    return float(t) if not np.isnan(t) else 0.0


def ranking_stability(lie: np.ndarray, aggregator: str = "product", p_shift: float = 0.3,
                      n_sim: int = 500, seed: int = 0, top_k: int = 3) -> dict[str, float]:
    """Mean Kendall tau-b and top-k overlap between baseline and perturbed rankings."""
    agg = AGGREGATORS[aggregator]
    rng = np.random.default_rng(seed)
    base = np.array([agg(*row) for row in lie], dtype=float)
    base_top = set(np.argsort(-base, kind="stable")[:top_k])
    taus, overlaps = [], []
    for _ in range(n_sim):
        p = perturb_ordinal(rng, lie, p_shift)
        s = np.array([agg(*row) for row in p], dtype=float)
        taus.append(kendall_tau_b(base, s))
        overlaps.append(len(base_top & set(np.argsort(-s, kind="stable")[:top_k])) / top_k)
    return {"tau_mean": float(np.mean(taus)), "tau_p05": float(np.quantile(taus, 0.05)),
            "topk_overlap": float(np.mean(overlaps)), "ties_share": tie_share(base)}


def tie_share(scores: Iterable[float]) -> float:
    """Fraction of risk pairs that are tied (unresolvable without extra info)."""
    s = list(scores)
    pairs = list(itertools.combinations(s, 2))
    return sum(1 for a, b in pairs if a == b) / len(pairs) if pairs else 0.0
