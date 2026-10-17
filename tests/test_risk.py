import numpy as np
import pytest

from crasme import risk as r


# --- parity with workbook v1.0 demo rows (values recomputed by hand) ---
@pytest.mark.parametrize("row,exp", [
    (r.RiskRow("DEMO-R01", "DEMO-001", "Unauthenticated management endpoint", 4, 5, 4, 0.5, 0.2, 150000),
     dict(inherent=80, inherent_band="Critical", residual=40, residual_band="High",
          inherent_ale=30000, residual_ale=15000, expected_reduction=15000)),
    (r.RiskRow("DEMO-R02", "DEMO-001", "Outdated dependency exploited", 3, 4, 4, 0.4, 0.1, 80000),
     dict(inherent=48, inherent_band="High", residual=29, residual_band="Medium",
          inherent_ale=8000, residual_ale=4800, expected_reduction=3200)),
])
def test_demo_rows(row, exp):
    for k, v in exp.items():
        assert getattr(row, k) == pytest.approx(v), k


@pytest.mark.parametrize("score,label", [(1, "Low"), (14, "Low"), (15, "Medium"), (39, "Medium"),
                                         (40, "High"), (74, "High"), (75, "Critical"), (125, "Critical")])
def test_band_boundaries(score, label):
    assert r.band(score) == label


def test_excel_rounding_half_away_from_zero():
    # Excel ROUND(12.5,0)=13 whereas Python round(12.5)=12; the model must follow Excel
    assert r.residual_score(25, 0.5) == 13
    assert round(12.5) == 12


@pytest.mark.parametrize("bad", [0, 6, 2.5, True, None])
def test_scale_validation(bad):
    with pytest.raises((ValueError, TypeError)):
        r.inherent_score(bad, 3, 3)


def test_effectiveness_and_probability_bounds():
    with pytest.raises(ValueError):
        r.residual_score(50, 1.2)
    with pytest.raises(ValueError):
        r.ale(1.5, 100)
    assert r.residual_score(50, None) is None


def test_only_30_distinct_scores():
    """Documented limitation: L x I x E has 30 distinct values, so many ties."""
    assert len(r.distinct_lie_scores()) == 30


def test_band_distribution_sums_to_one():
    d = r.band_distribution()
    assert sum(d.values()) == pytest.approx(1.0)
    # Exact cell counts of the 5x5x5 cube: only 10/125 cells reach "Critical",
    # 74% of cells are Low/Medium — a property reviewers should know.
    assert {k: round(v * 125) for k, v in d.items()} == {"Low": 47, "Medium": 46, "High": 22, "Critical": 10}


def test_pert_bounds_and_lognormal_ci():
    rng = np.random.default_rng(1)
    x = r.pert_sample(rng, 0.1, 0.3, 2.0, 50_000)
    assert x.min() >= 0.1 and x.max() <= 2.0
    y = r.lognormal_from_ci(rng, 10_000, 200_000, 200_000)
    assert np.quantile(y, 0.05) == pytest.approx(10_000, rel=0.03)
    assert np.quantile(y, 0.95) == pytest.approx(200_000, rel=0.03)


def test_monte_carlo_mean_matches_analytic():
    s = r.UncertainScenario("X", 0.5, 0.5, 0.5, 50_000, 50_000)
    res = r.simulate_annual_loss(s, n=100_000, seed=3)
    assert res.mean == pytest.approx(0.5 * 50_000, rel=0.03)


def test_monte_carlo_reproducible_and_residual_lower():
    s = r.UncertainScenario("X", 0.1, 0.4, 1.5, 5_000, 300_000, 0.3, 0.6)
    a = r.simulate_annual_loss(s, seed=7)
    b = r.simulate_annual_loss(s, seed=7)
    assert np.array_equal(a.samples, b.samples)
    assert r.simulate_annual_loss(s, seed=7, residual=True).mean < a.mean


def test_rank_probability_sums_to_k():
    sc = [r.UncertainScenario(f"R{i}", 0.1 * i, 0.2 * i, 0.4 * i, 1e4, 1e5) for i in range(1, 5)]
    res = [r.simulate_annual_loss(s, n=5000, seed=i) for i, s in enumerate(sc)]
    p = r.rank_probability(res, top_k=2)
    assert sum(p.values()) == pytest.approx(2.0)


def test_ranking_stability_no_noise_is_perfect():
    lie = np.array([[4, 5, 4], [3, 4, 4], [2, 2, 3], [5, 3, 2], [1, 2, 2]])
    out = r.ranking_stability(lie, p_shift=0.0, n_sim=10)
    assert out["tau_mean"] == pytest.approx(1.0)
    assert out["topk_overlap"] == pytest.approx(1.0)


def test_rating_range_validation_and_score_range():
    l = r.RatingRange(2, 3, 4, "EPSS 3%", "public PoC")
    i = r.RatingRange(3, 4, 4, "data flow", "personal data")
    e = r.RatingRange(3, 3, 5, "", "")
    s = r.score_range(l, i, e)
    assert (s["low"], s["central"], s["high"]) == (18, 36, 80)
    assert s["band_ambiguous"] and s["bands"] == ["Medium", "Critical"]
    assert s["undocumented"] == ["exposure"]
    with pytest.raises(ValueError):
        r.RatingRange(4, 3, 5)


def test_kev_floor_forces_top_likelihood():
    l = r.kev_floor(r.RatingRange(1, 2, 3), True)
    assert (l.central, l.high) == (5, 5) and l.low >= 4
    assert r.kev_floor(r.RatingRange(1, 2, 3), False).central == 2


def test_anchors_cover_all_levels():
    for dim in ("likelihood", "impact", "exposure"):
        assert set(r.ANCHORS[dim]) == {1, 2, 3, 4, 5}
