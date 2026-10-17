import numpy as np
import pytest

from crasme import agreement as a

# Shrout & Fleiss (1979), Table 2: 6 targets x 4 judges
SF = np.array([[9, 2, 5, 8], [6, 1, 3, 2], [8, 4, 6, 8], [7, 1, 2, 6], [10, 5, 6, 9], [6, 2, 4, 7]])


@pytest.mark.parametrize("kind,expected", [("ICC1_1", 0.17), ("ICC2_1", 0.29), ("ICC3_1", 0.71)])
def test_icc_shrout_fleiss(kind, expected):
    assert a.icc(SF, kind) == pytest.approx(expected, abs=0.006)


# Krippendorff (2011) "Computing Krippendorff's alpha-reliability", 4 observers x 12 units
N = np.nan
KR = np.array([
    [1, 2, 3, 3, 2, 1, 4, 1, 2, N, N, N],
    [1, 2, 3, 3, 2, 2, 4, 1, 2, 5, N, 3],
    [N, 3, 3, 3, 2, 3, 4, 2, 2, 5, 1, N],
    [1, 2, 3, 3, 2, 4, 4, 1, 2, 5, 1, N],
])


@pytest.mark.parametrize("level,expected", [("nominal", 0.743), ("ordinal", 0.815), ("interval", 0.849)])
def test_krippendorff_reference(level, expected):
    assert a.krippendorff_alpha(KR, level) == pytest.approx(expected, abs=0.001)


def test_krippendorff_matches_reference_package():
    kp = pytest.importorskip("krippendorff")
    for level in ("nominal", "ordinal", "interval", "ratio"):
        assert a.krippendorff_alpha(KR, level) == pytest.approx(
            kp.alpha(reliability_data=KR, level_of_measurement=level), abs=1e-9)


def test_weighted_kappa_matches_sklearn():
    sk = pytest.importorskip("sklearn.metrics")
    rng = np.random.default_rng(0)
    x = rng.integers(1, 6, 60)
    y = np.clip(x + rng.integers(-1, 2, 60), 1, 5)
    for w in ("linear", "quadratic"):
        assert a.weighted_kappa(x, y, range(1, 6), w) == pytest.approx(
            sk.cohen_kappa_score(x, y, labels=list(range(1, 6)), weights=w), abs=1e-12)


def test_perfect_agreement():
    x = [1, 2, 3, 4, 5, 3]
    assert a.weighted_kappa(x, x) == pytest.approx(1.0)
    assert a.krippendorff_alpha(np.array([x, x]), "ordinal") == pytest.approx(1.0)


def test_bootstrap_ci_contains_estimate():
    est, lo, hi = a.bootstrap_ci(lambda d: a.icc(d, "ICC2_1"), SF, n_boot=300)
    assert lo <= est <= hi


def test_icc_interpretation():
    assert a.interpret_icc(0.4) == "poor" and a.interpret_icc(0.95) == "excellent"
