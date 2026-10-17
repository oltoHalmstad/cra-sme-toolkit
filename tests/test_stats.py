import pandas as pd
import pytest

from crasme import stats as s


def test_paired_direction_aware_counts():
    r = s.paired_summary([0.2, 0.3, 0.4], [0.5, 0.6, 0.35], better="higher")
    assert (r["improved_cases"], r["worse_cases"]) == (2, 1)
    r = s.paired_summary([30, 20, 10], [20, 25, 5], better="lower")
    assert (r["improved_cases"], r["worse_cases"]) == (2, 1)


def test_paired_rejects_mismatch():
    with pytest.raises(ValueError):
        s.paired_summary([1, 2], [1])


def test_cliffs_delta_extremes():
    assert s.cliffs_delta([5, 6], [1, 2]) == 1.0
    assert s.cliffs_delta([1, 2], [1, 2]) == 0.0


def test_power_increases_with_n():
    assert s.power_paired_wilcoxon(10, 1.0, n_sim=400) > s.power_paired_wilcoxon(6, 1.0, n_sim=400)


def test_twfe_recovers_effect_without_noise():
    rows = [{"sme": f"S{u}", "period": p, "treated": int(p >= st), "y": 0.1 * u + 0.05 * p + 0.3 * int(p >= st)}
            for u, st in enumerate([2, 3, 4, 3]) for p in range(1, 6)]
    assert s.staggered_did(pd.DataFrame(rows), "y")["effect"] == pytest.approx(0.3, abs=1e-9)
