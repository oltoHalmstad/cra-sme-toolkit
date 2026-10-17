import pytest

from crasme import e3


def test_latin_square_balance():
    alloc = e3.allocate([f"R{i}" for i in range(6)], [f"S{i}" for i in range(12)], seed=1)
    assert e3.check_balance(alloc) == {"rater_condition_counts_equal": True,
                                       "every_scenario_in_every_condition": True, "no_repeat_ratings": True}
    assert len(alloc) == 6 * 12


def test_allocation_requires_multiples_of_three():
    with pytest.raises(ValueError):
        e3.allocate(["a", "b"], ["s1", "s2", "s3"])


def test_allocation_is_reproducible():
    a1 = e3.allocate(["a", "b", "c"], ["1", "2", "3"], seed=5)
    a2 = e3.allocate(["a", "b", "c"], ["1", "2", "3"], seed=5)
    assert a1.equals(a2)


@pytest.mark.slow
def test_analysis_recovers_simulated_effect():
    alloc = e3.allocate([f"R{i}" for i in range(9)], [f"S{i:02d}" for i in range(48)])
    df, ref = e3.simulate(alloc, {"A": 1.3, "B": 0.4, "C": 0.4}, seed=3)
    d = e3.delta_alpha(df, "B", "A", n_boot=200)
    assert d["point"] > 0 and d["supported"]
    m = e3.deviation_model(df, ref)
    key = next(k for k in m["coef"] if "[T.B]" in k)
    assert m["coef"][key] < 0          # B reduces absolute deviation from the reference
