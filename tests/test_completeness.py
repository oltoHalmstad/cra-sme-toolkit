"""E9-G completeness rules (post-hoc): unit tests."""
from crasme import completeness as C
from crasme.replay import Pkg


def test_purl_key_normalises_ecosystems():
    assert C.purl_key("pkg:npm/%40alloc/quick-lru@5.2.0") == ("npm", "@alloc/quick-lru")
    assert C.purl_key("pkg:maven/org.springframework/spring-beans@6.2.9") == ("Maven", "org.springframework:spring-beans")
    assert C.purl_key("pkg:golang/github.com/gin-gonic/gin@v1.9.0") == ("Go", "github.com/gin-gonic/gin")
    assert C.purl_key("pkg:pypi/Django@4.2") == ("PyPI", "django")
    assert C.purl_key("pkg:github/actions/checkout@v4") is None


def test_rules_fire_only_on_incomplete_evidence():
    inv = [Pkg("npm", f"p{i}", "1.0.0") for i in range(20)]
    ind = [("npm", f"p{i}") for i in range(20)]
    assert C.check(inv, "lockfile", "npm", ind) == []
    codes = lambda r: {x["code"] for x in r}  # noqa: E731
    assert codes(C.check(inv[:5], "lockfile", "npm", ind)) == {"INVENTORY_CROSSCHECK_LOW"}
    assert "INVENTORY_ECOSYSTEM_MISSING" in codes(C.check([Pkg("PyPI", "x", "1")], "lockfile", "npm", ind))
    assert "INVENTORY_METHOD_INCOMPLETE" in codes(C.check(inv, "no-package-manifest (C)", "c", []))
    # too few independent components -> no cross-check verdict
    assert C.check(inv[:1], "lockfile", "npm", ind[:5]) == []


def test_e9g_results_are_recorded():
    import json
    from conftest import ROOT
    r = json.loads((ROOT / "experiments/e9_release_replay/results/e9g-posthoc/E9G.json").read_text())
    assert r["label"].startswith("E9-G POST-HOC")
    assert r["A_natural"]["pass_on_known_incomplete"]["G3"]["k"] == 0
    assert r["B_seeded"]["baseline_reproduces_registered_decisions"] == "26/26"
