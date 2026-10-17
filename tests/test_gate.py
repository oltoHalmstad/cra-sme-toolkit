"""Release-decision engine: positive path, all seeded negative scenarios, CLI and schema."""
import json
import shutil
import sys

import jsonschema
import pytest

from conftest import ROOT
from crasme import gate
from crasme.demo import build_baseline
from crasme.mutation import MUTATIONS, run_suite

DECISION_SCHEMA = json.loads((ROOT / "schemas" / "release_decision.schema.json").read_text())


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    return build_baseline(tmp_path_factory.mktemp("bundle") / "b")


def test_baseline_passes_and_is_schema_valid(baseline):
    b, cat, pol, as_of = baseline
    d = gate.evaluate(b, pol, as_of, cat)
    assert d["decision"] == gate.PASS, d["reasons"]
    assert d["legal_conformity"] == "NOT_DETERMINED_BY_TOOL"
    assert d["eligible_for_human_conformity_review"] is True
    jsonschema.validate(d, DECISION_SCHEMA)


@pytest.mark.parametrize("m", MUTATIONS, ids=[m.mid for m in MUTATIONS])
def test_seeded_fault_never_passes(baseline, tmp_path, m):
    b, cat, pol, as_of = baseline
    d = tmp_path / "m"
    shutil.copytree(b, d)
    c = [dict(r) for r in cat]
    p = json.loads(json.dumps(pol))
    m.apply(d, c, p)
    res = gate.evaluate(d, p, as_of, c)
    assert res["decision"] == m.expect_decision, (m.description, res["reasons"])
    assert m.expect_code in [x["code"] for x in res["details"]]
    jsonschema.validate(res, DECISION_SCHEMA)


def test_suite_metrics():
    s = run_suite()["summary"]
    assert s["baseline_decision"] == gate.PASS
    assert s["false_green"] == 0 and s["freshness_recall"] == 1.0
    assert s["legacy_v11_false_green_rate"] > 0.5   # documents the v1.1 weakness the suite was built to catch


def test_unverified_catalogue_blocks_pass(baseline):
    b, cat, pol, as_of = baseline
    d = gate.evaluate(b, pol, as_of)                 # shipped catalogue: all rows legally unverified
    assert d["decision"] == gate.REVIEW and "LEGAL_MAPPING_REVIEW_PENDING" in d["reasons"]


def test_obligations_not_in_force_are_info_only(baseline, tmp_path):
    from datetime import datetime, timezone
    b, cat, pol, _ = baseline
    d = gate.evaluate(b, pol, datetime(2026, 10, 17, tzinfo=timezone.utc), cat)
    codes = {x["code"]: x["severity"] for x in d["details"]}
    assert codes.get("OBLIGATIONS_NOT_YET_IN_FORCE") == "INFO"
    assert d["stats"]["mandatory_obligations_not_yet_in_force"] > 30


def test_risk_scores_are_not_an_input():
    import inspect
    src = inspect.getsource(gate)
    assert "inherent" not in src and "risk_register" not in src


def test_cli_exit_codes_and_report(baseline, tmp_path):
    b, cat, pol, as_of = baseline
    d = tmp_path / "b"
    shutil.copytree(b, d)
    catf = tmp_path / "cat.csv"
    import csv
    with open(catf, "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(cat[0].keys()))
        wr.writeheader()
        wr.writerows(cat)
    args = ["--bundle", str(d), "--catalogue", str(catf), "--as-of", as_of.isoformat(), "--report", str(tmp_path / "r.md")]
    assert gate.main(args) == 0
    assert "PASS" in (tmp_path / "r.md").read_text()
    (d / "kev.json").write_text('{"catalogVersion": "x", "vulnerabilities": []}')   # tampered after recording
    assert gate.main(args) == 1
    shutil.rmtree(d)
    d.mkdir()
    assert gate.main(args) == 2                        # empty bundle -> REVIEW_REQUIRED


def test_ci_wrapper_importable():
    sys.path.insert(0, str(ROOT / "tools"))
    import ci_gate  # noqa: F401


def test_shipped_demo_bundle_decision_is_review_for_legal_pending():
    d = json.loads((ROOT / "examples" / "demo-release" / "decision.json").read_text())
    assert d["decision"] == "REVIEW_REQUIRED" and d["reasons"] == ["LEGAL_MAPPING_REVIEW_PENDING"]
    jsonschema.validate(d, DECISION_SCHEMA)
