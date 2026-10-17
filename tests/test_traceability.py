import json

import pytest

from conftest import ROOT
from crasme import traceability as t


def unit(**kw):
    base = dict(product_id="DEMO-001", build_id="abc123", requirement_id="P2-1", applicable=True,
                applicability_justification="SBOM required for all products", status="verified",
                control_id="C-SBOM", test_id="T-SBOM-01", evidence_uri="sbom.cdx.json",
                evidence_sha256="0" * 64, evidence_generated_at="2026-10-10T10:00:00Z", tool="cdxgen 12.8.6",
                owner="dev lead", reviewer="security lead", reviewed_at="2026-10-11T09:00:00Z")
    base.update(kw)
    return t.TraceUnit(**base)


def test_schema_accepts_valid_and_rejects_invalid():
    assert t.validate_units([unit().to_dict()]) == []
    bad = unit(applicable=False, applicability_justification="", status="not_applicable").to_dict()
    assert t.validate_units([bad])
    bad2 = unit(evidence_sha256="xyz").to_dict()
    assert t.validate_units([bad2])


def test_completeness_requires_human_review():
    assert unit().is_complete()
    assert not unit(reviewer="").is_complete()
    assert not unit(status="implemented").is_complete()


def test_coverage_counts_missing_decisions_as_gaps():
    units = [unit(), unit(requirement_id="P2-2", test_id="")]
    cov = t.coverage(units, {"P2-1", "P2-2", "P2-3"})
    assert cov["missing_decisions"] == ["P2-3"]
    assert cov["gaps"] == ["P2-2"]
    assert cov["coverage"] == pytest.approx(1 / 3)


def test_unjustified_not_applicable_flagged():
    cov = t.coverage([unit(applicable=False, applicability_justification=" ", status="not_applicable")])
    assert cov["unjustified_not_applicable"] == ["P2-1"]


def test_freshness_detects_stale_evidence():
    f = t.freshness([unit(), unit(requirement_id="P2-3", evidence_generated_at="2026-10-20T00:00:00Z")],
                    last_change_at="2026-10-15T00:00:00Z")
    assert f["stale"] == ["P2-1"]
    assert f["stale_share"] == 0.5


def test_release_gate_ignores_scores_and_blocks_exploitable():
    units = [unit()]
    g = t.release_gate(units, {"P2-1"}, [{"id": "CVE-2021-44906", "exploitable": True}], "abc123")
    assert not g["release_allowed"]
    assert any("CVE-2021-44906" in b for b in g["blockers"])


def test_release_gate_blocks_on_build_mismatch_and_missing_decision():
    g = t.release_gate([unit()], {"P2-1", "RA-01"}, [], "def456")
    assert len(g["blockers"]) == 2


def test_release_gate_passes_when_complete():
    assert t.release_gate([unit()], {"P2-1"}, [], "abc123")["release_allowed"]


def test_hash_verification_detects_tampering(tmp_path):
    ev = tmp_path / "sbom.cdx.json"
    ev.write_text('{"bomFormat":"CycloneDX"}')
    u = unit(evidence_sha256=t.sha256_file(ev))
    assert t.verify_hashes([u], tmp_path) == {"P2-1": True}
    ev.write_text('{"bomFormat":"CycloneDX","tampered":true}')
    assert t.verify_hashes([u], tmp_path) == {"P2-1": False}


def test_example_trace_file_is_schema_valid():
    p = ROOT / "examples" / "trace-units.example.json"
    assert t.validate_units(json.loads(p.read_text())) == []


def test_freshness_affected_subset():
    units = [unit(), unit(requirement_id="SUP-01")]
    f = t.freshness(units, "2026-10-15T00:00:00Z", affected={"P2-1"})
    assert f["stale"] == ["P2-1"] and f["stale_share"] == 1.0
