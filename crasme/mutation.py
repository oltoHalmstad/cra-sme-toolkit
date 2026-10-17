"""Seeded-fault (mutation) suite for the release-decision engine (E4/E7, rec. P2-03).

Each mutation plants exactly one fault into a valid baseline bundle. Metrics:
  false-green rate        = mutated bundles decided PASS / mutated bundles
  correct-code rate       = mutations where the expected reason code was reported
  freshness recall        = stale-evidence mutations detected / stale-evidence mutations
  baseline false-red      = baseline (fault-free) bundle not decided PASS

The faults are synthetic; this measures the engine's logic, not real-world prevalence.
"""
from __future__ import annotations

import csv
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .demo import FAKE_KEV_ID, PRODUCT, build_baseline, record_scan
from .gate import FAIL, PASS, REVIEW, evaluate
from .scanstatus import ScanManifest
from .traceability import sha256_file


def _j(p: Path):
    return json.loads(p.read_text())


def _w(p: Path, o):
    p.write_text(json.dumps(o, indent=1))


def _scan(b: Path, name: str, **kw):
    m = ScanManifest.load(b / "scan-status.json")
    for s in m.scans:
        if s.name == name:
            for k, v in kw.items():
                setattr(s, k, v)
    m.save(b / "scan-status.json")


def _rescan(b: Path, name, tool, kind, fname, exit_code=0):
    m = ScanManifest.load(b / "scan-status.json")
    record_scan(m, name, tool, kind, b / fname, exit_code,
                inputs=[b / "sbom.cdx.json"] if name == "vulns" and (b / "sbom.cdx.json").exists() else None)
    m.save(b / "scan-status.json")


def _units(b: Path, fn):
    u = _j(b / "trace-units.json")
    fn(u)
    _w(b / "trace-units.json", u)


def _first_applicable(u):
    return next(x for x in u if x["applicable"])


def _add_kev_finding(b: Path, vex_status=None, justification=None):
    v = _j(b / "vulns.json")
    v["Results"][0]["Vulnerabilities"].append({"VulnerabilityID": FAKE_KEV_ID, "PkgName": "lodash",
                                               "InstalledVersion": "4.17.21", "Severity": "HIGH"})
    _w(b / "vulns.json", v)
    _rescan(b, "vulns", "trivy", "trivy", "vulns.json")
    _refresh_manifest_hash(b, "vulns.json")
    if vex_status:
        st = {"vulnerability": {"name": FAKE_KEV_ID}, "status": vex_status}
        if justification:
            st["justification"] = justification
        _w(b / "vex.json", {"statements": [st]})


def _refresh_manifest_hash(b: Path, fname):
    m = _j(b / "evidence-manifest.json")
    for r in m["records"]:
        if r["evidence_uri"] == fname:
            r["evidence_sha256"] = sha256_file(b / fname)
    _w(b / "evidence-manifest.json", m)


def _evidence(b: Path, fn):
    m = _j(b / "evidence-manifest.json")
    fn(m["records"])
    _w(b / "evidence-manifest.json", m)


def _approval(b: Path, role, **kw):
    a = _j(b / "approvals.json")
    for x in a:
        if x["role"] == role:
            x.update(kw)
    _w(b / "approvals.json", a)


@dataclass
class Mutation:
    mid: str
    category: str
    description: str
    expect_decision: str
    expect_code: str
    apply: Callable[[Path, list, dict], None]
    stale: bool = False


def _m(mid, cat, desc, dec, code, stale=False):
    def deco(fn):
        MUTATIONS.append(Mutation(mid, cat, desc, dec, code, fn, stale))
        return fn
    return deco


MUTATIONS: list[Mutation] = []

# --- scanner / feed availability (P0-01) -------------------------------------
_m("M01", "scan", "KEV feed download failed (curl error)", REVIEW, "KEV_FEED_UNAVAILABLE")(
    lambda b, c, p: _scan(b, "kev", execution_status="FAILED", exit_code=6, error_code="EXIT_6"))
_m("M02", "scan", "KEV feed empty (v1.1 fallback {'vulnerabilities': []})", REVIEW, "KEV_FEED_UNAVAILABLE")(
    lambda b, c, p: (_w(b / "kev.json", {"catalogVersion": "x", "vulnerabilities": []}), _rescan(b, "kev", "curl", "kev", "kev.json")))
_m("M03", "scan", "KEV feed truncated (count mismatch)", REVIEW, "KEV_FEED_UNAVAILABLE")(
    lambda b, c, p: (_w(b / "kev.json", {"catalogVersion": "x", "count": 1500, "vulnerabilities": [{"cveID": FAKE_KEV_ID}]}),
                     _rescan(b, "kev", "curl", "kev", "kev.json")))
_m("M04", "scan", "Vulnerability scanner exited with error code 2", REVIEW, "SCAN_FAILED")(
    lambda b, c, p: _rescan(b, "vulns", "trivy", "trivy", "vulns.json", exit_code=2))
_m("M05", "scan", "Vulnerability scanner output file missing", REVIEW, "SCAN_OUTPUT_MISSING")(
    lambda b, c, p: ((b / "vulns.json").unlink(), _rescan(b, "vulns", "trivy", "trivy", "vulns.json")))
_m("M06", "scan", "Trivy JSON truncated/malformed", REVIEW, "SCAN_OUTPUT_INVALID")(
    lambda b, c, p: ((b / "vulns.json").write_text('{"SchemaVersion": 2, "Results": [{"Tar'),
                     _rescan(b, "vulns", "trivy", "trivy", "vulns.json"), _refresh_manifest_hash(b, "vulns.json")))
_m("M07", "scan", "SBOM generator produced an empty SBOM", REVIEW, "SCAN_OUTPUT_INVALID")(
    lambda b, c, p: (_w(b / "sbom.cdx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}),
                     _rescan(b, "sbom", "action", "cyclonedx", "sbom.cdx.json"), _refresh_manifest_hash(b, "sbom.cdx.json")))
_m("M08", "scan", "Required scan never recorded", REVIEW, "SCAN_NOT_RECORDED")(
    lambda b, c, p: (lambda m: (setattr(m, "scans", [s for s in m.scans if s.name != "sbom"]), m.save(b / "scan-status.json")))(
        ScanManifest.load(b / "scan-status.json")))
_m("M09", "scan", "Scan-status manifest from another build", REVIEW, "SCAN_MANIFEST_WRONG_BUILD")(
    lambda b, c, p: (lambda m: (setattr(m, "build_sha", "0" * 40), m.save(b / "scan-status.json")))(
        ScanManifest.load(b / "scan-status.json")))
_m("M10", "scan", "Scan output edited after recording", FAIL, "SCAN_OUTPUT_TAMPERED")(
    lambda b, c, p: (b / "vulns.json").write_text((b / "vulns.json").read_text().replace("LOW", "NONE")))
_m("M11", "scan", "Scan timed out", REVIEW, "SCAN_TIMEOUT")(
    lambda b, c, p: _scan(b, "sbom", execution_status="TIMEOUT", error_code="TIMEOUT"))
# --- findings -----------------------------------------------------------------
_m("M12", "finding", "KEV-listed component, reachability unknown (no VEX)", REVIEW, "KEV_TRIAGE_PENDING")(
    lambda b, c, p: _add_kev_finding(b))
_m("M13", "finding", "KEV-listed component, VEX affected", FAIL, "KNOWN_EXPLOITED_AFFECTED")(
    lambda b, c, p: _add_kev_finding(b, "affected"))
_m("M14", "finding", "KEV-listed component, VEX not_affected without justification", REVIEW, "KEV_NOT_AFFECTED_UNJUSTIFIED")(
    lambda b, c, p: _add_kev_finding(b, "not_affected"))
_m("M15", "finding", "Untriaged CRITICAL finding", REVIEW, "FINDING_UNTRIAGED")(
    lambda b, c, p: (lambda v: (v["Results"][0]["Vulnerabilities"].__setitem__(0, dict(v["Results"][0]["Vulnerabilities"][0], Severity="CRITICAL")),
                                _w(b / "vulns.json", v), _rescan(b, "vulns", "trivy", "trivy", "vulns.json"),
                                _refresh_manifest_hash(b, "vulns.json")))(_j(b / "vulns.json")))
# --- evidence lineage / freshness (P0-04) ---------------------------------------
_m("M16", "evidence", "Evidence record bound to another product", REVIEW, "EVIDENCE_WRONG_PRODUCT")(
    lambda b, c, p: _evidence(b, lambda r: r[0].update(product_id="OTHER-002")))
_m("M17", "evidence", "Evidence record from an older build", REVIEW, "EVIDENCE_WRONG_BUILD", stale=True)(
    lambda b, c, p: _evidence(b, lambda r: r[2].update(build_sha="9" * 40)))
_m("M18", "evidence", "Evidence for another artifact digest of same build id", REVIEW, "EVIDENCE_WRONG_BUILD", stale=True)(
    lambda b, c, p: _evidence(b, lambda r: r[3].update(artifact_digest="sha256:" + "cd" * 32)))
_m("M19", "evidence", "Evidence record without build identifier", REVIEW, "EVIDENCE_UNBOUND")(
    lambda b, c, p: _evidence(b, lambda r: r[4].pop("build_sha")))
_m("M20", "evidence", "Evidence file replaced after hashing", FAIL, "EVIDENCE_INTEGRITY_FAILED")(
    lambda b, c, p: (b / _j(b / "evidence-manifest.json")["records"][5]["evidence_uri"]).write_text("forged"))
_m("M21", "evidence", "Evidence file deleted", REVIEW, "EVIDENCE_FILE_MISSING")(
    lambda b, c, p: (b / _j(b / "evidence-manifest.json")["records"][6]["evidence_uri"]).unlink())
_m("M22", "evidence", "Lockfile changed after SBOM was produced", REVIEW, "EVIDENCE_STALE_INPUT_CHANGED", stale=True)(
    lambda b, c, p: (lambda pr: (pr["input_digests"].update(lockfile="22" * 32), _w(b / "product.json", pr)))(_j(b / "product.json")))
_m("M23", "evidence", "Evidence older than internal freshness rule (30 d)", REVIEW, "EVIDENCE_STALE_AGE", stale=True)(
    lambda b, c, p: (p["evidence_max_age_days"].update(document=30),
                     _evidence(b, lambda r: r[7].update(generated_at="2027-10-01T00:00:00+00:00"))))
_m("M24", "evidence", "Evidence manifest missing", REVIEW, "EVIDENCE_MANIFEST_MISSING")(
    lambda b, c, p: (b / "evidence-manifest.json").unlink())
# --- obligations (P0-02 / P0-03) ---------------------------------------------------
_m("M25", "obligation", "Mandatory obligation has no applicability decision (risk register says Low)", REVIEW, "APPLICABILITY_DECISION_MISSING")(
    lambda b, c, p: (_units(b, lambda u: u.remove(_first_applicable(u))),
                     _w(b / "risk-register.json", [{"risk_id": "R1", "inherent": 4, "band": "Low"}])))
_m("M26", "obligation", "Obligation marked N/A without rationale", REVIEW, "NA_WITHOUT_RATIONALE")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(applicable=False, applicability_justification="",
                                                                     status="not_applicable", reviewer="")))
_m("M27", "obligation", "Obligation recorded as failed", FAIL, "OBLIGATION_NOT_MET")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(status="failed")))
_m("M28", "obligation", "Obligation evidence not reviewed", REVIEW, "OBLIGATION_EVIDENCE_INCOMPLETE")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(reviewer="")))
_m("M29", "obligation", "Obligation evidence from an older build", REVIEW, "OBLIGATION_EVIDENCE_WRONG_BUILD", stale=True)(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(build_id="8" * 40)))
_m("M30", "obligation", "Obligation evidence hash not in manifest", REVIEW, "OBLIGATION_EVIDENCE_NOT_IN_MANIFEST")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(evidence_sha256="0" * 64)))
_m("M31", "obligation", "One mandatory legal mapping not verified", REVIEW, "LEGAL_MAPPING_REVIEW_PENDING")(
    lambda b, c, p: next(r for r in c if r["req_id"] == "P1-a").update(legal_status="unverified"))
# --- approvals --------------------------------------------------------------------
_m("M32", "approval", "Security-lead approval expired", REVIEW, "APPROVAL_EXPIRED")(
    lambda b, c, p: _approval(b, "security_lead", expires_at="2027-12-01T00:00:00+00:00"))
_m("M33", "approval", "Product-owner approval revoked", REVIEW, "APPROVAL_REVOKED")(
    lambda b, c, p: _approval(b, "product_owner", revoked=True))
_m("M34", "approval", "Approval given for previous build", REVIEW, "APPROVAL_WRONG_BUILD")(
    lambda b, c, p: _approval(b, "security_lead", build_sha="7" * 40))
_m("M35", "approval", "Approvals file missing", REVIEW, "APPROVAL_MISSING")(
    lambda b, c, p: (b / "approvals.json").unlink())
# --- bundle / engine ---------------------------------------------------------------
_m("M36", "bundle", "product.json missing", REVIEW, "PRODUCT_RECORD_MISSING")(
    lambda b, c, p: (b / "product.json").unlink())
_m("M37", "bundle", "trace-units.json corrupted (engine error path)", REVIEW, "ENGINE_ERROR")(
    lambda b, c, p: (b / "trace-units.json").write_text("[{not json"))


# --- added after adversarial review (v1.2) ------------------------------------------
_m("M38", "policy", "Policy removes the KEV feed from required scans", REVIEW, "POLICY_BELOW_MINIMUM")(
    lambda b, c, p: p.update(required_scans=["sbom", "vulns"]))
_m("M39", "policy", "Policy requires no human approval", REVIEW, "POLICY_BELOW_MINIMUM")(
    lambda b, c, p: p.update(required_approval_roles=[]))
_m("M40", "obligation", "Obligation cites a valid evidence file declared for another requirement", REVIEW, "OBLIGATION_EVIDENCE_MISATTRIBUTED")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(evidence_sha256=_j(b / "evidence-manifest.json")["records"][0]["evidence_sha256"])))
_m("M41", "obligation", "Duplicate trace units: a failed one shadowed by a verified one", REVIEW, "TRACE_UNIT_DUPLICATE")(
    lambda b, c, p: _units(b, lambda u: u.insert(0, dict(_first_applicable(u), status="failed"))))
_m("M42", "obligation", "Catalogue row with unparsable application date", REVIEW, "CATALOGUE_ROW_INVALID")(
    lambda b, c, p: next(r for r in c if r["req_id"] == "P1-b").update(applies_from="TBD"))
_m("M43", "approval", "Approval without expiry date", REVIEW, "APPROVAL_NO_EXPIRY")(
    lambda b, c, p: _approval(b, "product_owner", expires_at=None))
_m("M44", "approval", "Valid approval plus a later revocation for the same build", REVIEW, "APPROVAL_REVOKED")(
    lambda b, c, p: (lambda a: (a.append(dict(next(x for x in a if x["role"] == "security_lead"), revoked=True)),
                                _w(b / "approvals.json", a)))(_j(b / "approvals.json")))
_m("M45", "scan", "Scan recorded OK but without output digest", REVIEW, "SCAN_RECORD_INCOMPLETE")(
    lambda b, c, p: _scan(b, "vulns", output_digest=None))


# --- added after independent adversarial review (v1.2) -------------------------------
def _resign(b, name, fname):
    m = ScanManifest.load(b / "scan-status.json")
    for sc in m.scans:
        if sc.name == name:
            sc.output_path = fname
            sc.output_digest = __import__("hashlib").sha256((b / fname).read_bytes()).hexdigest()
    m.save(b / "scan-status.json")


_m("M46", "scan", "KEV record re-pointed at vulns.json with recomputed digest", REVIEW, "KEV_FEED_UNAVAILABLE")(
    lambda b, c, p: _resign(b, "kev", "vulns.json"))
_m("M47", "scan", "KEV feed emptied and digest recomputed (status left OK)", REVIEW, "KEV_FEED_UNAVAILABLE")(
    lambda b, c, p: (_w(b / "kev.json", {"catalogVersion": "x", "vulnerabilities": []}), _resign(b, "kev", "kev.json")))
_m("M48", "scan", "Trivy report with no targets (Results: [])", REVIEW, "SCAN_OUTPUT_INVALID")(
    lambda b, c, p: (_w(b / "vulns.json", {"SchemaVersion": 2, "ArtifactName": "sbom", "Results": []}),
                     _resign(b, "vulns", "vulns.json"), _refresh_manifest_hash(b, "vulns.json")))
_m("M49", "scan", "Vulnerability scan not bound to this bundle's SBOM", REVIEW, "SCAN_INPUT_UNBOUND")(
    lambda b, c, p: _scan(b, "vulns", input_digest="0" * 64))
_m("M50", "scan", "Scan snapshot two years old", REVIEW, "SCAN_STALE")(
    lambda b, c, p: _scan(b, "vulns", finished_at="2025-12-01T00:00:00+00:00"))
_m("M51", "finding", "Secret detected by the fs scan", REVIEW, "SECRET_FINDING")(
    lambda b, c, p: (lambda m: (_w(b / "trivy-fs.json", {"SchemaVersion": 2, "ArtifactName": ".", "Results": [
        {"Target": "app/config.py", "Secrets": [{"RuleID": "aws-access-key-id", "StartLine": 3, "Match": "***REDACTED***"}]}]}),
        record_scan(m, "fs", "trivy", "trivy", b / "trivy-fs.json"), m.save(b / "scan-status.json")))(ScanManifest.load(b / "scan-status.json")))
_m("M52", "finding", "VEX 'fixed' while the scan still detects the KEV vulnerability", REVIEW, "VEX_CONTRADICTS_SCAN")(
    lambda b, c, p: _add_kev_finding(b, "fixed"))
_m("M53", "finding", "VEX statement for another product", REVIEW, "KEV_TRIAGE_PENDING")(
    lambda b, c, p: (_add_kev_finding(b), _w(b / "vex.json", {"statements": [{"vulnerability": {"name": FAKE_KEV_ID},
        "products": [{"@id": "OTHER-002"}], "status": "not_affected", "justification": "component_not_present"}]})))
_m("M54", "finding", "Finding identified only by GHSA id (KEV status unknowable)", REVIEW, "KEV_STATUS_UNKNOWN")(
    lambda b, c, p: (lambda v: (v["Results"][0]["Vulnerabilities"].append({"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "PkgName": "lodash",
        "InstalledVersion": "4.17.21", "Severity": "LOW"}), _w(b / "vulns.json", v), _rescan(b, "vulns", "trivy", "trivy", "vulns.json"),
        _refresh_manifest_hash(b, "vulns.json")))(_j(b / "vulns.json")))
_m("M55", "obligation", "Conditional obligation without any decision", REVIEW, "APPLICABILITY_DECISION_MISSING")(
    lambda b, c, p: _units(b, lambda u: u.remove(next(x for x in u if x["requirement_id"] == "OSS-01"))))
_m("M56", "obligation", "N/A decision bound to another product/build", REVIEW, "OBLIGATION_EVIDENCE_WRONG_BUILD")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(applicable=False, status="not_applicable",
                                                                     product_id="OTHER", build_id="0" * 40)))
_m("M57", "obligation", "Obligation review timestamp before the evidence existed", REVIEW, "OBLIGATION_REVIEW_INVALID")(
    lambda b, c, p: _units(b, lambda u: _first_applicable(u).update(reviewed_at="2020-01-01T00:00:00Z")))
_m("M58", "obligation", "One evidence record claimed for every obligation", REVIEW, "EVIDENCE_OVERCLAIMED")(
    lambda b, c, p: _evidence(b, lambda r: r[0].update(requirement_ids=[x["requirement_id"] for x in _j(b / "trace-units.json")])))
_m("M59", "catalogue", "Catalogue edited without updating the pinned digest", REVIEW, "CATALOGUE_DIGEST_MISMATCH")(
    lambda b, c, p: next(r for r in c if r["req_id"] == "P1-j").update(mandatory="N"))
_m("M60", "catalogue", "Catalogue gate value mistyped", REVIEW, "CATALOGUE_ROW_INVALID")(
    lambda b, c, p: next(r for r in c if r["req_id"] == "P1-k").update(gate="Pre-market"))
_m("M61", "policy", "Policy disables verified-legal-mapping requirement", REVIEW, "POLICY_BELOW_MINIMUM")(
    lambda b, c, p: p.update(require_verified_legal_mapping=False))
_m("M62", "policy", "Policy does not pin the catalogue", REVIEW, "CATALOGUE_NOT_PINNED")(
    lambda b, c, p: p.update(catalogue_sha256=None))
_m("M63", "evidence", "Evidence declares lockfile digest but product record has none", REVIEW, "EVIDENCE_INPUT_UNVERIFIABLE")(
    lambda b, c, p: (lambda pr: (pr.pop("input_digests"), _w(b / "product.json", pr)))(_j(b / "product.json")))
_m("M64", "evidence", "Evidence timestamp in the future", REVIEW, "EVIDENCE_TIMESTAMP_INVALID")(
    lambda b, c, p: _evidence(b, lambda r: r[9].update(generated_at="2099-01-01T00:00:00+00:00")))
_m("M65", "approval", "Approval for the same build but another product", REVIEW, "APPROVAL_WRONG_BUILD")(
    lambda b, c, p: _approval(b, "product_owner", product_id="OTHER-999"))
_m("M66", "approval", "One person holds both approval roles", REVIEW, "APPROVAL_SAME_REVIEWER")(
    lambda b, c, p: _approval(b, "product_owner", reviewer="S. Lead"))
_m("M67", "approval", "Approval valid for 20 years", REVIEW, "APPROVAL_INVALID")(
    lambda b, c, p: _approval(b, "security_lead", expires_at="2047-12-19T12:00:00+00:00"))
_m("M68", "approval", "Approval dated after the assessment time", REVIEW, "APPROVAL_INVALID")(
    lambda b, c, p: _approval(b, "security_lead", approved_at="2030-01-01T00:00:00+00:00"))
_m("M69", "bundle", "product.json does not match the CI build (expect-build)", REVIEW, "PRODUCT_RECORD_MISMATCH")(
    lambda b, c, p: p.update(_expect_build="f" * 40))


def legacy_v11_decision(b: Path) -> str:
    """Decision the v1.1 CI gate (tools/legacy/ci_gate_v1_1.py) would reach on the same bundle.

    v1.1 logic: union of Trivy/OSV findings; block only on KEV hits; a missing/invalid file is
    silently treated as "no findings" and the empty-KEV fallback means "nothing exploited".
    """
    import sys as _sys
    legacy = Path(__file__).resolve().parent.parent / "tools" / "legacy"
    _sys.path.insert(0, str(legacy))
    import ci_gate_v1_1 as g  # type: ignore
    from .vulns import parse_trivy
    try:
        findings = g.load(str(b / "vulns.json"), parse_trivy)
    except (json.JSONDecodeError, OSError):
        return "ERROR"           # v1.1 crashes -> CI red (not green), counted as not PASS
    try:
        kev = {v["cveID"].upper() for v in json.loads((b / "kev.json").read_text()).get("vulnerabilities", [])}
    except (json.JSONDecodeError, OSError):
        kev = set()              # v1.1 workflow: curl failure -> '{"vulnerabilities":[]}' fallback
    return PASS if g.evaluate(findings, kev)["release_allowed"] else FAIL


def run_suite(out_csv: str | Path | None = None) -> dict:
    rows = []
    with tempfile.TemporaryDirectory() as td:
        base, cat, pol, as_of = build_baseline(Path(td) / "baseline")
        baseline = evaluate(base, pol, as_of, cat)
        for m in MUTATIONS:
            d = Path(td) / m.mid
            shutil.copytree(base, d)
            c = [dict(r) for r in cat]
            p = json.loads(json.dumps(pol))
            m.apply(d, c, p)
            eb = p.pop("_expect_build", None)
            res = evaluate(d, p, as_of, c, expect_build=eb)
            legacy = legacy_v11_decision(d)
            rows.append({"legacy_v11_decision": legacy, "legacy_v11_false_green": legacy == PASS,"mutation": m.mid, "category": m.category, "description": m.description,
                         "expected_decision": m.expect_decision, "decision": res["decision"],
                         "expected_code": m.expect_code, "code_reported": m.expect_code in [x["code"] for x in res["details"]],
                         "false_green": res["decision"] == PASS, "decision_matches": res["decision"] == m.expect_decision,
                         "stale_case": m.stale, "all_codes": " ".join(res["reasons"])})
    n = len(rows)
    stale = [r for r in rows if r["stale_case"]]
    summary = {"baseline_decision": baseline["decision"], "baseline_reasons": baseline["reasons"],
               "mutations": n, "false_green": sum(r["false_green"] for r in rows),
               "false_green_rate": sum(r["false_green"] for r in rows) / n,
               "decision_match_rate": sum(r["decision_matches"] for r in rows) / n,
               "correct_code_rate": sum(r["code_reported"] for r in rows) / n,
               "freshness_recall": (sum(r["decision"] != PASS for r in stale) / len(stale)) if stale else None,
               "legacy_v11_false_green": sum(r["legacy_v11_false_green"] for r in rows),
               "legacy_v11_false_green_rate": sum(r["legacy_v11_false_green"] for r in rows) / n,
               "legacy_v11_freshness_recall": (sum(not r["legacy_v11_false_green"] for r in stale) / len(stale)) if stale else None}
    if out_csv:
        with open(out_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    return {"summary": summary, "rows": rows}
