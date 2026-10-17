"""Build a SYNTHETIC, fully consistent release bundle for DEMO-001.

Used by the mutation suite (E4/E7), tests and documentation. Every value is
invented; the KEV feed contains a deliberately fake CVE-like ID.

    bundle, catalogue, policy, as_of = build_baseline(tmpdir)
    evaluate(bundle, policy, as_of, catalogue)["decision"] == "PASS"
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .gate import DEFAULT_POLICY, applies_from, catalogue_digest, load_catalogue
from .scanstatus import ScanManifest, ScanRecord, classify, digest_paths
from .traceability import sha256_file

PRODUCT = {"product_id": "DEMO-001", "product_version": "1.2.0", "build_sha": "3f2c9e1d" * 5,
           "artifact_digest": "sha256:" + "ab" * 32, "synthetic": True}
AS_OF = datetime(2027, 12, 20, 12, 0, tzinfo=timezone.utc)      # after full CRA application
FAKE_KEV_ID = "CVE-0000-00001"                                   # not a real CVE


def _write(p: Path, obj) -> Path:
    p.write_text(json.dumps(obj, indent=1) if not isinstance(obj, str) else obj, encoding="utf-8")
    return p


def verified_catalogue() -> list[dict]:
    """Catalogue copy with every row marked verified by a TEST FIXTURE reviewer (never ship this)."""
    cat = copy.deepcopy(load_catalogue())
    for r in cat:
        r.update(legal_status="verified", legal_reviewer="TEST FIXTURE — not a legal review",
                 legal_reviewed_date="2027-12-01")
    return cat


def release_relevant(catalogue, policy, as_of):
    gates = set(policy["obligation_gates"])
    out = []
    for r in catalogue:
        start = applies_from(r)
        if r["mandatory"] in ("Y", "conditional") and r["gate"] in gates and start and start <= as_of.date():
            out.append(r)
    return out


def record_scan(man: ScanManifest, name, tool, kind, path: Path, exit_code=0, required=True, version="1.0-demo",
                inputs: list[Path] | None = None):
    st, err, n = classify(tool, kind, exit_code, path)
    man.upsert(ScanRecord(name=name, tool=tool, kind=kind, required=required, execution_status=st,
                          tool_version=version, exit_code=exit_code, started_at="2027-12-19T10:00:00+00:00",
                          finished_at="2027-12-19T10:01:00+00:00", output_path=path.name,
                          output_digest=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
                          finding_count=n, error_code=err, input_digest=digest_paths(inputs) if inputs else None))


def evidence_record(path: Path, rids, tool="demo", etype=None, inputs=None, product=PRODUCT,
                    generated_at="2027-12-19T10:05:00+00:00"):
    return {"product_id": product["product_id"], "product_version": product["product_version"],
            "build_sha": product["build_sha"], "artifact_digest": product["artifact_digest"],
            "requirement_ids": rids, "evidence_type": etype or tool, "evidence_uri": path.name,
            "evidence_sha256": sha256_file(path), "input_digests": inputs or {}, "tool": tool,
            "tool_version": "1.0-demo", "generated_at": generated_at, "review_status": "reviewed"}


def build_baseline(root: str | Path):
    b = Path(root)
    b.mkdir(parents=True, exist_ok=True)
    product = dict(PRODUCT, input_digests={"lockfile": "11" * 32})
    _write(b / "product.json", product)
    _write(b / "sbom.cdx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        {"type": "library", "name": "express", "version": "4.21.2", "purl": "pkg:npm/express@4.21.2"}]})
    _write(b / "vulns.json", {"SchemaVersion": 2, "ArtifactName": "sbom.cdx.json", "Results": [
        {"Target": "sbom", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-0000-00002", "PkgName": "express", "InstalledVersion": "4.21.2", "Severity": "LOW"}]}]})
    fake = [{"cveID": FAKE_KEV_ID}] + [{"cveID": f"CVE-0000-{90000 + i}"} for i in range(1199)]   # invented IDs
    _write(b / "kev.json", {"title": "SYNTHETIC KEV snapshot (invented IDs)", "catalogVersion": "demo",
                            "count": len(fake), "vulnerabilities": fake})
    _write(b / "vex.json", {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []})
    man = ScanManifest(product["product_id"], product["build_sha"])
    record_scan(man, "sbom", "action", "cyclonedx", b / "sbom.cdx.json")
    record_scan(man, "vulns", "trivy", "trivy", b / "vulns.json", inputs=[b / "sbom.cdx.json"])
    record_scan(man, "kev", "curl", "kev", b / "kev.json")
    man.save(b / "scan-status.json")

    catalogue = verified_catalogue()
    policy = copy.deepcopy(DEFAULT_POLICY)
    policy["catalogue_sha256"] = catalogue_digest(catalogue)
    records = [evidence_record(b / "sbom.cdx.json", ["P2-1", "SC-01"], "syft", "sbom", {"lockfile": "11" * 32}),
               evidence_record(b / "vulns.json", ["P1-a", "P2-2"], "trivy", "vulns", {"lockfile": "11" * 32})]
    units = []
    for r in release_relevant(catalogue, policy, AS_OF):
        rid = r["req_id"]
        if r["mandatory"] == "conditional":
            units.append({"product_id": product["product_id"], "build_id": product["build_sha"], "requirement_id": rid,
                          "applicable": False, "applicability_justification": "Manufacturer is not an open-source steward (demo)",
                          "status": "not_applicable", "reviewer": "Compliance lead", "reviewed_at": "2027-12-18T09:00:00Z"})
            continue
        ev = _write(b / f"evidence-{rid}.md", f"# Evidence for {rid} (SYNTHETIC DEMO)\nbuild {product['build_sha']}\n")
        records.append(evidence_record(ev, [rid], "manual", "document"))
        units.append({"product_id": product["product_id"], "build_id": product["build_sha"], "requirement_id": rid,
                      "applicable": True, "applicability_justification": "Applies to DEMO-001 (demo)", "status": "verified",
                      "control_id": f"C-{rid}", "test_id": f"T-{rid}", "evidence_uri": ev.name,
                      "evidence_sha256": sha256_file(ev), "evidence_generated_at": "2027-12-19T10:05:00Z",
                      "owner": "Dev lead", "reviewer": "Security lead", "reviewed_at": "2027-12-19T11:00:00Z"})
    _write(b / "evidence-manifest.json", {"schema": "crasme-evidence-manifest/2", "records": records})
    _write(b / "trace-units.json", units)
    exp = (AS_OF + timedelta(days=30)).isoformat()
    _write(b / "approvals.json", [
        {"role": "security_lead", "reviewer": "S. Lead", "product_id": product["product_id"], "build_sha": product["build_sha"],
         "approved_at": "2027-12-19T12:00:00+00:00", "expires_at": exp, "revoked": False},
        {"role": "product_owner", "reviewer": "P. Owner", "product_id": product["product_id"], "build_sha": product["build_sha"],
         "approved_at": "2027-12-19T12:30:00+00:00", "expires_at": exp, "revoked": False}])
    return b, catalogue, policy, AS_OF
