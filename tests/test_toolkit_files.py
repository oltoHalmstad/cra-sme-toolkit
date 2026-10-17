"""Static checks on shipped artefacts: CI workflow hardening, templates, provenance CLI."""
import json
import re

import pytest
import yaml

from conftest import ROOT
from crasme import provenance
from crasme.traceability import sha256_file

SHA = re.compile(r"@[0-9a-f]{40}(\s|$)")


def uses_lines(path):
    wf = yaml.safe_load(path.read_text())
    steps = [s for j in wf["jobs"].values() for s in j.get("steps", [])]
    return wf, [s["uses"] for s in steps if "uses" in s]


def test_v11_workflow_actions_pinned_to_sha():
    wf, uses = uses_lines(ROOT / "automation" / "security-scan.v1.1.yml")
    assert uses, "no actions found"
    unpinned = [u for u in uses if not SHA.search(u)]
    assert not unpinned, f"unpinned actions: {unpinned}"


def test_v11_workflow_least_privilege():
    wf, _ = uses_lines(ROOT / "automation" / "security-scan.v1.1.yml")
    assert wf["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in wf.get(True, wf.get("on", {}))


@pytest.mark.xfail(reason="Review finding F-07: v1.0 workflow uses mutable tags", strict=True)
def test_v10_workflow_actions_pinned_to_sha():
    _, uses = uses_lines(ROOT / "automation" / "security-scan.yml")
    assert all(SHA.search(u) for u in uses)


REQUIRED = {
    "Incident-Reporting-Checklist.md": ["24 h", "72 h", "14 days", "one month", "UTC", "Single Reporting Platform"],
    "Product-Classification-Memo.md": ["Annex III", "Conformity assessment", "Substantial modification"],
    "Risk-Acceptance.md": ["cannot waive"],
    "Annex-VII-Technical-File-Index.md": ["risk assessment", "SBOM", "declaration of conformity"],
    "Coordinated-Vulnerability-Disclosure-Policy.md": ["Article 14", "Scope"],
}


@pytest.mark.parametrize("name,needles", REQUIRED.items())
def test_templates_contain_required_items(name, needles):
    txt = (ROOT / "templates" / name).read_text()
    for n in needles:
        assert n.lower() in txt.lower(), f"{name} lacks '{n}'"


def test_cvd_policy_placeholder_lint():
    """Pre-publication lint: an adapted CVD policy must not contain placeholders."""
    txt = (ROOT / "templates" / "Coordinated-Vulnerability-Disclosure-Policy.md").read_text()
    placeholders = re.findall(r"\[[A-Z][^\]]*\]|example\.invalid", txt)
    assert placeholders, "template should ship with placeholders; copy and adapt before publishing"


def test_provenance_cli(tmp_path):
    ev = tmp_path / "sbom.cdx.json"
    ev.write_text("{}")
    out = tmp_path / "manifest.json"
    provenance.main(["--product", "P1", "--build", "abc", "--tool", "cdxgen", "--tool-version", "12.8.6",
                     "--evidence", str(ev), "--requirement", "P2-1", "--out", str(out)])
    provenance.main(["--product", "P1", "--build", "abc", "--tool", "cdxgen", "--evidence", str(ev), "--out", str(out)])
    m = json.loads(out.read_text())
    assert len(m["records"]) == 2
    assert m["records"][0]["evidence_sha256"] == sha256_file(ev)
    assert m["records"][0]["review_status"] == "unreviewed"
