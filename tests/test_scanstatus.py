import json
import sys

import pytest

from conftest import ROOT
from crasme import scanstatus as ss

sys.path.insert(0, str(ROOT / "tools"))
import run_scan  # noqa: E402


def w(p, obj):
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))
    return p


@pytest.mark.parametrize("kind,content,status,err", [
    ("kev", {"catalogVersion": "1", "vulnerabilities": []}, ss.INVALID, "EMPTY_FEED"),
    ("kev", {"vulnerabilities": [{"cveID": "X"}]}, ss.INVALID, "NOT_KEV_FEED"),
    ("kev", {"catalogVersion": "1", "count": 9, "vulnerabilities": [{"cveID": "X"}]}, ss.INVALID, "TRUNCATED_FEED"),
    ("kev", {"catalogVersion": "1", "count": 1, "vulnerabilities": [{"cveID": "X"}]}, ss.OK, None),
    ("trivy", '{"SchemaVersion": 2, "Res', ss.INVALID, "MALFORMED_JSON"),
    ("trivy", {"Results": []}, ss.INVALID, "NOT_TRIVY_REPORT"),
    ("trivy", {"SchemaVersion": 2, "ArtifactName": "x", "Results": None}, ss.INVALID, "NO_TARGETS"),
    ("trivy", {"SchemaVersion": 2, "ArtifactName": "x", "Results": [{"Target": "sbom"}]}, ss.OK, None),
    ("osv", {"results": []}, ss.OK, None),      # OSV-Scanner omits clean sources
    ("cyclonedx", {"bomFormat": "CycloneDX", "components": []}, ss.INVALID, "EMPTY_SBOM"),
    ("cyclonedx", {"bomFormat": "SPDX"}, ss.INVALID, "NOT_CYCLONEDX"),
    ("osv", {"results": "nope"}, ss.INVALID, "NOT_OSV_REPORT"),
    ("sarif", {"version": "2.1.0", "runs": []}, ss.OK, None),
    ("sarif", "", ss.INVALID, "OUTPUT_EMPTY"),
])
def test_validate_output(tmp_path, kind, content, status, err):
    st, code, _ = ss.validate_output(kind, w(tmp_path / "o.json", content))
    assert (st, code) == (status, err)


def test_missing_output(tmp_path):
    assert ss.validate_output("trivy", tmp_path / "none.json")[0] == ss.MISSING


@pytest.mark.parametrize("tool,code,status,err", [
    ("osv-scanner", 1, ss.OK, None),            # 1 = vulnerabilities found, not an error
    ("osv-scanner", 128, ss.INVALID, "NO_PACKAGES_FOUND"),
    ("osv-scanner", 127, ss.FAILED, "TOOL_ERROR"),
    ("trivy", 1, ss.FAILED, "EXIT_1"),
    ("semgrep", 2, ss.FAILED, "EXIT_2"),
])
def test_exit_code_normalisation(tmp_path, tool, code, status, err):
    out = w(tmp_path / "o.json", {"results": [{"packages": []}]})
    st, e, _ = ss.classify(tool, "osv", code, out)
    assert (st, e) == (status, err)


def test_step_outcome_and_timeout(tmp_path):
    out = w(tmp_path / "o.json", {"results": [{"packages": []}]})
    assert ss.classify("action", "osv", None, out, step_outcome="failure")[0] == ss.FAILED
    assert ss.classify("osv-scanner", "osv", None, out, timed_out=True)[0] == ss.TIMEOUT


def test_redaction_masks_secret_values():
    doc = {"Results": [{"Secrets": [{"RuleID": "aws", "Match": "AKIAABCDEFGHIJKLMNOP",
                                     "Code": {"Lines": [{"Content": "key=AKIA…", "Highlighted": "key=AKIA…"}]}}]}]}
    red, n = ss.redact_trivy_secrets(doc)
    assert n == 1 and "AKIA" not in json.dumps(red)


def test_run_scan_records_failure_and_never_fakes_clean(tmp_path):
    m = tmp_path / "scan-status.json"
    common = ["--manifest", str(m), "--product", "P", "--build", "abc1234"]
    # command that fails and writes nothing
    assert run_scan.main(common + ["--name", "osv", "--tool", "osv-scanner", "--kind", "osv",
                                   "--output", str(tmp_path / "osv.json"), "--", sys.executable, "-c",
                                   "import sys; sys.exit(127)"]) == 0
    # command that succeeds and writes a valid KEV feed
    feed = tmp_path / "kev.json"
    code = f"import json; json.dump({{'catalogVersion':'1','count':1,'vulnerabilities':[{{'cveID':'X'}}]}}, open(r'{feed}','w'))"
    run_scan.main(common + ["--name", "kev", "--tool", "curl", "--kind", "kev", "--output", str(feed), "--",
                            sys.executable, "-c", code])
    recs = {s["name"]: s for s in json.loads(m.read_text())["scans"]}
    assert recs["osv"]["execution_status"] == ss.FAILED and recs["osv"]["error_code"] == "TOOL_ERROR"
    assert recs["kev"]["execution_status"] == ss.OK and recs["kev"]["output_digest"]
    # --exit-on-failure makes the step fail as well
    assert run_scan.main(common + ["--name", "x", "--tool", "trivy", "--kind", "trivy", "--output",
                                   str(tmp_path / "nope.json"), "--exit-on-failure"]) == 1


def test_run_scan_refuses_mixing_builds(tmp_path):
    m = tmp_path / "s.json"
    ss.ScanManifest("P", "abc1234").save(m)
    assert run_scan.main(["--manifest", str(m), "--product", "P", "--build", "def5678", "--name", "a",
                          "--tool", "trivy", "--kind", "trivy", "--output", str(tmp_path / "x.json")]) == 3


def test_run_scan_missing_binary_is_failed(tmp_path):
    m = tmp_path / "s.json"
    run_scan.main(["--manifest", str(m), "--product", "P", "--build", "abc1234", "--name", "a", "--tool", "trivy",
                   "--kind", "trivy", "--output", str(tmp_path / "x.json"), "--", "definitely-not-a-binary-xyz"])
    assert json.loads(m.read_text())["scans"][0]["execution_status"] == ss.FAILED
