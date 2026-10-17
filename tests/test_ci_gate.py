import json
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "tools"))
import ci_gate  # noqa: E402

E2 = ROOT / "experiments" / "e2_scanner_agreement" / "synthetic"


def test_gate_blocks_only_kev(tmp_path):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44906"}]}))  # test value, not a KEV claim
    out = tmp_path / "gate.json"
    rc = ci_gate.main(["--trivy", str(E2 / "node-app.trivy.json"), "--osv", str(E2 / "node-app.osv-scanner.json"),
                       "--kev", str(kev), "--out", str(out), "--enforce"])
    rep = json.loads(out.read_text())
    assert rc == 1 and not rep["release_allowed"]
    assert rep["article14_candidates"] == ["CVE-2021-44906"]
    assert len(rep["triage_queue"]) == 8   # 9 unique trivy+osv keys minus the KEV one


def test_gate_informational_mode_never_fails(tmp_path):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44906"}]}))
    assert ci_gate.main(["--trivy", str(E2 / "node-app.trivy.json"), "--kev", str(kev),
                         "--out", str(tmp_path / "g.json")]) == 0


def test_gate_handles_missing_inputs(tmp_path):
    kev = tmp_path / "kev.json"
    kev.write_text('{"vulnerabilities": []}')
    assert ci_gate.main(["--trivy", str(tmp_path / "nope.json"), "--kev", str(kev), "--out", str(tmp_path / "g.json"),
                         "--enforce"]) == 0
