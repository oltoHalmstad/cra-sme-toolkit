import json

import pytest

from conftest import ROOT
from crasme import sbom, vulns

E1 = ROOT / "experiments" / "e1_sbom_benchmark"
E2 = ROOT / "experiments" / "e2_scanner_agreement" / "synthetic"


@pytest.mark.parametrize("purl,exp", [
    ("pkg:pypi/Jinja2@3.1.6", ("pypi", "", "jinja2", "3.1.6")),
    ("pkg:pypi/charset_normalizer@3.5.2", ("pypi", "", "charset-normalizer", "3.5.2")),
    ("pkg:npm/%40types/node@20.1.0", ("npm", "@types", "node", "20.1.0")),
    ("pkg:maven/org.Apache.logging.log4j/log4j-core@2.14.1?type=jar", ("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1")),
    ("pkg:golang/github.com/gin-gonic/gin@v1.9.0#sub", ("golang", "github.com/gin-gonic", "gin", "v1.9.0")),
])
def test_parse_purl(purl, exp):
    assert sbom.parse_purl(purl).key == exp


def test_parse_purl_rejects_garbage():
    assert sbom.parse_purl("not-a-purl") is None
    assert sbom.parse_purl("pkg:npm") is None


def test_cyclonedx_nested_and_root_excluded(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"component": {"bom-ref": "root", "purl": "pkg:npm/app@1.0.0"}},
           "components": [{"bom-ref": "root", "purl": "pkg:npm/app@1.0.0"},
                          {"purl": "pkg:npm/a@1.0.0", "components": [{"purl": "pkg:npm/b@2.0.0"}]}]}
    p = tmp_path / "x.cdx.json"
    p.write_text(json.dumps(doc))
    comps, meta = sbom.load_sbom(p)
    assert {c.name for c in comps} == {"a", "b"}


def test_spdx_parsing(tmp_path):
    doc = {"spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: demo-1.0"]},
           "packages": [{"name": "x", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/x@1.0"}]}]}
    p = tmp_path / "x.spdx.json"
    p.write_text(json.dumps(doc))
    comps, meta = sbom.load_sbom(p)
    assert meta["format"] == "SPDX-2.3" and len(comps) == 1


def test_rejects_unknown_format(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{}")
    with pytest.raises(ValueError):
        sbom.load_sbom(p)


# --- regression on the real E1 pilot run (17 Oct 2026) ---
@pytest.mark.parametrize("fixture,output,recall,precision", [
    ("py-app", "py-app.cyclonedx-py-req.cdx.json", 4 / 12, 1.0),     # manifest mode misses transitive deps
    ("py-app", "py-app.cyclonedx-py-env.cdx.json", 1.0, 12 / 13),    # env mode also lists pip itself
    ("py-app", "py-app.cdxgen.cdx.json", 1.0, 12 / 13),
    ("node-app", "node-app.cdxgen.cdx.json", 1.0, 1.0),
    ("node-app", "node-app.cyclonedx-npm.cdx.json", 1.0, 1.0),
    ("c-vendored", "c-vendored.cdxgen.cdx.json", 0.5, 1.0),          # vendored C code not detected
])
def test_e1_pilot_regression(fixture, output, recall, precision):
    truth = sbom.load_ground_truth(E1 / "fixtures" / fixture / "ground_truth.csv")
    found, _ = sbom.load_sbom(E1 / "pilot-results" / output)
    m = sbom.accuracy(found, truth)
    assert m["recall"] == pytest.approx(recall)
    assert m["precision"] == pytest.approx(precision)


def test_scanner_parsers_and_agreement():
    by = {s: vulns.load_findings(E2 / f"node-app.{s}.json", s) for s in ("trivy", "grype", "osv-scanner")}
    assert len(by["trivy"]) == 9 and len(by["grype"]) == 8 and len(by["osv-scanner"]) == 7
    # OSV ids are resolved to their CVE alias so they collapse with Trivy/Grype
    assert all(f.vuln_id.startswith("CVE-") for f in by["osv-scanner"])
    rows = {r["pair"]: r for r in vulns.agreement_table(by)}
    assert rows["grype vs trivy"]["both"] == 7
    assert len(vulns.consensus(by, 3)) == 7
    assert len(vulns.consensus(by, 1)) == 10


def test_alias_canonicalisation_prefers_cve():
    assert vulns._canonical("GHSA-xxxx", ["CVE-2021-1", "CVE-2020-9"]) == "CVE-2020-9"
    assert vulns._canonical("PYSEC-1", []) == "PYSEC-1"
