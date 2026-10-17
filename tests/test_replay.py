import csv
import json
from datetime import datetime, timezone

import pytest

from conftest import ROOT
from crasme import replay as r

T = lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
E9 = ROOT / "experiments" / "e9_release_replay"


# --- CVSS v3 base score (FIRST reference vectors) ---------------------------------
@pytest.mark.parametrize("vec,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3(vec, score):
    assert r.cvss3_base(vec) == score


def test_cvss_garbage():
    assert r.cvss3_base("nonsense") is None


# --- version ordering ------------------------------------------------------------------
@pytest.mark.parametrize("eco,a,b", [
    ("npm", "1.2.3", "1.10.0"), ("npm", "2.0.0-beta.1", "2.0.0"), ("Go", "v0.9.9", "v0.10.0"),
    ("PyPI", "1.0rc1", "1.0"), ("PyPI", "2.9", "2.10"), ("Maven", "1.0-alpha", "1.0"),
    ("Maven", "2.14.1", "2.15.0"), ("Maven", "5.3.30", "5.3.31"), ("crates.io", "0.4.9", "0.4.10"),
])
def test_version_order(eco, a, b):
    assert r.version_key(eco, a) < r.version_key(eco, b)


def vuln(eco, name, events=None, versions=None, **kw):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if events:
        aff["ranges"] = [{"type": "ECOSYSTEM" if eco != "Go" else "SEMVER", "events": events}]
    if versions:
        aff["versions"] = versions
    return {"id": kw.get("id", "GHSA-test"), "affected": [aff], **{k: v for k, v in kw.items() if k != "id"}}


@pytest.mark.parametrize("ver,exp", [("4.17.20", True), ("4.17.21", False), ("3.0.0", False), ("4.0.0", True)])
def test_affects_ranges(ver, exp):
    v = vuln("npm", "lodash", [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}])
    assert r.affects(v, r.Pkg("npm", "lodash", ver)) is exp


def test_affects_last_affected_and_open_range():
    v = vuln("PyPI", "pyyaml", [{"introduced": "0"}, {"last_affected": "5.3"}])
    assert r.affects(v, r.Pkg("PyPI", "pyyaml", "5.3")) is True
    assert r.affects(v, r.Pkg("PyPI", "pyyaml", "5.4")) is False
    open_ = vuln("Go", "example.com/m", [{"introduced": "1.2.0"}])
    assert r.affects(open_, r.Pkg("Go", "example.com/m", "v1.9.0")) is True


def test_affects_versions_list_name_normalisation_and_unknown():
    v = vuln("PyPI", "Jinja2", versions=["2.10"])
    assert r.affects(v, r.Pkg("PyPI", "jinja2", "2.10")) is True
    assert r.affects(v, r.Pkg("PyPI", "jinja2", "3.0")) is False
    git_only = {"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "GIT", "events": []}]}]}
    assert r.affects(git_only, r.Pkg("npm", "x", "1.0.0")) is None
    other = vuln("npm", "other", [{"introduced": "0"}])
    assert r.affects(other, r.Pkg("npm", "x", "1.0.0")) is None


def test_known_at_and_withdrawn():
    v = {"published": "2025-03-01T00:00:00Z", "withdrawn": "2025-06-01T00:00:00Z"}
    assert not r.known_at(v, T("2025-02-01T00:00:00"))
    assert r.known_at(v, T("2025-04-01T00:00:00"))
    assert not r.known_at(v, T("2025-07-01T00:00:00"))


def test_kev_listed_at_via_alias():
    kev = r.kev_index({"vulnerabilities": [{"cveID": "CVE-2021-23337", "dateAdded": "2025-01-10"}]})
    v = {"id": "GHSA-35jh", "aliases": ["CVE-2021-23337"]}
    assert r.kev_listed_at(v, kev, T("2025-01-09T00:00:00")) is None
    assert r.kev_listed_at(v, kev, T("2025-02-01T00:00:00")) is not None


def test_replay_release_and_gates():
    pk = r.Pkg("npm", "lodash", "4.17.20")
    vulns = {pk: [vuln("npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}], id="GHSA-a", aliases=["CVE-1"],
                       published="2024-01-01T00:00:00Z", severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]),
                  vuln("npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}], id="GHSA-b",
                       published="2026-01-01T00:00:00Z")]}
    kev = r.kev_index({"vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2024-06-01"}]})
    pub = {("npm", "lodash", "4.17.21"): T("2021-02-20T00:00:00")}
    rr = r.replay_release("p", "v1", T("2025-01-01T00:00:00"), [pk], vulns, kev, pub)
    assert len(rr.known) == 1 and len(rr.later) == 1
    assert rr.known[0].kev_added and rr.known[0].fix_available_at_release
    m = r.release_metrics(rr)
    assert (m["gate_none"], m["gate_naive_kev"], m["gate_cvss7"]) == ("PASS", "FAIL", "FAIL")
    assert r.gate_crasme_security(rr) == "REVIEW_REQUIRED"
    kev_doc = {"vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2024-06-01"}] +
               [{"cveID": f"CVE-0000-{i}", "dateAdded": "2024-01-01"} for i in range(1200)]}
    d = r.engine_decision(rr, [pk], "a" * 40, kev_doc)
    assert d["decision"] == "REVIEW_REQUIRED" and d["scope"] == "security"
    assert "KEV_TRIAGE_PENDING" in d["reasons"] and not d["eligible_for_human_conformity_review"]


def _kev(n=1200):
    return {"vulnerabilities": [{"cveID": f"CVE-0000-{i}", "dateAdded": "2024-01-01"} for i in range(n)]}


def test_empty_inventory_is_review_only_for_crasme():
    rr = r.replay_release("c-firmware", "v1", T("2025-01-01T00:00:00"), [], {}, {})
    m = r.release_metrics(rr)
    assert m["gate_naive_kev"] == "PASS" and m["gate_cvss7"] == "PASS"
    d = r.engine_decision(rr, [], "b" * 40, _kev())
    assert d["decision"] == "REVIEW_REQUIRED" and "SCAN_OUTPUT_INVALID" in d["reasons"]


def test_clean_release_passes_security_scope():
    pk = r.Pkg("npm", "left-pad", "1.3.0")
    rr = r.replay_release("p", "v2", T("2025-01-01T00:00:00"), [pk], {pk: []}, {})
    d = r.engine_decision(rr, [pk], "c" * 40, _kev())
    assert d["decision"] == "PASS" and d["eligible_for_human_conformity_review"] is False


def test_kev_snapshot_is_time_travelled():
    pk = r.Pkg("npm", "lodash", "4.17.20")
    v = vuln("npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}], id="GHSA-z", aliases=["CVE-2021-23337"],
             published="2021-02-15T00:00:00Z", severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"}])
    kev = {"vulnerabilities": [{"cveID": "CVE-2021-23337", "dateAdded": "2026-01-10"}] + _kev()["vulnerabilities"]}
    before = r.replay_release("p", "v1", T("2025-06-01T00:00:00"), [pk], {pk: [v]}, r.kev_index(kev))
    after = r.replay_release("p", "v9", T("2026-06-01T00:00:00"), [pk], {pk: [v]}, r.kev_index(kev))
    assert r.engine_decision(before, [pk], "d" * 40, kev)["decision"] == "PASS"            # MEDIUM, not yet KEV
    assert "KEV_TRIAGE_PENDING" in r.engine_decision(after, [pk], "d" * 40, kev)["reasons"]


# --- lockfile parsers ----------------------------------------------------------------------
def test_parsers():
    pl = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"},
                     "node_modules/@s/b": {"version": "2.0.0", "dev": True}, "node_modules/a/node_modules/c": {"version": "3.0.0"}}})
    assert {(p.name, p.version, p.dev) for p in r.parse_package_lock(pl, include_dev=True)} == {("a", "1.0.0", False), ("@s/b", "2.0.0", True), ("c", "3.0.0", False)}
    assert r.parse_go_sum("golang.org/x/net v0.23.0 h1:x\ngolang.org/x/net v0.23.0/go.mod h1:y\n") == {r.Pkg("Go", "golang.org/x/net", "v0.23.0")}
    assert r.parse_requirements("-c c.txt\naiohttp==3.14.3\nAio_DNS[x]==4.0.4 ; python_version>'3'\nfoo>=1\n") == {
        r.Pkg("PyPI", "aiohttp", "3.14.3"), r.Pkg("PyPI", "aio-dns", "4.0.4")}
    assert r.parse_cargo_lock('[[package]]\nname="serde"\nversion="1.0.1"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="local"\nversion="0.1.0"\n') == {r.Pkg("crates.io", "serde", "1.0.1")}
    assert r.Pkg("npm", "@s/b", "2.0.0").purl == "pkg:npm/%40s/b@2.0.0"


def test_pnpm_and_yarn():
    pn = "lockfileVersion: '9.0'\npackages:\n  '@babel/core@7.24.0':\n    resolution: {}\n  zod@3.23.8:\n    resolution: {}\n"
    assert {(p.name, p.version) for p in r.parse_pnpm_lock(pn)} == {("@babel/core", "7.24.0"), ("zod", "3.23.8")}
    y = '"@babel/core@^7.0.0":\n  version "7.24.0"\n\nlodash@^4.17.0, lodash@^4.17.21:\n  version "4.17.21"\n'
    assert {(p.name, p.version) for p in r.parse_yarn_lock(y)} == {("@babel/core", "7.24.0"), ("lodash", "4.17.21")}


# --- frozen real dataset (regression) -------------------------------------------------------
def test_frozen_release_sample():
    rows = list(csv.DictReader(open(E9 / "releases.csv")))
    assert len(rows) == 144 and len({x["product_id"] for x in rows}) == 20
    assert all(len(x["commit_sha"]) == 40 for x in rows)


def test_inventory_summary_statuses():
    rows = list(csv.DictReader(open(E9 / "inventories" / "summary.csv")))
    assert len(rows) == 144
    lock = [x for x in rows if x["inventory_status"] == "lockfile"]
    assert len(lock) == 94 and all(int(x["n_components"]) > 0 for x in lock)
    assert {x["product_id"] for x in rows if x["inventory_status"].startswith("no-package-manifest")} == {"mosquitto", "tasmota", "pihole-ftl"}


@pytest.mark.parametrize("a,b", [("1.0", "1.0.1"), ("1.0-rc1", "1.0"), ("1.0", "1.0-sp1"), ("1.0.0", "1.0") ])
def test_maven_padding(a, b):
    ka, kb = r.version_key("Maven", a), r.version_key("Maven", b)
    if (a, b) == ("1.0.0", "1.0"):
        assert ka == kb
    else:
        assert ka < kb
