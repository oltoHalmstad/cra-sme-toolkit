import csv
import shutil
import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "tools"))
import catalogue_review as cr  # noqa: E402


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    (tmp_path / "crasme" / "_data").mkdir(parents=True)
    shutil.copy(ROOT / "data" / "cra_requirements_catalogue.csv", tmp_path / "data")
    monkeypatch.setattr(cr, "ROOT", tmp_path)
    monkeypatch.setattr(cr, "CAT", tmp_path / "data" / "cra_requirements_catalogue.csv")
    monkeypatch.setattr(cr, "LOG", tmp_path / "data" / "catalogue-review-log.csv")
    return tmp_path


def rows(p):
    return {r["req_id"]: r for r in csv.DictReader(open(p))}


def test_verify_requires_named_legal_reviewer(sandbox):
    with pytest.raises(SystemExit):
        cr.main(["--ids", "P1-a", "--status", "verified", "--rationale", "x"])


def test_review_updates_row_and_appends_log(sandbox):
    cr.main(["--ids", "P1-a,P1-b", "--status", "verified", "--legal-reviewer", "A. Lawyer",
             "--rationale", "checked consolidated text", "--date", "2026-11-01"])
    r = rows(sandbox / "data" / "cra_requirements_catalogue.csv")
    assert r["P1-a"]["legal_status"] == "verified" and r["P1-a"]["legal_reviewer"] == "A. Lawyer"
    assert r["P1-c"]["legal_status"] == "unverified"
    cr.main(["--ids", "P1-a", "--status", "superseded", "--rationale", "new guidance", "--date", "2026-12-01"])
    log = list(csv.DictReader(open(sandbox / "data" / "catalogue-review-log.csv")))
    assert [l["new_status"] for l in log] == ["verified", "verified", "superseded"]   # history kept


def test_unknown_id_rejected(sandbox):
    with pytest.raises(SystemExit):
        cr.main(["--ids", "NOPE-1", "--status", "unverified", "--rationale", "x"])


def test_shipped_catalogue_is_not_presented_as_verified():
    r = rows(ROOT / "data" / "cra_requirements_catalogue.csv")
    assert all(x["legal_status"] == "unverified" for x in r.values())
    for x in r.values():
        assert x["source_url"].startswith("https://eur-lex.europa.eu/")
        assert x["requirement_kind"] and x["operator_roles"] and x["catalogue_version"] == "1.2.0"
