import string

from crasme.traceability import load_catalogue

CAT = load_catalogue()
IDS = [r["req_id"] for r in CAT]


def test_unique_ids():
    assert len(IDS) == len(set(IDS))


def test_annex_i_part_i_complete():
    letters = {r["cra_reference"].split("(2)(")[1].rstrip(")") for r in CAT
               if r["cra_reference"].startswith("Annex I Part I(2)")}
    assert letters == set(string.ascii_lowercase[:13])  # (a)-(m)


def test_annex_i_part_ii_complete():
    pts = {r["cra_reference"] for r in CAT if r["cra_reference"].startswith("Annex I Part II")}
    assert pts == {f"Annex I Part II({i})" for i in range(1, 9)}


def test_reporting_rows_apply_from_sept_2026():
    for r in CAT:
        if r["req_id"].startswith("REP-"):
            assert r["applies_from"] == "2026-09-11"


def test_every_row_has_reference_and_evidence():
    for r in CAT:
        assert r["cra_reference"].strip() and r["evidence_type"].strip(), r["req_id"]
        assert r["mandatory"] in {"Y", "N", "conditional"}


def test_v10_mislabelled_letters_are_documented():
    """Regression for review finding F-01: v1.0 matrix used wrong Annex I Part I letters."""
    notes = {r["req_id"]: r["verify_note"] for r in CAT}
    assert "correct letter is (c)" in notes["P1-c"]
    assert "(d)-(f)" in notes["P1-d"]
