"""Recalculate the shipped workbooks with LibreOffice and compare with crasme.risk."""
import shutil
import subprocess

import pytest

from conftest import ROOT
from crasme.risk import RiskRow

openpyxl = pytest.importorskip("openpyxl")
SOFFICE = shutil.which("soffice") or shutil.which("libreoffice")
BOOKS = ["CRA-SME-Risk-and-Evidence-Calculator.xlsx", "CRA-SME-Risk-and-Evidence-Calculator-v1.2.xlsx"]


def recalc(src, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run([SOFFICE, "--headless", "--calc", "--convert-to", "xlsx", "--outdir", str(out), str(src)],
                   check=True, capture_output=True, timeout=180)
    return openpyxl.load_workbook(out / src.name, data_only=True)


@pytest.mark.slow
@pytest.mark.skipif(SOFFICE is None, reason="LibreOffice not installed")
@pytest.mark.parametrize("book", BOOKS)
def test_formula_parity(book, tmp_path):
    wb = recalc(ROOT / book, tmp_path)
    ws = wb["Risk Register"]
    checked = 0
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row[0] or row[4] is None:
            continue
        r = RiskRow(row[0], row[1], row[2], int(row[4]), int(row[5]), int(row[6]),
                    row[10], row[13], row[14])
        assert row[7] == r.inherent and row[8] == r.inherent_band
        assert row[11] == r.residual and row[12] == r.residual_band
        assert row[15] == pytest.approx(r.inherent_ale) and row[17] == pytest.approx(r.residual_ale)
        assert row[18] == pytest.approx(r.expected_reduction)
        checked += 1
    assert checked >= 2


def test_readiness_weights_sum_to_one():
    for book in BOOKS:
        ws = openpyxl.load_workbook(ROOT / book)["Readiness"]
        assert sum(ws.cell(i, 2).value for i in range(2, 8)) == pytest.approx(1.0)


def test_v12_evidence_matrix_matches_catalogue():
    from crasme.traceability import load_catalogue
    ws = openpyxl.load_workbook(ROOT / BOOKS[1])["CRA Evidence Matrix"]
    ids = [ws.cell(i, 1).value for i in range(2, ws.max_row + 1) if ws.cell(i, 1).value]
    assert ids == [r["req_id"] for r in load_catalogue()]


def test_v12_risk_register_has_research_columns():
    ws = openpyxl.load_workbook(ROOT / BOOKS[1])["Risk Register"]
    headers = [c.value for c in ws[1]]
    for h in ("Mandatory / release blocker (Y/N)", "Known exploited (KEV) Y/N", "EPSS 0-1",
              "Loss p05 EUR", "Loss p95 EUR", "Assessor rationale"):
        assert h in headers


def test_v12_matrix_shows_legal_status_and_anchors_sheet():
    from crasme.traceability import load_catalogue
    wb = openpyxl.load_workbook(ROOT / BOOKS[1])
    ws = wb["CRA Evidence Matrix"]
    hdr = [c.value for c in ws[1]]
    col = hdr.index("Legal status") + 1
    cat = {r["req_id"]: r["legal_status"] for r in load_catalogue()}
    for i in range(2, ws.max_row + 1):
        assert ws.cell(i, col).value == cat[ws.cell(i, 1).value]
    assert "Scoring anchors" in wb.sheetnames
