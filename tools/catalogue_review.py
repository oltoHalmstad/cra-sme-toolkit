"""Record a legal/technical review of catalogue rows (recommendation P0-03).

    python tools/catalogue_review.py --ids P1-a,P1-b --status verified \
        --legal-reviewer "Name, firm" --rationale "Checked against consolidated text 2026-xx" \
        [--technical-reviewer "Name"] [--date 2026-11-02]

Status values: verified | unverified | superseded. Only a named legal reviewer can set
'verified'. Every change is appended to data/catalogue-review-log.csv (audit history is never
rewritten). The packaged copy in crasme/_data/ is kept in sync.
"""
import argparse
import csv
import shutil
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAT = ROOT / "data" / "cra_requirements_catalogue.csv"
LOG = ROOT / "data" / "catalogue-review-log.csv"
LOG_COLS = ["date", "req_id", "old_status", "new_status", "legal_reviewer", "technical_reviewer", "rationale"]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", required=True, help="comma-separated req_ids, or ALL")
    ap.add_argument("--status", required=True, choices=["verified", "unverified", "superseded"])
    ap.add_argument("--legal-reviewer", default="")
    ap.add_argument("--technical-reviewer", default="")
    ap.add_argument("--rationale", required=True)
    ap.add_argument("--date", default=date.today().isoformat())
    a = ap.parse_args(argv)
    if a.status == "verified" and not a.legal_reviewer.strip():
        ap.error("--legal-reviewer is required to mark rows verified")
    rows = list(csv.DictReader(open(CAT, newline="", encoding="utf-8")))
    ids = {r["req_id"] for r in rows} if a.ids == "ALL" else set(a.ids.split(","))
    unknown = ids - {r["req_id"] for r in rows}
    if unknown:
        ap.error(f"unknown req_ids: {sorted(unknown)}")
    log_new = not LOG.exists()
    with open(LOG, "a", newline="", encoding="utf-8") as lf:
        lw = csv.DictWriter(lf, fieldnames=LOG_COLS)
        if log_new:
            lw.writeheader()
        for r in rows:
            if r["req_id"] in ids:
                lw.writerow({"date": a.date, "req_id": r["req_id"], "old_status": r["legal_status"],
                             "new_status": a.status, "legal_reviewer": a.legal_reviewer,
                             "technical_reviewer": a.technical_reviewer, "rationale": a.rationale})
                r.update(legal_status=a.status, legal_reviewer=a.legal_reviewer, legal_reviewed_date=a.date,
                         technical_reviewer=a.technical_reviewer or r["technical_reviewer"], review_rationale=a.rationale)
    with open(CAT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    shutil.copyfile(CAT, ROOT / "crasme" / "_data" / CAT.name)
    print(f"{len(ids)} row(s) -> {a.status}; logged to {LOG.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
