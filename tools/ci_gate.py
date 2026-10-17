"""CI release gate: known-exploited vulnerabilities (CISA KEV) block; everything else goes to triage.

Exit code 1 only with --enforce and at least one blocker. Scores are never used to block or
unblock (concept note §7). A KEV hit is also a candidate Article 14 event: the gate report flags
it for the reporting-triage owner, who decides awareness/reportability — the tool does not.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from crasme.vulns import parse_osv, parse_trivy  # noqa: E402


def load(path, parser):
    p = Path(path) if path else None
    if not p or not p.exists():
        return set()
    return parser(json.loads(p.read_text()))


def evaluate(findings, kev_ids):
    # de-duplicate across scanners on the normalised (package, vuln id) key
    merged = {}
    for f in findings:
        rec = merged.setdefault(f.key, {"package": f.package, "id": f.vuln_id, "severity": set(), "scanners": set()})
        if f.severity:
            rec["severity"].add(f.severity)
        rec["scanners"].add(f.scanner)
    blockers, triage = [], []
    for key in sorted(merged):
        rec = merged[key]
        rec["severity"], rec["scanners"] = sorted(rec["severity"]), sorted(rec["scanners"])
        (blockers if rec["id"] in kev_ids else triage).append(rec)
    return {"release_allowed": not blockers,
            "blockers": blockers,
            "article14_candidates": [b["id"] for b in blockers],
            "triage_queue": triage,
            "note": "Human triage required for every finding; KEV listing is evidence of active exploitation, "
                    "absence from KEV is NOT evidence of non-exploitation."}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy"); ap.add_argument("--osv"); ap.add_argument("--kev", required=True)
    ap.add_argument("--out", default="gate-report.json"); ap.add_argument("--enforce", action="store_true")
    a = ap.parse_args(argv)
    kev = {v["cveID"].upper() for v in json.loads(Path(a.kev).read_text()).get("vulnerabilities", [])}
    findings = load(a.trivy, parse_trivy) | load(a.osv, parse_osv)
    rep = evaluate(findings, kev)
    rep["kev_entries_loaded"] = len(kev)
    Path(a.out).write_text(json.dumps(rep, indent=2))
    print(f"findings={len(rep['blockers']) + len(rep['triage_queue'])} blockers={len(rep['blockers'])} kev={len(kev)} -> {a.out}")
    return 1 if (a.enforce and rep["blockers"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
