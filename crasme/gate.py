"""Single release-decision engine (v1.2, recommendations P0-02 and P0-04).

Combines, for ONE product build:
  product record · scanner execution status · vulnerability findings + KEV + VEX ·
  evidence manifest (build-bound, hashed, freshness rules) · CRA obligation catalogue
  (in-force date, legal-review status) · traceability units · human approvals

and emits a versioned decision:
  PASS            every required check completed, no blocking finding, all in-force mandatory
                  obligations evidenced for this build, legal mappings verified, approvals valid
  FAIL            a known security/compliance blocker was detected
  REVIEW_REQUIRED anything incomplete, ambiguous, stale, unverified or needing human judgement

PASS means "technically eligible for human conformity review". It never means the
product is legally conformant (`legal_conformity` is always NOT_DETERMINED_BY_TOOL).
Risk scores are deliberately NOT an input.

CLI:
  python -m crasme.gate --bundle evidence/ --policy policy.yaml --out decision.json --report decision.md
  exit codes: 0 PASS · 1 FAIL · 2 REVIEW_REQUIRED · 3 engine error (decision written as REVIEW_REQUIRED)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import traceback
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from . import __version__
from .scanstatus import OK, ScanManifest
from .traceability import CATALOGUE_PATH, TraceUnit, sha256_file
from .vulns import parse_osv, parse_trivy

SCHEMA_VERSION = "1.0"
PASS, FAIL, REVIEW = "PASS", "FAIL", "REVIEW_REQUIRED"
SEV_FAIL, SEV_REVIEW, SEV_INFO = "FAIL", "REVIEW", "INFO"

REASON_CODES = {
    # bundle / engine
    "PRODUCT_RECORD_MISSING": (SEV_REVIEW, "product.json missing or invalid"),
    "ENGINE_ERROR": (SEV_REVIEW, "decision engine raised an error; no automated approval possible"),
    "BUNDLE_FILE_MISSING": (SEV_REVIEW, "a file required by policy is missing from the bundle"),
    # scans
    "SCAN_NOT_RECORDED": (SEV_REVIEW, "required scan has no execution-status record"),
    "SCAN_FAILED": (SEV_REVIEW, "required scan process failed"),
    "SCAN_TIMEOUT": (SEV_REVIEW, "required scan timed out"),
    "SCAN_OUTPUT_MISSING": (SEV_REVIEW, "required scan produced no output"),
    "SCAN_OUTPUT_INVALID": (SEV_REVIEW, "required scan output malformed, truncated or empty"),
    "SCAN_SKIPPED": (SEV_REVIEW, "required scan was skipped"),
    "SCAN_MANIFEST_WRONG_BUILD": (SEV_REVIEW, "scan-status manifest belongs to another product/build"),
    "SCAN_OUTPUT_TAMPERED": (SEV_FAIL, "scan output digest differs from the recorded digest"),
    "OPTIONAL_SCAN_NOT_OK": (SEV_INFO, "optional scan did not complete"),
    "KEV_FEED_UNAVAILABLE": (SEV_REVIEW, "known-exploited feed unavailable/invalid; exploitation status unknown"),
    # findings
    "KNOWN_EXPLOITED_AFFECTED": (SEV_FAIL, "KEV-listed vulnerability affects this build (VEX: affected)"),
    "KEV_TRIAGE_PENDING": (SEV_REVIEW, "KEV-listed vulnerability present; affectedness/reachability not determined"),
    "KEV_NOT_AFFECTED_UNJUSTIFIED": (SEV_REVIEW, "VEX not_affected statement lacks a justification"),
    "ARTICLE14_ASSESSMENT_REQUIRED": (SEV_REVIEW, "possible actively exploited vulnerability: Art. 14 reportability decision needed"),
    "FINDING_UNTRIAGED": (SEV_REVIEW, "high-severity finding without a VEX/triage decision"),
    # evidence
    "EVIDENCE_MANIFEST_MISSING": (SEV_REVIEW, "evidence manifest missing"),
    "EVIDENCE_WRONG_PRODUCT": (SEV_REVIEW, "evidence record is bound to another product"),
    "EVIDENCE_WRONG_BUILD": (SEV_REVIEW, "evidence record is bound to another build/version/artifact"),
    "EVIDENCE_UNBOUND": (SEV_REVIEW, "evidence record lacks product/build identifiers"),
    "EVIDENCE_FILE_MISSING": (SEV_REVIEW, "evidence file referenced by manifest is missing"),
    "EVIDENCE_INTEGRITY_FAILED": (SEV_FAIL, "evidence file hash does not match manifest (tampered or replaced)"),
    "EVIDENCE_STALE_AGE": (SEV_REVIEW, "evidence older than the configured freshness rule"),
    "EVIDENCE_STALE_INPUT_CHANGED": (SEV_REVIEW, "evidence was produced from inputs that have since changed"),
    # obligations
    "LEGAL_MAPPING_REVIEW_PENDING": (SEV_REVIEW, "in-force mandatory obligation(s) without verified legal mapping"),
    "APPLICABILITY_DECISION_MISSING": (SEV_REVIEW, "no applicability decision recorded for in-force mandatory obligation"),
    "NA_WITHOUT_RATIONALE": (SEV_REVIEW, "obligation marked not applicable without rationale/reviewer"),
    "OBLIGATION_NOT_MET": (SEV_FAIL, "applicable obligation recorded as failed"),
    "OBLIGATION_EVIDENCE_INCOMPLETE": (SEV_REVIEW, "applicable obligation lacks verified, reviewed evidence"),
    "OBLIGATION_EVIDENCE_WRONG_BUILD": (SEV_REVIEW, "obligation evidence is for another product/build"),
    "OBLIGATION_EVIDENCE_NOT_IN_MANIFEST": (SEV_REVIEW, "obligation evidence hash not found among valid manifest records"),
    "OBLIGATIONS_NOT_YET_IN_FORCE": (SEV_INFO, "obligations whose application date is after the assessment date"),
    # approvals
    "APPROVAL_MISSING": (SEV_REVIEW, "required human approval missing"),
    "APPROVAL_EXPIRED": (SEV_REVIEW, "human approval expired"),
    "APPROVAL_REVOKED": (SEV_REVIEW, "human approval revoked"),
    "APPROVAL_WRONG_BUILD": (SEV_REVIEW, "human approval given for a different build"),
}

DEFAULT_POLICY = {
    "required_scans": ["sbom", "vulns", "kev"],
    "required_approval_roles": ["security_lead", "product_owner"],
    "obligation_gates": ["pre-market", "lifecycle"],
    "require_verified_legal_mapping": True,
    "untriaged_review_severities": ["CRITICAL", "HIGH"],
    # Freshness rules are INTERNAL policy, not legal intervals (the CRA sets none for evidence age).
    "evidence_max_age_days": {"default": None},
}

def _schema_path(name: str) -> Path:
    pkg = Path(__file__).resolve().parent
    for p in (pkg.parent / "schemas" / name, pkg / "_data" / name):
        if p.exists():
            return p
    raise FileNotFoundError(name)


_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")


@dataclass
class Reason:
    code: str
    detail: str = ""
    refs: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return REASON_CODES[self.code][0]

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "description": REASON_CODES[self.code][1],
                "detail": self.detail, "refs": sorted(set(self.refs))}


def _parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_policy(path: str | Path | None) -> dict:
    pol = json.loads(json.dumps(DEFAULT_POLICY))
    if path:
        import yaml
        pol.update(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
    return pol


def applies_from(row: dict) -> date | None:
    m = _DATE.search(row.get("applies_from", ""))
    return date.fromisoformat(m.group(1)) if m else None


class Engine:
    def __init__(self, bundle: str | Path, policy: dict, as_of: datetime, catalogue: list[dict]):
        self.bundle = Path(bundle)
        self.policy = policy
        self.as_of = as_of
        self.catalogue = catalogue
        self.reasons: list[Reason] = []
        self.stats: dict = {}
        self.product: dict = {}
        self.valid_evidence_hashes: set[str] = set()

    # -- helpers ------------------------------------------------------------
    def add(self, code: str, detail: str = "", refs: list[str] | None = None) -> None:
        for r in self.reasons:   # merge same code
            if r.code == code:
                r.refs.extend(refs or [])
                if detail and detail not in r.detail:
                    r.detail = f"{r.detail}; {detail}" if r.detail else detail
                return
        self.reasons.append(Reason(code, detail, list(refs or [])))

    def file(self, name: str) -> Path:
        return self.bundle / name

    def binding_ok(self, rec: dict) -> str | None:
        """Return a reason code if the record is not bound to the build under assessment."""
        p = self.product
        if not rec.get("product_id") or not rec.get("build_sha"):
            return "EVIDENCE_UNBOUND"
        if rec["product_id"] != p["product_id"]:
            return "EVIDENCE_WRONG_PRODUCT"
        if rec["build_sha"] != p["build_sha"]:
            return "EVIDENCE_WRONG_BUILD"
        for k in ("product_version", "artifact_digest"):
            if rec.get(k) and p.get(k) and rec[k] != p[k]:
                return "EVIDENCE_WRONG_BUILD"
        return None

    # -- checks -------------------------------------------------------------
    def check_product(self) -> bool:
        f = self.file("product.json")
        try:
            self.product = _load_json(f)
            import jsonschema
            schema = json.loads(_schema_path("product.schema.json").read_text(encoding="utf-8"))
            errs = sorted(jsonschema.Draft202012Validator(schema).iter_errors(self.product), key=str)
            if errs:
                raise ValueError("; ".join(f"{list(e.path)}: {e.message}" for e in errs[:3]))
            return True
        except (OSError, ValueError, json.JSONDecodeError) as e:
            self.add("PRODUCT_RECORD_MISSING", f"{f.name}: {e}")
            return False

    def check_scans(self) -> dict[str, Path]:
        """Return {scan name: output path} for scans that are OK and untampered."""
        ok_outputs: dict[str, Path] = {}
        f = self.file("scan-status.json")
        required = list(self.policy["required_scans"])
        if not f.exists():
            self.add("SCAN_NOT_RECORDED", "scan-status.json missing", required)
            if "kev" in required:
                self.add("KEV_FEED_UNAVAILABLE", "no scan-status record")
            return ok_outputs
        man = ScanManifest.load(f)
        if (man.product_id, man.build_sha) != (self.product["product_id"], self.product["build_sha"]):
            self.add("SCAN_MANIFEST_WRONG_BUILD", f"{man.product_id}@{man.build_sha}")
            if "kev" in required:
                self.add("KEV_FEED_UNAVAILABLE", "scan manifest not for this build")
            return ok_outputs
        by_name = {s.name: s for s in man.scans}
        status_code = {"FAILED": "SCAN_FAILED", "TIMEOUT": "SCAN_TIMEOUT", "MISSING": "SCAN_OUTPUT_MISSING",
                       "INVALID": "SCAN_OUTPUT_INVALID", "SKIPPED": "SCAN_SKIPPED"}
        for name in required:
            if name not in by_name:
                self.add("SCAN_NOT_RECORDED", "", [name])
        for s in man.scans:
            is_req = s.name in required or s.required
            out = self.bundle / Path(s.output_path).name if s.output_path else None
            if s.execution_status != OK:
                self.add(status_code[s.execution_status] if is_req else "OPTIONAL_SCAN_NOT_OK",
                         f"{s.name}: {s.error_code}", [s.name])
                continue
            if out is None or not out.is_file():
                if is_req:
                    self.add("SCAN_OUTPUT_MISSING", f"{s.name}: recorded OK but file absent", [s.name])
                continue
            if s.output_digest and hashlib.sha256(out.read_bytes()).hexdigest() != s.output_digest:
                self.add("SCAN_OUTPUT_TAMPERED", "", [s.name])
                continue
            ok_outputs[s.name] = out
        if "kev" in required and "kev" not in ok_outputs:
            self.add("KEV_FEED_UNAVAILABLE", "known-exploited status cannot be established")
        self.stats["scans_recorded"] = len(man.scans)
        self.stats["scans_ok"] = len(ok_outputs)
        return ok_outputs

    def check_findings(self, outputs: dict[str, Path]) -> None:
        findings = set()
        for name, path in outputs.items():
            doc = _load_json(path)
            if "Results" in doc and "SchemaVersion" in doc:
                findings |= parse_trivy(doc)
            elif "results" in doc:
                findings |= parse_osv(doc)
        merged: dict[tuple, dict] = {}
        for f in findings:
            m = merged.setdefault(f.key, {"id": f.vuln_id, "package": f.package, "sev": set()})
            if f.severity:
                m["sev"].add(f.severity)
        vex = self.load_vex()
        kev = set()
        if "kev" in outputs:
            kev = {v["cveID"].upper() for v in _load_json(outputs["kev"]).get("vulnerabilities", [])}
        review_sev = set(self.policy.get("untriaged_review_severities", []))
        for key, m in merged.items():
            st = vex.get(m["id"]) or {}
            status = st.get("status")
            ref = f"{m['package']} {m['id']}"
            if m["id"] in kev:
                if status == "affected":
                    self.add("KNOWN_EXPLOITED_AFFECTED", "", [ref])
                    self.add("ARTICLE14_ASSESSMENT_REQUIRED", "", [m["id"]])
                elif status in ("not_affected", "fixed"):
                    if status == "not_affected" and not (st.get("justification") or st.get("impact_statement")):
                        self.add("KEV_NOT_AFFECTED_UNJUSTIFIED", "", [ref])
                else:
                    self.add("KEV_TRIAGE_PENDING", "", [ref])
                    self.add("ARTICLE14_ASSESSMENT_REQUIRED", "", [m["id"]])
            elif status is None and m["sev"] & review_sev:
                self.add("FINDING_UNTRIAGED", "", [ref])
        self.stats["findings_unique"] = len(merged)
        self.stats["kev_hits"] = sum(1 for m in merged.values() if m["id"] in kev)

    def load_vex(self) -> dict[str, dict]:
        """OpenVEX-style statements: {statements: [{vulnerability: {name}, status, justification}]}."""
        f = self.file("vex.json")
        if not f.exists():
            return {}
        out = {}
        for s in _load_json(f).get("statements", []):
            name = (s.get("vulnerability") or {}).get("name") or s.get("vulnerability_id")
            if name:
                out[str(name).upper()] = s
        return out

    def check_evidence(self) -> None:
        f = self.file("evidence-manifest.json")
        if not f.exists():
            self.add("EVIDENCE_MANIFEST_MISSING")
            return
        man = _load_json(f)
        ages = self.policy.get("evidence_max_age_days") or {}
        current_inputs = self.product.get("input_digests") or {}
        n_ok = 0
        for rec in man.get("records", []):
            ref = rec.get("evidence_uri", "?")
            bad = self.binding_ok(rec)
            if bad:
                self.add(bad, "", [ref])
                continue
            p = self.bundle / Path(ref).name
            if not p.is_file():
                self.add("EVIDENCE_FILE_MISSING", "", [ref])
                continue
            if sha256_file(p) != rec.get("evidence_sha256"):
                self.add("EVIDENCE_INTEGRITY_FAILED", "", [ref])
                continue
            max_age = ages.get(rec.get("evidence_type") or rec.get("tool"), ages.get("default"))
            if max_age is not None and rec.get("generated_at"):
                age = (self.as_of - _parse_dt(rec["generated_at"])).total_seconds() / 86400
                if age > max_age:
                    self.add("EVIDENCE_STALE_AGE", f"> {max_age} d (internal policy)", [ref])
                    continue
            stale_input = [k for k, v in (rec.get("input_digests") or {}).items()
                           if k in current_inputs and current_inputs[k] != v]
            if stale_input:
                self.add("EVIDENCE_STALE_INPUT_CHANGED", ",".join(stale_input), [ref])
                continue
            self.valid_evidence_hashes.add(rec["evidence_sha256"])
            n_ok += 1
        self.stats["evidence_records"] = len(man.get("records", []))
        self.stats["evidence_valid"] = n_ok

    def check_obligations(self) -> None:
        units: dict[str, TraceUnit] = {}
        f = self.file("trace-units.json")
        if f.exists():
            for d in _load_json(f):
                u = TraceUnit(**d)
                units[u.requirement_id] = u
        gates = set(self.policy["obligation_gates"])
        today = self.as_of.date()
        in_force, future, unverified = [], [], []
        for row in self.catalogue:
            if row["mandatory"] not in ("Y", "conditional") or row["gate"] not in gates:
                continue
            start = applies_from(row)
            if start is None or start > today:
                future.append(row["req_id"])
                continue
            rid = row["req_id"]
            u = units.get(rid)
            if row["mandatory"] == "conditional" and (u is None or not u.applicable):
                if u is not None and not u.applicability_justification.strip():
                    self.add("NA_WITHOUT_RATIONALE", "", [rid])
                continue
            in_force.append(rid)
            if self.policy.get("require_verified_legal_mapping", True) and row.get("legal_status") != "verified":
                unverified.append(rid)
            if u is None:
                self.add("APPLICABILITY_DECISION_MISSING", "", [rid])
                continue
            if not u.applicable:
                if not (u.applicability_justification.strip() and u.reviewer):
                    self.add("NA_WITHOUT_RATIONALE", "", [rid])
                continue
            if u.status == "failed":
                self.add("OBLIGATION_NOT_MET", "", [rid])
                continue
            if u.product_id != self.product["product_id"] or u.build_id != self.product["build_sha"]:
                self.add("OBLIGATION_EVIDENCE_WRONG_BUILD", "", [rid])
                continue
            if not u.is_complete():
                self.add("OBLIGATION_EVIDENCE_INCOMPLETE", "", [rid])
                continue
            if u.evidence_sha256 not in self.valid_evidence_hashes:
                self.add("OBLIGATION_EVIDENCE_NOT_IN_MANIFEST", "", [rid])
        if unverified:
            self.add("LEGAL_MAPPING_REVIEW_PENDING", f"{len(unverified)} row(s)", unverified)
        if future:
            self.add("OBLIGATIONS_NOT_YET_IN_FORCE", f"{len(future)} row(s) apply after {today}", future)
        self.stats["mandatory_obligations_in_force"] = len(in_force)
        self.stats["mandatory_obligations_not_yet_in_force"] = len(future)

    def check_approvals(self) -> None:
        f = self.file("approvals.json")
        approvals = _load_json(f) if f.exists() else []
        for role in self.policy["required_approval_roles"]:
            cands = [a for a in approvals if a.get("role") == role]
            if not cands:
                self.add("APPROVAL_MISSING", "", [role])
                continue
            good = None
            codes = []
            for a in cands:
                if a.get("build_sha") != self.product["build_sha"]:
                    codes.append("APPROVAL_WRONG_BUILD")
                elif a.get("revoked"):
                    codes.append("APPROVAL_REVOKED")
                elif a.get("expires_at") and _parse_dt(a["expires_at"]) <= self.as_of:
                    codes.append("APPROVAL_EXPIRED")
                elif not a.get("reviewer"):
                    codes.append("APPROVAL_MISSING")
                else:
                    good = a
            if not good:
                self.add(codes[-1] if codes else "APPROVAL_MISSING", "", [role])

    # -- run ------------------------------------------------------------------
    def run(self) -> dict:
        if self.check_product():
            outputs = self.check_scans()
            self.check_findings(outputs)
            self.check_evidence()
            self.check_obligations()
            self.check_approvals()
        return self.decision()

    def decision(self) -> dict:
        sev = {r.severity for r in self.reasons}
        verdict = FAIL if SEV_FAIL in sev else REVIEW if SEV_REVIEW in sev else PASS
        digests = {}
        if self.bundle.is_dir():
            for p in sorted(self.bundle.iterdir()):
                if p.is_file() and p.suffix in (".json", ".yaml", ".yml", ".sarif", ".md") and p.name != "decision.json":
                    digests[p.name] = sha256_file(p)
        order = {SEV_FAIL: 0, SEV_REVIEW: 1, SEV_INFO: 2}
        reasons = sorted(self.reasons, key=lambda r: (order[r.severity], r.code))
        return {
            "schema_version": SCHEMA_VERSION,
            "engine": f"crasme.gate {__version__}",
            "product_id": self.product.get("product_id"),
            "product_version": self.product.get("product_version"),
            "build_sha": self.product.get("build_sha"),
            "artifact_digest": self.product.get("artifact_digest"),
            "decision": verdict,
            "reasons": [r.code for r in reasons if r.severity != SEV_INFO],
            "details": [r.to_dict() for r in reasons],
            "stats": self.stats,
            "eligible_for_human_conformity_review": verdict == PASS,
            "legal_conformity": "NOT_DETERMINED_BY_TOOL",
            "as_of": self.as_of.isoformat(timespec="seconds"),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "input_digests": digests,
            "bundle_digest": hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest(),
            "policy_digest": hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest(),
            "disclaimer": "Automated evidence check only. Not legal advice and not a conformity assessment.",
        }


def load_catalogue(path: str | Path = CATALOGUE_PATH) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def evaluate(bundle: str | Path, policy: dict | None = None, as_of: datetime | None = None,
             catalogue: list[dict] | None = None) -> dict:
    as_of = as_of or datetime.now(timezone.utc)
    pol = policy if policy is not None else load_policy(None)
    try:
        return Engine(bundle, pol, as_of, catalogue if catalogue is not None else load_catalogue()).run()
    except Exception as e:  # fail safe: never PASS on engine error
        eng = Engine(bundle, pol, as_of, [])
        eng.add("ENGINE_ERROR", f"{type(e).__name__}: {e}")
        d = eng.decision()
        d["traceback"] = traceback.format_exc(limit=3)
        return d


def render_markdown(d: dict) -> str:
    icon = {PASS: "PASS", FAIL: "FAIL", REVIEW: "REVIEW REQUIRED"}[d["decision"]]
    lines = [f"# Release decision: **{icon}**", "",
             f"Product `{d['product_id']}` {d['product_version']} · build `{d['build_sha']}` · assessed as of {d['as_of']}",
             "", "> Automated evidence check only. PASS = eligible for human conformity review; "
                 "legal conformity is **not determined** by this tool.", "",
             "| Severity | Code | Description | Refs |", "|---|---|---|---|"]
    for r in d["details"]:
        refs = ", ".join(r["refs"][:8]) + (" …" if len(r["refs"]) > 8 else "")
        lines.append(f"| {r['severity']} | `{r['code']}` | {r['description']}{(' — ' + r['detail']) if r['detail'] else ''} | {refs} |")
    lines += ["", "Stats: " + ", ".join(f"{k}={v}" for k, v in d["stats"].items()),
              f"Bundle digest: `{d['bundle_digest']}`"]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CRA-SME release decision engine")
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--policy")
    ap.add_argument("--catalogue", default=str(CATALOGUE_PATH))
    ap.add_argument("--as-of", help="ISO date/time to assess against (default: now). Use 2027-12-11 for readiness checks")
    ap.add_argument("--out", default=None)
    ap.add_argument("--report", default=None)
    a = ap.parse_args(argv)
    as_of = _parse_dt(a.as_of) if a.as_of else None
    try:
        pol = load_policy(a.policy)
        cat = load_catalogue(a.catalogue)
    except Exception as e:
        print(f"cannot load policy/catalogue: {e}", file=sys.stderr)
        d = evaluate(a.bundle, DEFAULT_POLICY, as_of, None)
        d["decision"] = REVIEW
        code = 3
    else:
        d = evaluate(a.bundle, pol, as_of, cat)
        code = {PASS: 0, FAIL: 1, REVIEW: 2}[d["decision"]]
        if "ENGINE_ERROR" in d["reasons"]:
            code = 3
    out = Path(a.out) if a.out else Path(a.bundle) / "decision.json"
    out.write_text(json.dumps(d, indent=2), encoding="utf-8")
    if a.report:
        Path(a.report).write_text(render_markdown(d), encoding="utf-8")
    print(f"{d['decision']}: {', '.join(d['reasons']) or 'no blocking reasons'} -> {out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
