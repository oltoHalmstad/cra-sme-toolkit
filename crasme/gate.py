"""Single release-decision engine (v1.2, recommendations P0-02 and P0-04).

Combines, for ONE product build:
  product record · scanner execution status (re-validated) · vulnerability, secret,
  misconfiguration and SAST findings + KEV + VEX + triage · evidence manifest (build-bound,
  hashed, freshness rules) · pinned CRA obligation catalogue (in-force date, legal-review
  status) · traceability units · human approvals

and emits a versioned decision:
  PASS            every required check completed, no blocking finding, all in-force mandatory
                  obligations evidenced for this build, legal mappings verified, approvals valid
  FAIL            a known security/compliance blocker was detected
  REVIEW_REQUIRED anything incomplete, ambiguous, stale, unverified or needing human judgement

PASS means "technically eligible for human conformity review". It never means the
product is legally conformant (`legal_conformity` is always NOT_DETERMINED_BY_TOOL).
Risk scores are deliberately NOT an input.

Trust boundary: hashes inside the bundle detect accidental or careless changes only. Anyone who
can rewrite the whole bundle can recompute them. Authenticity comes from the signed build
provenance attestation (attest job) and from `--expect-build/--expect-product`, which bind the
decision to the CI run that produced it.

CLI:
  python -m crasme.gate --bundle evidence/ --policy policy.yaml --expect-build "$GITHUB_SHA" \
      --out decision.json --report decision.md
  exit codes: 0 PASS · 1 FAIL · 2 REVIEW_REQUIRED · 3 engine/config error (decision REVIEW_REQUIRED)
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
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .scanstatus import OK, ScanManifest, digest_paths, validate_output
from .traceability import CATALOGUE_PATH, TraceUnit, sha256_file
from .vulns import parse_osv, parse_trivy

SCHEMA_VERSION = "1.0"
PASS, FAIL, REVIEW = "PASS", "FAIL", "REVIEW_REQUIRED"
SEV_FAIL, SEV_REVIEW, SEV_INFO = "FAIL", "REVIEW", "INFO"

REASON_CODES = {
    # bundle / engine / policy / catalogue
    "PRODUCT_RECORD_MISSING": (SEV_REVIEW, "product.json missing or invalid"),
    "PRODUCT_RECORD_MISMATCH": (SEV_REVIEW, "product.json does not match the build/product expected by CI"),
    "ENGINE_ERROR": (SEV_REVIEW, "decision engine or configuration error; no automated approval possible"),
    "SCOPE_SECURITY_ONLY": (SEV_INFO, "security-only evaluation: obligations, evidence manifest and approvals NOT assessed"),
    "POLICY_BELOW_MINIMUM": (SEV_REVIEW, "policy weakens a minimum safeguard (floor re-applied)"),
    "CATALOGUE_NOT_PINNED": (SEV_REVIEW, "policy does not pin the obligation catalogue digest"),
    "CATALOGUE_DIGEST_MISMATCH": (SEV_REVIEW, "obligation catalogue differs from the pinned digest"),
    "CATALOGUE_ROW_INVALID": (SEV_REVIEW, "catalogue row has an invalid mandatory/gate/date value"),
    "CATALOGUE_EMPTY": (SEV_REVIEW, "no in-force mandatory obligation evaluated"),
    "TRACE_UNIT_DUPLICATE": (SEV_REVIEW, "more than one traceability unit for the same obligation"),
    # scans
    "SCAN_NOT_RECORDED": (SEV_REVIEW, "required scan has no execution-status record"),
    "SCAN_RECORD_DUPLICATE": (SEV_REVIEW, "scan name recorded more than once"),
    "SCAN_FAILED": (SEV_REVIEW, "required scan process failed"),
    "SCAN_TIMEOUT": (SEV_REVIEW, "required scan timed out"),
    "SCAN_OUTPUT_MISSING": (SEV_REVIEW, "required scan produced no output"),
    "SCAN_OUTPUT_INVALID": (SEV_REVIEW, "scan output malformed, empty, of the wrong kind or shared"),
    "SCAN_SKIPPED": (SEV_REVIEW, "required scan was skipped"),
    "SCAN_RECORD_INCOMPLETE": (SEV_REVIEW, "scan record lacks digest/timestamps; integrity or freshness unverifiable"),
    "SCAN_INPUT_UNBOUND": (SEV_REVIEW, "vulnerability scan is not bound to the SBOM in this bundle"),
    "SCAN_STALE": (SEV_REVIEW, "scan or feed older than the configured freshness rule"),
    "SCAN_MANIFEST_WRONG_BUILD": (SEV_REVIEW, "scan-status manifest belongs to another product/build"),
    "SCAN_OUTPUT_TAMPERED": (SEV_FAIL, "scan output digest differs from the recorded digest"),
    "OPTIONAL_SCAN_NOT_OK": (SEV_INFO, "optional scan did not complete"),
    "KEV_FEED_UNAVAILABLE": (SEV_REVIEW, "known-exploited feed unavailable/invalid; exploitation status unknown"),
    # findings
    "KNOWN_EXPLOITED_AFFECTED": (SEV_FAIL, "KEV-listed vulnerability affects this build (VEX: affected)"),
    "KEV_TRIAGE_PENDING": (SEV_REVIEW, "KEV-listed vulnerability present; affectedness/reachability not determined"),
    "KEV_NOT_AFFECTED_UNJUSTIFIED": (SEV_REVIEW, "VEX not_affected statement lacks a justification"),
    "VEX_CONTRADICTS_SCAN": (SEV_REVIEW, "VEX says fixed, but the scan still detects the vulnerability in this build"),
    "VEX_STATUS_INVALID": (SEV_REVIEW, "VEX statement has an unknown status"),
    "ARTICLE14_ASSESSMENT_REQUIRED": (SEV_REVIEW, "possible actively exploited vulnerability: Art. 14 reportability decision needed"),
    "KEV_STATUS_UNKNOWN": (SEV_REVIEW, "finding has no CVE alias, so known-exploited status cannot be checked"),
    "FINDING_UNTRIAGED": (SEV_REVIEW, "high/critical/unknown-severity finding without a resolving VEX/triage decision"),
    "FINDING_AFFECTED_UNRESOLVED": (SEV_REVIEW, "high/critical finding confirmed affected and not fixed"),
    "SECRET_FINDING": (SEV_REVIEW, "secret detected in the source tree"),
    "MISCONFIG_FINDING": (SEV_REVIEW, "high/critical misconfiguration detected"),
    "SAST_FINDING": (SEV_REVIEW, "error-level static-analysis finding"),
    # evidence
    "EVIDENCE_MANIFEST_MISSING": (SEV_REVIEW, "evidence manifest missing"),
    "EVIDENCE_WRONG_PRODUCT": (SEV_REVIEW, "evidence record is bound to another product"),
    "EVIDENCE_WRONG_BUILD": (SEV_REVIEW, "evidence record is bound to another build/version/artifact"),
    "EVIDENCE_UNBOUND": (SEV_REVIEW, "evidence record lacks product/build identifiers"),
    "EVIDENCE_PATH_INVALID": (SEV_REVIEW, "evidence URI is absolute or escapes the bundle"),
    "EVIDENCE_FILE_MISSING": (SEV_REVIEW, "evidence file referenced by manifest is missing"),
    "EVIDENCE_INTEGRITY_FAILED": (SEV_FAIL, "evidence file hash does not match manifest (tampered or replaced)"),
    "EVIDENCE_TIMESTAMP_INVALID": (SEV_REVIEW, "evidence timestamp missing, unparsable or in the future"),
    "EVIDENCE_STALE_AGE": (SEV_REVIEW, "evidence older than the configured freshness rule"),
    "EVIDENCE_STALE_INPUT_CHANGED": (SEV_REVIEW, "evidence was produced from inputs that have since changed"),
    "EVIDENCE_INPUT_UNVERIFIABLE": (SEV_REVIEW, "evidence declares input digests the product record does not provide"),
    "EVIDENCE_OVERCLAIMED": (SEV_REVIEW, "one evidence record is declared for too many obligations"),
    # obligations
    "LEGAL_MAPPING_REVIEW_PENDING": (SEV_REVIEW, "in-force mandatory obligation(s) without verified legal mapping"),
    "APPLICABILITY_DECISION_MISSING": (SEV_REVIEW, "no applicability decision recorded for in-force mandatory obligation"),
    "NA_WITHOUT_RATIONALE": (SEV_REVIEW, "obligation marked not applicable without rationale/reviewer"),
    "OBLIGATION_NOT_MET": (SEV_FAIL, "applicable obligation recorded as failed"),
    "OBLIGATION_EVIDENCE_INCOMPLETE": (SEV_REVIEW, "applicable obligation lacks verified, reviewed evidence"),
    "OBLIGATION_REVIEW_INVALID": (SEV_REVIEW, "obligation review timestamp invalid, in the future or before the evidence"),
    "OBLIGATION_EVIDENCE_WRONG_BUILD": (SEV_REVIEW, "obligation decision/evidence is for another product/build"),
    "OBLIGATION_EVIDENCE_NOT_IN_MANIFEST": (SEV_REVIEW, "obligation evidence hash not found among valid manifest records"),
    "OBLIGATION_EVIDENCE_MISATTRIBUTED": (SEV_REVIEW, "evidence record is not declared for this obligation / URI mismatch"),
    "OBLIGATIONS_NOT_YET_IN_FORCE": (SEV_INFO, "obligations whose application date is after the assessment date"),
    # approvals
    "APPROVAL_MISSING": (SEV_REVIEW, "required human approval missing"),
    "APPROVAL_EXPIRED": (SEV_REVIEW, "human approval expired"),
    "APPROVAL_NO_EXPIRY": (SEV_REVIEW, "human approval has no (valid) expiry date"),
    "APPROVAL_INVALID": (SEV_REVIEW, "approval timestamp missing, in the future or validity window too long"),
    "APPROVAL_REVOKED": (SEV_REVIEW, "human approval revoked"),
    "APPROVAL_WRONG_BUILD": (SEV_REVIEW, "human approval given for a different build or product"),
    "APPROVAL_SAME_REVIEWER": (SEV_REVIEW, "one person holds more than one required approval role"),
}

DEFAULT_POLICY = {
    "required_scans": ["sbom", "vulns", "kev"],
    "required_approval_roles": ["security_lead", "product_owner"],
    "obligation_gates": ["pre-market", "lifecycle"],
    "require_verified_legal_mapping": True,
    "untriaged_review_severities": ["CRITICAL", "HIGH"],
    # Freshness rules are INTERNAL policy, not legal intervals (the CRA sets none for evidence age).
    "evidence_max_age_days": {"default": None},
    "scan_max_age_days": {"default": 30, "vulns": 7, "kev": 7},
    "approval_max_validity_days": 90,
    "kev_min_entries": 1000,
    "max_requirements_per_evidence": 3,
    "catalogue_sha256": None,     # pin with: crasme-gate --print-catalogue-digest
}
# Floors a policy file cannot lower (violations are reported and the floor re-applied).
MIN_REQUIRED_SCANS = {"sbom", "vulns", "kev"}
MIN_REVIEW_SEVERITIES = {"CRITICAL", "HIGH"}
MIN_OBLIGATION_GATES = {"pre-market", "lifecycle"}
MIN_APPROVAL_ROLES = 2
VALID_MANDATORY = {"Y", "N", "conditional"}
VALID_GATES = {"pre-market", "lifecycle", "event-driven"}
SCAN_KINDS = {"sbom": {"cyclonedx"}, "vulns": {"trivy", "osv"}, "kev": {"kev"},
              "fs": {"trivy"}, "osv": {"osv"}, "sast": {"sarif"}}
VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
CLOCK_SKEW = timedelta(hours=1)

_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _schema_path(name: str) -> Path:
    pkg = Path(__file__).resolve().parent
    for p in (pkg.parent / "schemas" / name, pkg / "_data" / name):
        if p.exists():
            return p
    raise FileNotFoundError(name)


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
                "detail": self.detail, "refs": sorted(set(map(str, self.refs)))}


def _parse_dt(s) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _try_dt(s) -> datetime | None:
    try:
        return _parse_dt(s) if s else None
    except (ValueError, TypeError):
        return None


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_policy(path: str | Path | None) -> dict:
    pol = json.loads(json.dumps(DEFAULT_POLICY))
    if path:
        import yaml
        pol.update(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
    return pol


def applies_from(row: dict) -> date | None:
    m = _DATE.search(row.get("applies_from", "") or "")
    return date.fromisoformat(m.group(1)) if m else None


def catalogue_digest(catalogue: list[dict]) -> str:
    """Content digest of the catalogue rows (order-independent, file-format independent)."""
    rows = sorted((json.dumps(r, sort_keys=True, ensure_ascii=False) for r in catalogue))
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


class Engine:
    def __init__(self, bundle: str | Path, policy: dict, as_of: datetime, catalogue: list[dict],
                 expect_build: str | None = None, expect_product: str | None = None, scope: str = "full"):
        if scope not in ("full", "security"):
            raise ValueError("scope must be 'full' or 'security'")
        self.scope = scope
        self.bundle = Path(bundle)
        self.policy = json.loads(json.dumps(policy))   # never mutate the caller's policy
        self.as_of = (as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
        self.catalogue = catalogue
        self.expect_build, self.expect_product = expect_build, expect_product
        self.reasons: list[Reason] = []
        self.stats: dict = {}
        self.product: dict = {}
        self.valid_evidence: dict[str, dict] = {}   # sha256 -> {"rids": set, "uri": basename, "generated_at": dt}

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

    # -- policy and catalogue -------------------------------------------------------
    def check_policy(self) -> None:
        pol = self.policy
        def floor(key, minimum, label):
            have = set(pol.get(key) or [])
            if not minimum <= have:
                self.add("POLICY_BELOW_MINIMUM", f"{key} lacks {sorted(minimum - have)}", [label])
                pol[key] = sorted(have | minimum)
        floor("required_scans", MIN_REQUIRED_SCANS, "required_scans")
        floor("untriaged_review_severities", MIN_REVIEW_SEVERITIES, "untriaged_review_severities")
        floor("obligation_gates", MIN_OBLIGATION_GATES, "obligation_gates")
        if len(set(pol.get("required_approval_roles") or [])) < MIN_APPROVAL_ROLES:
            self.add("POLICY_BELOW_MINIMUM", f"fewer than {MIN_APPROVAL_ROLES} approval roles", ["required_approval_roles"])
            pol["required_approval_roles"] = sorted(set(pol.get("required_approval_roles") or [])
                                                    | set(DEFAULT_POLICY["required_approval_roles"]))
        if pol.get("require_verified_legal_mapping") is not True:
            self.add("POLICY_BELOW_MINIMUM", "require_verified_legal_mapping must be true", ["require_verified_legal_mapping"])
            pol["require_verified_legal_mapping"] = True
        for key in ("approval_max_validity_days", "kev_min_entries", "max_requirements_per_evidence"):
            if not isinstance(pol.get(key), int) or pol[key] <= 0:
                self.add("POLICY_BELOW_MINIMUM", f"{key} must be a positive integer", [key])
                pol[key] = DEFAULT_POLICY[key]
        pin = pol.get("catalogue_sha256")
        dig = catalogue_digest(self.catalogue)
        self.stats["catalogue_sha256"] = dig
        if not pin:
            self.add("CATALOGUE_NOT_PINNED", "set policy catalogue_sha256", [dig[:16]])
        elif pin != dig:
            self.add("CATALOGUE_DIGEST_MISMATCH", f"pinned {pin[:12]}…, got {dig[:12]}…")

    # -- product --------------------------------------------------------------------
    def check_product(self) -> bool:
        f = self.file("product.json")
        try:
            self.product = _load_json(f)
            import jsonschema
            schema = json.loads(_schema_path("product.schema.json").read_text(encoding="utf-8"))
            errs = sorted(jsonschema.Draft202012Validator(schema).iter_errors(self.product), key=str)
            if errs:
                raise ValueError("; ".join(f"{list(e.path)}: {e.message}" for e in errs[:3]))
        except (OSError, ValueError, json.JSONDecodeError) as e:
            self.add("PRODUCT_RECORD_MISSING", f"{f.name}: {e}")
            self.product = self.product if isinstance(self.product, dict) else {}
            return False
        if self.expect_build and self.product["build_sha"] != self.expect_build:
            self.add("PRODUCT_RECORD_MISMATCH", f"build {self.product['build_sha']} != expected {self.expect_build}")
            return False
        if self.expect_product and self.product["product_id"] != self.expect_product:
            self.add("PRODUCT_RECORD_MISMATCH", f"product {self.product['product_id']} != expected {self.expect_product}")
            return False
        return True

    # -- scans ----------------------------------------------------------------------
    def check_scans(self) -> dict[str, tuple[Path, str]]:
        """Return {scan name: (output path, kind)} for scans that are OK, re-validated, fresh and untampered."""
        ok: dict[str, tuple[Path, str]] = {}
        f = self.file("scan-status.json")
        required = list(self.policy["required_scans"])
        if not f.exists():
            self.add("SCAN_NOT_RECORDED", "scan-status.json missing", required)
            self.add("KEV_FEED_UNAVAILABLE", "no scan-status record")
            return ok
        man = ScanManifest.load(f)
        if (man.product_id, man.build_sha) != (self.product["product_id"], self.product["build_sha"]):
            self.add("SCAN_MANIFEST_WRONG_BUILD", f"{man.product_id}@{man.build_sha}")
            self.add("KEV_FEED_UNAVAILABLE", "scan manifest not for this build")
            return ok
        names = [s.name for s in man.scans]
        dups = {n for n in names if names.count(n) > 1}
        if dups:
            self.add("SCAN_RECORD_DUPLICATE", "", sorted(dups))
        outs = [Path(s.output_path).name for s in man.scans if s.output_path]
        shared = {o for o in outs if outs.count(o) > 1}
        status_code = {"FAILED": "SCAN_FAILED", "TIMEOUT": "SCAN_TIMEOUT", "MISSING": "SCAN_OUTPUT_MISSING",
                       "INVALID": "SCAN_OUTPUT_INVALID", "SKIPPED": "SCAN_SKIPPED"}
        ages = self.policy.get("scan_max_age_days") or {}
        for name in required:
            if name not in names:
                self.add("SCAN_NOT_RECORDED", "", [name])
        for s in man.scans:
            is_req = s.name in required or s.required
            bad = (lambda code, detail="": self.add(code if is_req else "OPTIONAL_SCAN_NOT_OK", detail, [s.name]))
            if s.name in dups:
                continue
            if s.execution_status != OK:
                bad(status_code[s.execution_status], f"{s.name}: {s.error_code}")
                continue
            expected = SCAN_KINDS.get(s.name)
            if expected and s.kind not in expected:
                bad("SCAN_OUTPUT_INVALID", f"{s.name}: kind {s.kind} not in {sorted(expected)}")
                continue
            out = self.bundle / Path(s.output_path).name if s.output_path else None
            if out is None or not out.is_file():
                bad("SCAN_OUTPUT_MISSING", f"{s.name}: recorded OK but file absent")
                continue
            if out.name in shared:
                bad("SCAN_OUTPUT_INVALID", f"{s.name}: output file shared with another scan")
                continue
            if not s.output_digest:
                bad("SCAN_RECORD_INCOMPLETE", f"{s.name}: no output digest")
                continue
            if hashlib.sha256(out.read_bytes()).hexdigest() != s.output_digest:
                self.add("SCAN_OUTPUT_TAMPERED", "", [s.name])
                continue
            st, err, n = validate_output(s.kind, out)          # never trust the recorded status alone
            if st != OK:
                bad("SCAN_OUTPUT_INVALID", f"{s.name}: re-validation {err}")
                continue
            fin = _try_dt(s.finished_at)
            if fin is None or fin > self.as_of + CLOCK_SKEW:
                bad("SCAN_RECORD_INCOMPLETE", f"{s.name}: finished_at missing/invalid/future")
                continue
            max_age = ages.get(s.name, ages.get("default"))
            if max_age is not None and (self.as_of - fin).total_seconds() / 86400 > max_age:
                bad("SCAN_STALE", f"{s.name}: > {max_age} d (internal policy)")
                continue
            if s.kind == "kev" and (n or 0) < self.policy["kev_min_entries"]:
                bad("SCAN_OUTPUT_INVALID", f"kev: {n} entries < sanity floor {self.policy['kev_min_entries']}")
                continue
            ok[s.name] = (out, s.kind)
        # the vulnerability scan must be bound to the SBOM of this bundle
        if "vulns" in ok and "sbom" in ok:
            vrec = next(s for s in man.scans if s.name == "vulns")
            if not vrec.input_digest or vrec.input_digest != digest_paths([ok["sbom"][0]]):
                self.add("SCAN_INPUT_UNBOUND", "vulns input_digest does not match sbom output", ["vulns"])
                ok.pop("vulns")
        if "kev" not in ok:
            self.add("KEV_FEED_UNAVAILABLE", "known-exploited status cannot be established")
        self.stats["scans_recorded"] = len(man.scans)
        self.stats["scans_ok"] = len(ok)
        return ok

    # -- findings ---------------------------------------------------------------------
    def _vex(self) -> dict[str, dict]:
        """OpenVEX-style statements bound to this product (statements naming other products are ignored)."""
        f = self.file("vex.json")
        if not f.exists():
            return {}
        out = {}
        ids = {self.product["product_id"], self.product.get("purl", "")} - {""}
        for s in _load_json(f).get("statements", []):
            name = (s.get("vulnerability") or {}).get("name") or s.get("vulnerability_id")
            if not name:
                continue
            prods = s.get("products")
            if prods:
                pid = {p if isinstance(p, str) else p.get("@id", "") for p in prods}
                if not pid & ids:
                    continue
            if s.get("status") not in VEX_STATUSES:
                self.add("VEX_STATUS_INVALID", "", [str(name)])
                continue
            out[str(name).strip().upper()] = s
        return out

    def _triage(self) -> dict[tuple[str, str], dict]:
        """triage.json: [{kind: secret|misconfig|sast, id, decision: false_positive|accepted|revoked, reviewer, rationale}]."""
        f = self.file("triage.json")
        out = {}
        if f.exists():
            for t in _load_json(f):
                if t.get("reviewer") and t.get("rationale") and t.get("decision") in ("false_positive", "accepted", "revoked"):
                    out[(t.get("kind"), str(t.get("id")))] = t
        return out

    def check_findings(self, outputs: dict[str, tuple[Path, str]]) -> None:
        vulns = set()
        secrets, misconf, sast = [], [], []
        for name, (path, kind) in outputs.items():
            doc = _load_json(path)
            if kind == "trivy":
                vulns |= parse_trivy(doc)
                for res in doc.get("Results") or []:
                    tgt = res.get("Target", "")
                    for s in res.get("Secrets") or []:
                        secrets.append(f"{tgt}:{s.get('RuleID')}:{s.get('StartLine')}")
                    for m in res.get("Misconfigurations") or []:
                        if str(m.get("Status", "FAIL")).upper() == "FAIL":
                            misconf.append((f"{tgt}:{m.get('ID') or m.get('AVDID')}", str(m.get("Severity", "")).upper()))
            elif kind == "osv":
                vulns |= parse_osv(doc)
            elif kind == "sarif":
                for run in doc.get("runs") or []:
                    for r in run.get("results") or []:
                        if r.get("level", "warning") == "error":
                            loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
                            sast.append(f"{r.get('ruleId')}:{(loc.get('artifactLocation') or {}).get('uri')}:"
                                        f"{(loc.get('region') or {}).get('startLine')}")
        merged: dict[tuple, dict] = {}
        for f in vulns:
            m = merged.setdefault(f.key, {"id": f.vuln_id.strip().upper(), "package": f.package, "sev": set()})
            if f.severity:
                m["sev"].add(f.severity.strip().upper())
        vex = self._vex()
        kev = set()
        if "kev" in outputs:
            kev = {str(v.get("cveID", "")).strip().upper() for v in _load_json(outputs["kev"][0]).get("vulnerabilities", [])}
        review_sev = set(self.policy["untriaged_review_severities"])
        for m in merged.values():
            st = vex.get(m["id"]) or {}
            status = st.get("status")
            justified = bool(st.get("justification") or st.get("impact_statement"))
            ref = f"{m['package']} {m['id']}"
            if m["id"] in kev:
                if status == "affected":
                    self.add("KNOWN_EXPLOITED_AFFECTED", "", [ref])
                    self.add("ARTICLE14_ASSESSMENT_REQUIRED", "", [m["id"]])
                elif status == "not_affected":
                    if not justified:
                        self.add("KEV_NOT_AFFECTED_UNJUSTIFIED", "", [ref])
                elif status == "fixed":
                    self.add("VEX_CONTRADICTS_SCAN", "", [ref])
                    self.add("ARTICLE14_ASSESSMENT_REQUIRED", "", [m["id"]])
                else:
                    self.add("KEV_TRIAGE_PENDING", "", [ref])
                    self.add("ARTICLE14_ASSESSMENT_REQUIRED", "", [m["id"]])
                continue
            if not m["id"].startswith("CVE-") and status not in ("not_affected", "fixed"):
                self.add("KEV_STATUS_UNKNOWN", "resolve alias or add a VEX statement", [ref])
                continue
            unknown_sev = not (m["sev"] - {"UNKNOWN", "NONE", ""})
            if not (m["sev"] & review_sev or unknown_sev):
                continue
            if status == "not_affected":
                if not justified:
                    self.add("KEV_NOT_AFFECTED_UNJUSTIFIED", "non-KEV finding", [ref])
            elif status == "fixed":
                self.add("VEX_CONTRADICTS_SCAN", "", [ref])
            elif status == "affected":
                self.add("FINDING_AFFECTED_UNRESOLVED", "", [ref])
            else:
                self.add("FINDING_UNTRIAGED", "unknown severity" if unknown_sev else "", [ref])
        tri = self._triage()
        for sid in secrets:
            if ("secret", sid) not in tri:
                self.add("SECRET_FINDING", "", [sid])
        for mid, sev in misconf:
            if (sev in review_sev or sev in ("", "UNKNOWN")) and ("misconfig", mid) not in tri:
                self.add("MISCONFIG_FINDING", "", [mid])
        for aid in sast:
            if ("sast", aid) not in tri:
                self.add("SAST_FINDING", "", [aid])
        self.stats["findings_unique"] = len(merged)
        self.stats["kev_hits"] = sum(1 for m in merged.values() if m["id"] in kev)
        self.stats["secret_findings"] = len(secrets)

    # -- evidence --------------------------------------------------------------------
    def check_evidence(self) -> None:
        f = self.file("evidence-manifest.json")
        if not f.exists():
            self.add("EVIDENCE_MANIFEST_MISSING")
            return
        man = _load_json(f)
        ages = self.policy.get("evidence_max_age_days") or {}
        current_inputs = self.product.get("input_digests") or {}
        max_rids = self.policy["max_requirements_per_evidence"]
        n_ok = 0
        for rec in man.get("records", []):
            ref = str(rec.get("evidence_uri", "?"))
            bad = self.binding_ok(rec)
            if bad:
                self.add(bad, "", [ref])
                continue
            if ".." in Path(ref).parts or Path(ref).is_absolute():
                self.add("EVIDENCE_PATH_INVALID", "", [ref])
                continue
            p = self.bundle / Path(ref).name
            if not p.is_file():
                self.add("EVIDENCE_FILE_MISSING", "", [ref])
                continue
            if sha256_file(p) != rec.get("evidence_sha256"):
                self.add("EVIDENCE_INTEGRITY_FAILED", "", [ref])
                continue
            gen = _try_dt(rec.get("generated_at"))
            if rec.get("generated_at") and (gen is None or gen > self.as_of + CLOCK_SKEW):
                self.add("EVIDENCE_TIMESTAMP_INVALID", "", [ref])
                continue
            max_age = ages.get(rec.get("evidence_type") or rec.get("tool"), ages.get("default"))
            if max_age is not None:
                if gen is None:
                    self.add("EVIDENCE_TIMESTAMP_INVALID", "age rule applies but generated_at missing", [ref])
                    continue
                if (self.as_of - gen).total_seconds() / 86400 > max_age:
                    self.add("EVIDENCE_STALE_AGE", f"> {max_age} d (internal policy)", [ref])
                    continue
            rec_inputs = rec.get("input_digests") or {}
            unverifiable = [k for k in rec_inputs if k not in current_inputs]
            if unverifiable:
                self.add("EVIDENCE_INPUT_UNVERIFIABLE", ",".join(unverifiable), [ref])
                continue
            stale_input = [k for k, v in rec_inputs.items() if current_inputs[k] != v]
            if stale_input:
                self.add("EVIDENCE_STALE_INPUT_CHANGED", ",".join(stale_input), [ref])
                continue
            rids = set(rec.get("requirement_ids") or [])
            if len(rids) > max_rids:
                self.add("EVIDENCE_OVERCLAIMED", f"{len(rids)} > {max_rids}", [ref])
                continue
            slot = self.valid_evidence.setdefault(rec["evidence_sha256"], {"rids": set(), "uri": p.name, "generated_at": gen})
            slot["rids"] |= rids
            n_ok += 1
        self.stats["evidence_records"] = len(man.get("records", []))
        self.stats["evidence_valid"] = n_ok

    # -- obligations ------------------------------------------------------------------
    def check_obligations(self) -> None:
        units: dict[str, TraceUnit] = {}
        dup_ids: set[str] = set()
        f = self.file("trace-units.json")
        if f.exists():
            for d in _load_json(f):
                u = TraceUnit(**d)
                if u.requirement_id in units:
                    dup_ids.add(u.requirement_id)
                units[u.requirement_id] = u
        if dup_ids:
            self.add("TRACE_UNIT_DUPLICATE", "", sorted(dup_ids))
        gates = set(self.policy["obligation_gates"])
        today = self.as_of.date()          # as_of is normalised to UTC
        in_force, future, unverified = [], [], []
        for row in self.catalogue:
            rid = row.get("req_id", "?")
            if row.get("mandatory") not in VALID_MANDATORY or row.get("gate") not in VALID_GATES:
                self.add("CATALOGUE_ROW_INVALID", "mandatory/gate", [rid])
                continue
            if row["mandatory"] == "N" or row["gate"] not in gates:
                continue
            start = applies_from(row)
            if start is None:
                self.add("CATALOGUE_ROW_INVALID", "applies_from", [rid])
                continue
            if start > today:
                future.append(rid)
                continue
            in_force.append(rid)
            if row.get("legal_status") != "verified":
                unverified.append(rid)
            if rid in dup_ids:
                continue          # already REVIEW; never pick one silently
            u = units.get(rid)
            if u is None:
                self.add("APPLICABILITY_DECISION_MISSING", "", [rid])
                continue
            if u.product_id != self.product["product_id"] or u.build_id != self.product["build_sha"]:
                self.add("OBLIGATION_EVIDENCE_WRONG_BUILD", "", [rid])
                continue
            if not u.applicable:
                if not (u.applicability_justification.strip() and u.reviewer.strip() and _try_dt(u.reviewed_at)):
                    self.add("NA_WITHOUT_RATIONALE", "", [rid])
                continue
            if u.status == "failed":
                self.add("OBLIGATION_NOT_MET", "", [rid])
                continue
            if not u.is_complete():
                self.add("OBLIGATION_EVIDENCE_INCOMPLETE", "", [rid])
                continue
            ev = self.valid_evidence.get(u.evidence_sha256)
            if ev is None:
                self.add("OBLIGATION_EVIDENCE_NOT_IN_MANIFEST", "", [rid])
                continue
            if rid not in ev["rids"] or Path(u.evidence_uri).name != ev["uri"]:
                self.add("OBLIGATION_EVIDENCE_MISATTRIBUTED", "", [rid])
                continue
            rev = _try_dt(u.reviewed_at)
            if rev is None or rev > self.as_of + CLOCK_SKEW or (ev["generated_at"] and rev < ev["generated_at"]):
                self.add("OBLIGATION_REVIEW_INVALID", "", [rid])
        if unverified:
            self.add("LEGAL_MAPPING_REVIEW_PENDING", f"{len(unverified)} row(s)", unverified)
        if future:
            self.add("OBLIGATIONS_NOT_YET_IN_FORCE", f"{len(future)} row(s) apply after {today}", future)
        if not in_force:
            self.add("CATALOGUE_EMPTY", f"as of {today}")
        self.stats["mandatory_obligations_in_force"] = len(in_force)
        self.stats["mandatory_obligations_not_yet_in_force"] = len(future)

    # -- approvals --------------------------------------------------------------------
    def check_approvals(self) -> None:
        f = self.file("approvals.json")
        approvals = _load_json(f) if f.exists() else []
        p = self.product
        max_days = self.policy["approval_max_validity_days"]
        holders: dict[str, str] = {}
        for role in self.policy["required_approval_roles"]:
            cands = [a for a in approvals if a.get("role") == role]
            if not cands:
                self.add("APPROVAL_MISSING", "", [role])
                continue
            if any(a.get("revoked") is True and a.get("build_sha") == p["build_sha"] for a in cands):
                self.add("APPROVAL_REVOKED", "a revocation for this build overrides other approvals", [role])
                continue
            good, codes = None, []
            for a in cands:
                appr, exp = _try_dt(a.get("approved_at")), _try_dt(a.get("expires_at"))
                if a.get("build_sha") != p["build_sha"] or a.get("product_id") != p["product_id"] or any(
                        a.get(k) and p.get(k) and a[k] != p[k] for k in ("product_version", "artifact_digest")):
                    codes.append("APPROVAL_WRONG_BUILD")
                elif a.get("revoked") not in (False, None):
                    codes.append("APPROVAL_REVOKED")
                elif not str(a.get("reviewer", "")).strip():
                    codes.append("APPROVAL_MISSING")
                elif exp is None:
                    codes.append("APPROVAL_NO_EXPIRY")
                elif appr is None or appr > self.as_of + CLOCK_SKEW or (exp - appr).days > max_days:
                    codes.append("APPROVAL_INVALID")
                elif exp <= self.as_of:
                    codes.append("APPROVAL_EXPIRED")
                else:
                    good = a
            if not good:
                self.add(codes[-1] if codes else "APPROVAL_MISSING", "", [role])
                continue
            who = str(good["reviewer"]).strip().lower()
            if who in holders:
                self.add("APPROVAL_SAME_REVIEWER", f"{holders[who]} and {role}", [role])
            holders[who] = role

    # -- run ------------------------------------------------------------------
    def run(self) -> dict:
        if self.scope == "security":
            # research/replay use (E9): scan + finding checks only; never eligible for conformity review
            self.add("SCOPE_SECURITY_ONLY")
            self.check_policy_security()
            if self.check_product():
                self.check_findings(self.check_scans())
            return self.decision()
        self.check_policy()
        if self.check_product():
            outputs = self.check_scans()
            self.check_findings(outputs)
            self.check_evidence()
            self.check_obligations()
            self.check_approvals()
        return self.decision()

    def check_policy_security(self) -> None:
        """Scan/finding floors only (catalogue, approvals and obligations are out of scope)."""
        pol = self.policy
        for key, minimum in (("required_scans", MIN_REQUIRED_SCANS), ("untriaged_review_severities", MIN_REVIEW_SEVERITIES)):
            have = set(pol.get(key) or [])
            if not minimum <= have:
                self.add("POLICY_BELOW_MINIMUM", f"{key} lacks {sorted(minimum - have)}", [key])
                pol[key] = sorted(have | minimum)
        if not isinstance(pol.get("kev_min_entries"), int) or pol["kev_min_entries"] <= 0:
            self.add("POLICY_BELOW_MINIMUM", "kev_min_entries must be a positive integer", ["kev_min_entries"])
            pol["kev_min_entries"] = DEFAULT_POLICY["kev_min_entries"]

    def decision(self) -> dict:
        sev = {r.severity for r in self.reasons}
        verdict = FAIL if SEV_FAIL in sev else REVIEW if SEV_REVIEW in sev else PASS
        digests = {}
        if self.bundle.is_dir():
            for p in sorted(self.bundle.iterdir()):
                if p.is_file() and p.suffix in (".json", ".yaml", ".yml", ".sarif", ".md") and p.name not in ("decision.json", "decision.md"):
                    digests[p.name] = sha256_file(p)
        order = {SEV_FAIL: 0, SEV_REVIEW: 1, SEV_INFO: 2}
        reasons = sorted(self.reasons, key=lambda r: (order[r.severity], r.code))
        prod = self.product if isinstance(self.product, dict) else {}
        return {
            "schema_version": SCHEMA_VERSION,
            "engine": f"crasme.gate {__version__}",
            "product_id": prod.get("product_id"),
            "product_version": prod.get("product_version"),
            "build_sha": prod.get("build_sha"),
            "artifact_digest": prod.get("artifact_digest"),
            "decision": verdict,
            "reasons": [r.code for r in reasons if r.severity != SEV_INFO],
            "details": [r.to_dict() for r in reasons],
            "stats": self.stats,
            "scope": self.scope,
            "eligible_for_human_conformity_review": verdict == PASS and self.scope == "full",
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
             catalogue: list[dict] | None = None, expect_build: str | None = None,
             expect_product: str | None = None, scope: str = "full") -> dict:
    as_of = as_of or datetime.now(timezone.utc)
    pol = policy if policy is not None else load_policy(None)
    try:
        return Engine(bundle, pol, as_of, catalogue if catalogue is not None else load_catalogue(),
                      expect_build, expect_product, scope).run()
    except Exception as e:  # fail safe: never PASS on engine error
        eng = Engine(bundle, pol if isinstance(pol, dict) else {}, as_of, [])
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
    ap.add_argument("--bundle")
    ap.add_argument("--policy")
    ap.add_argument("--catalogue", default=str(CATALOGUE_PATH))
    ap.add_argument("--as-of", help="ISO date/time to assess against (default: now). Use 2027-12-11 for readiness checks")
    ap.add_argument("--expect-build", help="build SHA the CI run is building (e.g. $GITHUB_SHA)")
    ap.add_argument("--expect-product", help="product id the CI run is building")
    ap.add_argument("--print-catalogue-digest", action="store_true", help="print the digest to pin in policy and exit")
    ap.add_argument("--out", default=None)
    ap.add_argument("--report", default=None)
    a = ap.parse_args(argv)
    if a.print_catalogue_digest:
        print(catalogue_digest(load_catalogue(a.catalogue)))
        return 0
    if not a.bundle:
        ap.error("--bundle is required")
    as_of = _parse_dt(a.as_of) if a.as_of else None
    code = None
    try:
        pol = load_policy(a.policy)
        cat = load_catalogue(a.catalogue)
    except Exception as e:
        print(f"cannot load policy/catalogue: {e}", file=sys.stderr)
        eng = Engine(a.bundle, DEFAULT_POLICY, as_of or datetime.now(timezone.utc), [])
        eng.add("ENGINE_ERROR", f"config: {type(e).__name__}: {e}")
        d = eng.decision()
        code = 3
    else:
        d = evaluate(a.bundle, pol, as_of, cat, a.expect_build, a.expect_product)
        code = 3 if "ENGINE_ERROR" in d["reasons"] else {PASS: 0, FAIL: 1, REVIEW: 2}[d["decision"]]
    out = Path(a.out) if a.out else Path(a.bundle) / "decision.json"
    out.write_text(json.dumps(d, indent=2), encoding="utf-8")
    if a.report:
        Path(a.report).write_text(render_markdown(d), encoding="utf-8")
    print(f"{d['decision']}: {', '.join(d['reasons']) or 'no blocking reasons'} -> {out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
