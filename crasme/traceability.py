"""Evidence graph, traceability coverage, freshness and release gate (O3, RQ1, RQ4).

Traceability unit (concept note §5):
(product ID, version/build, requirement ID, applicability justification, risk ID,
 control ID, test ID, evidence hash, reviewer, timestamp, status)

Key rule: release blockers come from mandatory obligations and exploitable
vulnerabilities, NEVER from a risk-score threshold.
"""
from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

_PKG = Path(__file__).resolve().parent
_REPO = _PKG.parent
# Prefer the repository copies (editable/dev use); fall back to the packaged copies (pip install).
SCHEMA_PATH = next(p for p in (_REPO / "schemas" / "trace_unit.schema.json",
                              _PKG / "_data" / "trace_unit.schema.json") if p.exists())
CATALOGUE_PATH = next(p for p in (_REPO / "data" / "cra_requirements_catalogue.csv",
                                 _PKG / "_data" / "cra_requirements_catalogue.csv") if p.exists())

VALID_STATUS = {"not_started", "in_progress", "implemented", "verified", "not_applicable", "failed"}


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class TraceUnit:
    product_id: str
    build_id: str
    requirement_id: str
    applicable: bool
    applicability_justification: str
    status: str = "not_started"
    risk_ids: list[str] = field(default_factory=list)
    control_id: str = ""
    test_id: str = ""
    evidence_uri: str = ""
    evidence_sha256: str = ""
    evidence_generated_at: str = ""      # ISO-8601 UTC
    tool: str = ""                       # e.g. "syft 1.x" — provenance
    owner: str = ""
    reviewer: str = ""
    reviewed_at: str = ""

    def is_complete(self) -> bool:
        """Complete = applicable obligation with control, test, evidence(hash), owner and human review."""
        if not self.applicable:
            return bool(self.applicability_justification.strip()) and bool(self.reviewer)
        return all([self.control_id, self.test_id, self.evidence_uri, self.evidence_sha256,
                    self.owner, self.reviewer, self.reviewed_at, self.status == "verified"])

    def to_dict(self) -> dict:
        return asdict(self)


def load_units(path: str | Path) -> list[TraceUnit]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [TraceUnit(**d) for d in data]


def validate_units(units: list[dict]) -> list[str]:
    """JSON-Schema validation; returns a list of error messages (empty = valid)."""
    import jsonschema
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    return [f"{list(e.path)}: {e.message}" for e in v.iter_errors(units)]


def load_catalogue(path: str | Path = CATALOGUE_PATH) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def coverage(units: list[TraceUnit], catalogue_ids: set[str] | None = None) -> dict:
    """Share of obligations with a complete, reviewed trace. Missing catalogue rows count as gaps."""
    by_req = {u.requirement_id: u for u in units}
    ids = catalogue_ids or set(by_req)
    missing = sorted(ids - set(by_req))
    applicable = [by_req[i] for i in ids if i in by_req and by_req[i].applicable]
    complete = [u for u in applicable if u.is_complete()]
    na_unjustified = [u.requirement_id for u in units
                      if not u.applicable and not u.applicability_justification.strip()]
    denom = len(applicable) + len(missing)
    return {"obligations": len(ids), "applicable": len(applicable), "complete": len(complete),
            "coverage": len(complete) / denom if denom else 0.0,
            "missing_decisions": missing, "unjustified_not_applicable": na_unjustified,
            "gaps": sorted(u.requirement_id for u in applicable if not u.is_complete())}


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def freshness(units: list[TraceUnit], last_change_at: str, affected: set[str] | None = None) -> dict:
    """Days by which evidence lags the last relevant product change (negative lag = fresh).

    ``affected``: requirement IDs whose evidence the change invalidates (e.g. a dependency
    bump affects SBOM / vulnerability evidence, not the support-period decision). None = all.
    """
    change = _parse(last_change_at)
    lags = []
    stale = []
    for u in units:
        if affected is not None and u.requirement_id not in affected:
            continue
        if u.applicable and u.evidence_generated_at:
            lag = (change - _parse(u.evidence_generated_at)).total_seconds() / 86400
            lags.append(lag)
            if lag > 0:
                stale.append(u.requirement_id)
    return {"median_lag_days": median(lags) if lags else None, "stale": sorted(stale),
            "stale_share": len(stale) / len(lags) if lags else None}


def verify_hashes(units: list[TraceUnit], base_dir: str | Path) -> dict[str, bool]:
    """Recompute evidence hashes; False flags tampered or replaced evidence."""
    out = {}
    for u in units:
        if u.evidence_uri and u.evidence_sha256 and not u.evidence_uri.startswith(("http://", "https://")):
            p = Path(base_dir) / u.evidence_uri
            out[u.requirement_id] = p.exists() and sha256_file(p) == u.evidence_sha256
    return out


def release_gate(units: list[TraceUnit], mandatory_ids: set[str], open_findings: list[dict],
                 build_id: str) -> dict:
    """Return blockers. Risk scores are deliberately NOT an input.

    open_findings: dicts with keys id, exploitable (bool), known_exploited (bool), accepted_rationale.
    """
    blockers = []
    by_req = {u.requirement_id: u for u in units}
    for rid in sorted(mandatory_ids):
        u = by_req.get(rid)
        if u is None:
            blockers.append(f"{rid}: no applicability decision recorded")
        elif u.applicable and not u.is_complete():
            blockers.append(f"{rid}: applicable but evidence incomplete/unreviewed")
        elif u.applicable and u.build_id != build_id:
            blockers.append(f"{rid}: evidence is for build {u.build_id}, not {build_id}")
    for f in open_findings:
        if f.get("known_exploited") or f.get("exploitable"):
            blockers.append(f"{f['id']}: known exploitable vulnerability open (Annex I Part I(2)(a))")
    return {"release_allowed": not blockers, "blockers": blockers}
