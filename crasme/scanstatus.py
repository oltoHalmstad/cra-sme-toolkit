"""Scanner execution-status records (v1.2, recommendation P0-01).

A missing, failed, timed-out, truncated or empty scan output is never a clean
result. Each required scan is recorded with an explicit status, and the release
decision engine (``crasme.gate``) treats any status other than OK as
REVIEW_REQUIRED.

Tool exit codes are normalised separately from execution errors, because some
tools use a non-zero exit code to mean "findings present".
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0"

OK = "OK"
FAILED = "FAILED"          # process error / non-zero exit not documented as "findings"
TIMEOUT = "TIMEOUT"
MISSING = "MISSING"        # expected output file absent
INVALID = "INVALID"        # output present but malformed, truncated or semantically empty
SKIPPED = "SKIPPED"        # deliberately not run (must be optional, else gate escalates)
STATUSES = {OK, FAILED, TIMEOUT, MISSING, INVALID, SKIPPED}

# Exit codes that mean "ran correctly" (documented behaviour; re-check on tool upgrades).
# osv-scanner v2: 0 = no vulns, 1 = vulns found, 127 = general error, 128 = no packages found.
# semgrep: 0 = ok, 1 = findings (with --error), >=2 = error.
SUCCESS_EXIT_CODES = {
    "syft": {0}, "trivy": {0}, "cdxgen": {0}, "cyclonedx-py": {0}, "cyclonedx-npm": {0},
    "osv-scanner": {0, 1}, "semgrep": {0, 1}, "grype": {0, 1}, "curl": {0}, "action": {0},
}
NAMED_EXIT_ERRORS = {("osv-scanner", 128): "NO_PACKAGES_FOUND", ("osv-scanner", 127): "TOOL_ERROR"}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest_paths(paths: list[str | Path]) -> str | None:
    """Combined digest over input files, keyed by file NAME (location-independent, so a CI path
    and the flattened evidence bundle give the same value); None if any file is missing."""
    h = hashlib.sha256()
    for pp in sorted((Path(x) for x in paths), key=lambda q: q.name):
        if not pp.is_file():
            return None
        h.update(pp.name.encode() + b"\0" + hashlib.sha256(pp.read_bytes()).digest())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Output validators: return (status, error_code, finding_count)
# ---------------------------------------------------------------------------
def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except UnicodeDecodeError:
        return None, "NOT_UTF8"
    except json.JSONDecodeError:
        return None, "MALFORMED_JSON"


def validate_output(kind: str, path: str | Path) -> tuple[str, str | None, int | None]:
    p = Path(path)
    if not p.is_file():
        return MISSING, "OUTPUT_MISSING", None
    if p.stat().st_size == 0:
        return INVALID, "OUTPUT_EMPTY", None
    doc, err = _load_json(p)
    if err:
        return INVALID, err, None
    if not isinstance(doc, dict):
        return INVALID, "UNEXPECTED_STRUCTURE", None
    if kind == "cyclonedx":
        if doc.get("bomFormat") != "CycloneDX":
            return INVALID, "NOT_CYCLONEDX", None
        n = len(doc.get("components") or [])
        return (OK, None, n) if n > 0 else (INVALID, "EMPTY_SBOM", 0)
    if kind == "trivy":
        if "SchemaVersion" not in doc or "ArtifactName" not in doc:
            return INVALID, "NOT_TRIVY_REPORT", None
        res = doc.get("Results") or []
        if not res:
            return INVALID, "NO_TARGETS", 0      # nothing was scanned: not a clean result
        n = sum(len(r.get("Vulnerabilities") or []) + len(r.get("Secrets") or [])
                + len(r.get("Misconfigurations") or []) for r in res)
        return OK, None, n
    if kind == "osv":
        if not isinstance(doc.get("results"), list):
            return INVALID, "NOT_OSV_REPORT", None
        if not doc["results"]:
            return INVALID, "NO_TARGETS", 0
        n = sum(len(pk.get("vulnerabilities") or []) for r in doc["results"] for pk in r.get("packages") or [])
        return OK, None, n
    if kind == "sarif":
        if not isinstance(doc.get("runs"), list) or not str(doc.get("version", "")).startswith("2."):
            return INVALID, "NOT_SARIF", None
        return OK, None, sum(len(r.get("results") or []) for r in doc["runs"])
    if kind == "kev":
        vulns = doc.get("vulnerabilities")
        if not isinstance(vulns, list) or "catalogVersion" not in doc:
            return INVALID, "NOT_KEV_FEED", None
        if not vulns:
            return INVALID, "EMPTY_FEED", 0
        if isinstance(doc.get("count"), int) and doc["count"] != len(vulns):
            return INVALID, "TRUNCATED_FEED", len(vulns)
        return OK, None, len(vulns)
    raise ValueError(f"unknown output kind {kind!r}")


@dataclass
class ScanRecord:
    name: str
    tool: str
    kind: str
    required: bool
    execution_status: str
    tool_version: str = "unknown"
    exit_code: int | None = None
    started_at: str = ""
    finished_at: str = ""
    input_digest: str | None = None
    output_path: str = ""
    output_digest: str | None = None
    finding_count: int | None = None
    error_code: str | None = None

    def __post_init__(self):
        if self.execution_status not in STATUSES:
            raise ValueError(f"bad status {self.execution_status}")


def classify(tool: str, kind: str, exit_code: int | None, output: str | Path, timed_out: bool = False,
             step_outcome: str | None = None) -> tuple[str, str | None, int | None]:
    """Combine process result and output validation into one status."""
    if timed_out:
        return TIMEOUT, "TIMEOUT", None
    if step_outcome is not None and step_outcome not in ("success",):
        return FAILED, f"STEP_{step_outcome.upper()}", None
    if exit_code is not None:
        named = NAMED_EXIT_ERRORS.get((tool, exit_code))
        if named:
            return (INVALID if named == "NO_PACKAGES_FOUND" else FAILED), named, None
        if exit_code not in SUCCESS_EXIT_CODES.get(tool, {0}):
            return FAILED, f"EXIT_{exit_code}", None
    return validate_output(kind, output)


@dataclass
class ScanManifest:
    product_id: str
    build_sha: str
    scans: list[ScanRecord] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "product_id": self.product_id,
                "build_sha": self.build_sha, "scans": [asdict(s) for s in self.scans]}

    @classmethod
    def load(cls, path: str | Path) -> "ScanManifest":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(d["product_id"], d["build_sha"], [ScanRecord(**s) for s in d.get("scans", [])],
                   d.get("schema_version", SCHEMA_VERSION))

    def upsert(self, rec: ScanRecord) -> None:
        self.scans = [s for s in self.scans if s.name != rec.name] + [rec]

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Redaction (P1-05): secret-scanner output must not re-publish the secret
# ---------------------------------------------------------------------------
MASK = "***REDACTED***"


def redact_trivy_secrets(doc: dict) -> tuple[dict, int]:
    """Mask matched secret values and code excerpts in a Trivy JSON report."""
    n = 0
    for res in doc.get("Results") or []:
        for s in res.get("Secrets") or []:
            if "Match" in s:
                s["Match"] = MASK
                n += 1
            for line in ((s.get("Code") or {}).get("Lines") or []):
                for k in ("Content", "Highlighted"):
                    if k in line:
                        line[k] = MASK
    return doc, n
