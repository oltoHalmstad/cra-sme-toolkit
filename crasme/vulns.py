"""Normalise scanner outputs (Trivy, Grype, OSV-Scanner) for agreement studies (E2).

Findings are reduced to (package key, canonical vulnerability id). Aliases are
resolved to a CVE when the scanner reports one so GHSA/CVE duplicates collapse.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    package: str        # ecosystem-agnostic "name@version"
    vuln_id: str        # canonical id (CVE preferred)
    severity: str = ""
    scanner: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.package.lower(), self.vuln_id.upper())


def _canonical(primary: str, aliases: list[str] | None) -> str:
    ids = [primary] + list(aliases or [])
    cves = sorted(i for i in ids if i and i.upper().startswith("CVE-"))
    return (cves[0] if cves else primary).upper()


def parse_trivy(doc: dict) -> set[Finding]:
    out = set()
    for res in doc.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            out.add(Finding(f"{v.get('PkgName')}@{v.get('InstalledVersion')}",
                            _canonical(v.get("VulnerabilityID", ""), v.get("VendorIDs")),
                            (v.get("Severity") or "").upper(), "trivy"))
    return out


def parse_grype(doc: dict) -> set[Finding]:
    out = set()
    for m in doc.get("matches", []) or []:
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        aliases = [r.get("id") for r in m.get("relatedVulnerabilities", []) or []]
        out.add(Finding(f"{art.get('name')}@{art.get('version')}", _canonical(v.get("id", ""), aliases),
                        (v.get("severity") or "").upper(), "grype"))
    return out


def parse_osv(doc: dict) -> set[Finding]:
    out = set()
    for res in doc.get("results", []) or []:
        for p in res.get("packages", []) or []:
            pkg = p.get("package", {})
            for v in p.get("vulnerabilities", []) or []:
                sev = ""
                ds = v.get("database_specific") or {}
                if isinstance(ds, dict):
                    sev = str(ds.get("severity", "")).upper()
                out.add(Finding(f"{pkg.get('name')}@{pkg.get('version')}",
                                _canonical(v.get("id", ""), v.get("aliases")), sev, "osv-scanner"))
    return out


PARSERS = {"trivy": parse_trivy, "grype": parse_grype, "osv-scanner": parse_osv}


def load_findings(path: str | Path, scanner: str) -> set[Finding]:
    return PARSERS[scanner](json.loads(Path(path).read_text(encoding="utf-8")))


def agreement_table(by_scanner: dict[str, set[Finding]]) -> list[dict]:
    """Pairwise overlap of normalised finding keys."""
    keys = {s: {f.key for f in fs} for s, fs in by_scanner.items()}
    rows = []
    for a, b in combinations(sorted(keys), 2):
        inter = keys[a] & keys[b]
        union = keys[a] | keys[b]
        rows.append({"pair": f"{a} vs {b}", "a_only": len(keys[a] - keys[b]), "b_only": len(keys[b] - keys[a]),
                     "both": len(inter), "jaccard": len(inter) / len(union) if union else 1.0})
    return rows


def consensus(by_scanner: dict[str, set[Finding]], min_votes: int = 2) -> set[tuple[str, str]]:
    """Findings reported by at least ``min_votes`` scanners (a triage-priority heuristic, not ground truth)."""
    counts: dict[tuple[str, str], int] = {}
    for fs in by_scanner.values():
        for k in {f.key for f in fs}:
            counts[k] = counts.get(k, 0) + 1
    return {k for k, c in counts.items() if c >= min_votes}
