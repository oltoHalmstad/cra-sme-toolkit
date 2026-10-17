"""E9 retrospective release replay: inventories, vulnerability time-travel and baseline gates.

The question: had each real release been gated when it was published, what was *knowable then*
(vulnerability published, fix available, listed as known-exploited) and what would each gate
have decided?

Data sources (fetched in CI, cached and archived with the results):
  * component inventories: lockfiles at the release commit (this module) and/or SBOM generators
  * OSV records (https://osv.dev): `published`, `withdrawn`, `affected[].ranges/versions`, aliases
  * CISA KEV catalogue: `dateAdded` per CVE

Known limitations (reported in the paper): OSV affected ranges are today's knowledge (hindsight);
OSV `published` can lag the original disclosure; lockfile inventories over-approximate what is
shipped (dev dependencies) or under-approximate it (vendored / C code).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

# ---------------------------------------------------------------------------
# Inventories from lockfiles
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Pkg:
    ecosystem: str      # OSV ecosystem name: npm, PyPI, Go, crates.io, Maven, Hex
    name: str
    version: str
    dev: bool = False

    @property
    def purl(self) -> str:
        t = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo", "Maven": "maven", "Hex": "hex"}[self.ecosystem]
        n = self.name
        if t == "npm" and n.startswith("@"):
            n = "%40" + n[1:]
        if t == "maven" and ":" in n:
            n = n.replace(":", "/")
        return f"pkg:{t}/{n}@{self.version}"


_PEP503 = re.compile(r"[-_.]+")


def norm_pypi(n: str) -> str:
    return _PEP503.sub("-", n).lower()


def parse_package_lock(text: str, include_dev: bool = False) -> set[Pkg]:
    doc = json.loads(text)
    out = set()
    if "packages" in doc:                                   # lockfile v2/v3
        for path, meta in doc["packages"].items():
            if not path or "node_modules/" not in path or meta.get("link"):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            if meta.get("version") and (include_dev or not meta.get("dev")):
                out.add(Pkg("npm", name, meta["version"], bool(meta.get("dev"))))
    else:                                                   # lockfile v1
        def walk(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version") and not str(meta["version"]).startswith(("file:", "git", "http")):
                    if include_dev or not meta.get("dev"):
                        out.add(Pkg("npm", name, meta["version"], bool(meta.get("dev"))))
                walk(meta.get("dependencies"))
        walk(doc.get("dependencies"))
    return out


_PNPM_KEY = re.compile(r"^/?(@?[^@/][^@]*?)(?:@|/)(\d[^(/]*)")


def parse_pnpm_lock(text: str, include_dev: bool = False) -> set[Pkg]:
    import yaml
    doc = yaml.safe_load(text) or {}
    out = set()
    for key, meta in (doc.get("packages") or {}).items():
        m = _PNPM_KEY.match(str(key))
        if not m:
            continue
        dev = bool((meta or {}).get("dev"))
        if include_dev or not dev:
            out.add(Pkg("npm", m.group(1), m.group(2), dev))
    return out


def parse_yarn_lock(text: str) -> set[Pkg]:
    out = set()
    header = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")):
            header = line.rstrip(":").split(",")[0].strip().strip('"')
        elif header and line.strip().startswith(("version ", "version:")):
            ver = line.split(None, 1)[1].strip().strip('"')
            name = header.rsplit("@", 1)[0] if not header.startswith("@") else "@" + header[1:].rsplit("@", 1)[0]
            name = name.split("@npm:")[0]
            if header.startswith("__metadata"):
                continue
            out.add(Pkg("npm", name, ver))
    return out


def parse_go_sum(text: str) -> set[Pkg]:
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            out.add(Pkg("Go", parts[0], parts[1]))
    return out


def parse_cargo_lock(text: str) -> set[Pkg]:
    import tomllib
    doc = tomllib.loads(text)
    return {Pkg("crates.io", p["name"], p["version"]) for p in doc.get("package", [])
            if str(p.get("source", "")).startswith("registry+")}


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)")


def parse_requirements(text: str) -> set[Pkg]:
    out = set()
    for line in text.splitlines():
        m = _REQ.match(line)
        if m:
            out.add(Pkg("PyPI", norm_pypi(m.group(1)), m.group(2)))
    return out


def parse_rebar_lock(text: str) -> set[Pkg]:
    """rebar3 lock: {<<"name">>,{pkg,<<"name">>,<<"1.2.3">>},0} — Hex packages only."""
    return {Pkg("Hex", m.group(1), m.group(2)) for m in
            re.finditer(r'\{<<"([a-z0-9_]+)">>,\s*\{pkg,\s*<<"[a-z0-9_]+">>,\s*<<"([^"]+)">>', text)}


PARSERS = {
    "package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock, "yarn.lock": parse_yarn_lock, "go.sum": parse_go_sum,
    "Cargo.lock": parse_cargo_lock, "rebar.lock": parse_rebar_lock,
}


def parser_for(path: str):
    base = path.rsplit("/", 1)[-1]
    if base in PARSERS:
        return PARSERS[base]
    if base.startswith("requirements") and base.endswith(".txt") or base == "package_constraints.txt":
        return parse_requirements
    return None


# ---------------------------------------------------------------------------
# Version comparison (ecosystem-aware, conservative)
# ---------------------------------------------------------------------------
def _semver_key(v: str):
    v = v.lstrip("v").split("+", 1)[0]
    core, _, pre = v.partition("-")
    nums = []
    for x in core.split("."):
        m = re.match(r"\d+", x)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    pre_key = (1,) if not pre else (0,) + tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))
    return tuple(nums), pre_key


class _MavenVersion:
    """Simplified Maven ComparableVersion: numbers > release(null) > qualifiers; padding = release."""
    Q = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4, "snapshot": 5,
         "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}
    PAD = (1, 6, "")

    def __init__(self, v: str):
        items = []
        for tok in re.split(r"[.\-]", v.lower()):
            if tok.isdigit():
                items.append((2, int(tok), ""))
            else:
                m = re.match(r"([a-z]*)(\d*)", tok)
                items.append((1, self.Q.get(m.group(1), 0), "" if m.group(1) in self.Q else m.group(1)))
                if m.group(2):
                    items.append((2, int(m.group(2)), ""))
        # Maven trims zero/null items that precede a qualifier or the end ("1.0-rc1" == "1-rc-1")
        kept = []
        for i, it in enumerate(items):
            if it in ((2, 0, ""), self.PAD):
                j = i + 1
                while j < len(items) and items[j] in ((2, 0, ""), self.PAD):
                    j += 1
                if j == len(items) or items[j][0] == 1:
                    continue
            kept.append(it)
        self.items = kept

    def _cmp(self, o: "_MavenVersion") -> int:
        n = max(len(self.items), len(o.items))
        a = self.items + [self.PAD] * (n - len(self.items))
        b = o.items + [self.PAD] * (n - len(o.items))
        return (a > b) - (a < b)

    def __lt__(self, o): return self._cmp(o) < 0
    def __le__(self, o): return self._cmp(o) <= 0
    def __gt__(self, o): return self._cmp(o) > 0
    def __ge__(self, o): return self._cmp(o) >= 0
    def __eq__(self, o): return self._cmp(o) == 0


def _maven_key(v: str):
    return _MavenVersion(v)


def version_key(ecosystem: str, v: str):
    if ecosystem == "PyPI":
        from packaging.version import InvalidVersion, Version
        try:
            return Version(v)
        except InvalidVersion:
            return None
    if ecosystem == "Maven":
        return _maven_key(v)
    if re.match(r"^v?\d", v or ""):
        return _semver_key(v)
    return None


def affects(vuln: dict, pkg: Pkg) -> bool | None:
    """True/False if OSV says this package version is (not) affected; None if undecidable."""
    decided_any = False
    for aff in vuln.get("affected", []):
        p = aff.get("package") or {}
        name = p.get("name", "")
        if p.get("ecosystem", "").split(":")[0] != pkg.ecosystem:
            continue
        if (norm_pypi(name) if pkg.ecosystem == "PyPI" else name) != pkg.name:
            continue
        if pkg.version in (aff.get("versions") or []):
            return True
        key = version_key(pkg.ecosystem, pkg.version)
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            if key is None:
                return None
            decided_any = True
            intro = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif intro is not None and ("fixed" in ev or "last_affected" in ev or "limit" in ev):
                    hi_raw = ev.get("fixed") or ev.get("limit") or ev.get("last_affected")
                    lo = None if intro == "0" else version_key(pkg.ecosystem, intro)
                    hi = version_key(pkg.ecosystem, hi_raw)
                    if (intro != "0" and lo is None) or hi is None:
                        return None
                    upper_ok = key <= hi if "last_affected" in ev else key < hi
                    if (lo is None or key >= lo) and upper_ok:
                        return True
                    intro = None
            if intro is not None:                    # open-ended range
                lo = None if intro == "0" else version_key(pkg.ecosystem, intro)
                if intro != "0" and lo is None:
                    return None
                if lo is None or key >= lo:
                    return True
        if aff.get("versions"):
            decided_any = True
    return False if decided_any else None


def fixed_versions(vuln: dict, pkg: Pkg) -> list[str]:
    out = []
    for aff in vuln.get("affected", []):
        p = aff.get("package") or {}
        if p.get("ecosystem", "").split(":")[0] == pkg.ecosystem and \
                (norm_pypi(p.get("name", "")) if pkg.ecosystem == "PyPI" else p.get("name")) == pkg.name:
            for rng in aff.get("ranges", []):
                out += [ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev]
    return out


# ---------------------------------------------------------------------------
# Time-travel
# ---------------------------------------------------------------------------
def _dt(s) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def known_at(vuln: dict, when: datetime) -> bool:
    pub = _dt(vuln.get("published"))
    wd = _dt(vuln.get("withdrawn"))
    return pub is not None and pub <= when and not (wd and wd <= when)


def cve_ids(vuln: dict) -> set[str]:
    return {i.upper() for i in [vuln.get("id", "")] + list(vuln.get("aliases") or []) if i.upper().startswith("CVE-")}


def kev_index(kev_doc: dict) -> dict[str, datetime]:
    return {v["cveID"].strip().upper(): _dt(v["dateAdded"]) for v in kev_doc.get("vulnerabilities", [])}


def kev_listed_at(vuln: dict, kev: dict[str, datetime], when: datetime) -> datetime | None:
    dates = [kev[c] for c in cve_ids(vuln) if c in kev and kev[c] <= when]
    return min(dates) if dates else None


# ---------------------------------------------------------------------------
# CVSS v3.x base score (FIRST spec) — for the "block on CVSS >= 7" baseline
# ---------------------------------------------------------------------------
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "C": {"H": .56, "L": .22, "N": 0}, "I": {"H": .56, "L": .22, "N": 0},
      "A": {"H": .56, "L": .22, "N": 0}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        s = m["S"]
        pr = {"N": .85, "L": .62 if s == "U" else .68, "H": .27 if s == "U" else .5}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        imp = 6.42 * iss if s == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if imp <= 0:
            return 0.0
        return _roundup(min(imp + expl, 10)) if s == "U" else _roundup(min(1.08 * (imp + expl), 10))
    except (KeyError, ValueError, IndexError):
        return None


def severity_score(vuln: dict) -> float | None:
    best = None
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            v = cvss3_base(s.get("score", ""))
            best = v if best is None or (v is not None and v > best) else best
    if best is None:
        label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        best = {"CRITICAL": 9.0, "HIGH": 7.0, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 2.0}.get(label)
    return best


# ---------------------------------------------------------------------------
# Per-release replay
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    vuln_id: str
    pkg: Pkg
    published: datetime | None
    kev_added: datetime | None          # KEV dateAdded if listed by release date
    kev_added_ever: datetime | None     # KEV dateAdded at any time (for lead-time)
    score: float | None
    fix_available_at_release: bool
    affected: bool | None
    aliases: frozenset = frozenset()


@dataclass
class ReleaseReplay:
    product_id: str
    tag: str
    release_date: datetime
    inventory_ok: bool                  # inventory obtained and non-empty
    n_components: int
    known: list[Finding] = field(default_factory=list)      # affecting + published by release date
    later: list[Finding] = field(default_factory=list)      # affecting, published after release
    undecidable: int = 0                                    # affected() returned None


def replay_release(product_id: str, tag: str, release_date: datetime, pkgs: Iterable[Pkg],
                   vulns_by_pkg: dict[Pkg, list[dict]], kev: dict[str, datetime],
                   versions_published: dict[tuple[str, str, str], datetime] | None = None) -> ReleaseReplay:
    pkgs = list(pkgs)
    rr = ReleaseReplay(product_id, tag, release_date, bool(pkgs), len(pkgs))
    for pkg in pkgs:
        for v in vulns_by_pkg.get(pkg, []):
            a = affects(v, pkg)
            if a is None:
                rr.undecidable += 1
                continue
            if not a:
                continue
            fixes = fixed_versions(v, pkg)
            fix_at = False
            if versions_published is not None:
                fix_at = any((d := versions_published.get((pkg.ecosystem, pkg.name, f))) and d <= release_date for f in fixes)
            f = Finding(v.get("id", "?"), pkg, _dt(v.get("published")), kev_listed_at(v, kev, release_date),
                        kev_listed_at(v, kev, datetime.max.replace(tzinfo=timezone.utc)), severity_score(v), fix_at, a,
                        frozenset(v.get("aliases") or []))
            (rr.known if known_at(v, release_date) else rr.later).append(f)
    return rr


# ---------------------------------------------------------------------------
# Gates compared in E9 (decision on what was knowable at the release date)
# ---------------------------------------------------------------------------
def gate_none(rr: ReleaseReplay) -> str:
    return "PASS"


def gate_naive_kev(rr: ReleaseReplay) -> str:
    """v1.1 / typical 'KEV hit' CI check: block on KEV-listed findings; missing data = clean."""
    return "FAIL" if any(f.kev_added for f in rr.known) else "PASS"


def gate_cvss7(rr: ReleaseReplay) -> str:
    """Common practice: block on any known finding with CVSS >= 7.0; missing data = clean."""
    return "FAIL" if any((f.score or 0) >= 7.0 for f in rr.known) else "PASS"


def gate_crasme_security(rr: ReleaseReplay) -> str:
    """CRA-SME v1.2 security-only semantics (no VEX/triage available retrospectively):
    empty/failed inventory -> REVIEW; KEV-listed -> REVIEW (triage + Art. 14 assessment);
    CRITICAL/HIGH or unknown severity untriaged -> REVIEW; undecidable matches -> REVIEW."""
    if not rr.inventory_ok:
        return "REVIEW_REQUIRED"
    if any(f.kev_added for f in rr.known):
        return "REVIEW_REQUIRED"
    if any(f.score is None or f.score >= 7.0 for f in rr.known):
        return "REVIEW_REQUIRED"
    if rr.undecidable:
        return "REVIEW_REQUIRED"
    return "PASS"


# Baselines re-implemented transparently. The CRA-SME v1.2 decision itself is produced by the real
# engine (crasme.gate, scope="security") via engine_decision(); gate_crasme_security() documents the
# expected semantics and is cross-checked against the engine in the tests.
GATES = {"none": gate_none, "naive_kev": gate_naive_kev, "cvss7": gate_cvss7}


def _sev_label(score):
    if score is None:
        return ""
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


def build_engine_bundle(rr: "ReleaseReplay", pkgs: list, commit_sha: str, kev_doc: dict, root, undecidable_vulns=()):
    """Write a release bundle for crasme.gate from the replayed (as-of release date) knowledge."""
    from pathlib import Path
    from .scanstatus import ScanManifest, ScanRecord, classify, digest_paths, sha256_bytes
    b = Path(root)
    b.mkdir(parents=True, exist_ok=True)
    when = rr.release_date.isoformat(timespec="seconds")
    (b / "product.json").write_text(json.dumps({"product_id": rr.product_id, "product_version": rr.tag,
                                                "build_sha": commit_sha}))
    (b / "sbom.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": p.name, "version": p.version, "purl": p.purl} for p in pkgs]}))
    by_pkg: dict = {}
    for f in rr.known:
        by_pkg.setdefault(f.pkg, []).append({"id": f.vuln_id, "aliases": sorted(f.aliases),
                                             "database_specific": {"severity": _sev_label(f.score)}})
    for pkg, vid, aliases in undecidable_vulns:                         # possibly affected -> unknown severity
        by_pkg.setdefault(pkg, []).append({"id": vid, "aliases": sorted(aliases), "database_specific": {"severity": ""}})
    (b / "vulns.json").write_text(json.dumps({"results": [{"packages": [
        {"package": {"name": p.name, "version": p.version, "ecosystem": p.ecosystem}, "vulnerabilities": v}
        for p, v in by_pkg.items()]}] if by_pkg else []}))
    entries = [v for v in kev_doc.get("vulnerabilities", []) if _dt(v.get("dateAdded")) and _dt(v["dateAdded"]) <= rr.release_date]
    (b / "kev.json").write_text(json.dumps({"title": "KEV as of release date", "catalogVersion": f"as-of-{when}",
                                            "count": len(entries), "vulnerabilities": entries}))
    man = ScanManifest(rr.product_id, commit_sha)
    for name, kind, fname, inputs in (("sbom", "cyclonedx", "sbom.cdx.json", None),
                                      ("vulns", "osv", "vulns.json", [b / "sbom.cdx.json"]),
                                      ("kev", "kev", "kev.json", None)):
        st, err, n = classify("replay", kind, 0, b / fname)
        man.upsert(ScanRecord(name=name, tool="replay", kind=kind, required=True, execution_status=st, tool_version="e9",
                              exit_code=0, started_at=when, finished_at=when, output_path=fname,
                              output_digest=sha256_bytes((b / fname).read_bytes()), finding_count=n, error_code=err,
                              input_digest=digest_paths(inputs) if inputs else None))
    man.save(b / "scan-status.json")
    return b


def engine_decision(rr: "ReleaseReplay", pkgs: list, commit_sha: str, kev_doc: dict, undecidable_vulns=()) -> dict:
    import tempfile
    from datetime import timedelta
    from .gate import evaluate, load_policy
    with tempfile.TemporaryDirectory() as td:
        b = build_engine_bundle(rr, pkgs, commit_sha, kev_doc, td, undecidable_vulns)
        return evaluate(b, load_policy(None), rr.release_date + timedelta(minutes=1), [], scope="security")


def release_metrics(rr: ReleaseReplay) -> dict:
    k = rr.known
    return {
        "product_id": rr.product_id, "tag": rr.tag, "release_date": rr.release_date.date().isoformat(),
        "inventory_ok": rr.inventory_ok, "n_components": rr.n_components,
        "known_vulns": len(k), "known_high": sum(1 for f in k if (f.score or 0) >= 7),
        "known_kev": sum(1 for f in k if f.kev_added),
        "known_fix_available": sum(1 for f in k if f.fix_available_at_release),
        "later_vulns": len(rr.later), "later_kev": sum(1 for f in rr.later if f.kev_added_ever),
        "undecidable": rr.undecidable,
        **{f"gate_{n}": g(rr) for n, g in GATES.items()},
    }
