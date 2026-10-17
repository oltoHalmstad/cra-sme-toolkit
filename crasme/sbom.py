"""SBOM parsing and accuracy metrics (experiment E1, RQ4).

Parses CycloneDX JSON (1.4-1.6) and SPDX 2.x JSON, normalises package URLs,
and compares generator output against a ground-truth dependency list.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote

_PEP503 = re.compile(r"[-_.]+")


@dataclass(frozen=True)
class Component:
    ecosystem: str          # purl type, e.g. pypi, npm, maven, golang
    namespace: str
    name: str
    version: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.ecosystem, self.namespace, self.name, self.version)

    @property
    def name_key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.namespace, self.name)


def normalise_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return _PEP503.sub("-", name).lower()
    if ecosystem in ("npm", "nuget", "golang", "cargo", "gem", "composer"):
        return name.lower() if ecosystem in ("nuget", "composer") else name
    return name


def parse_purl(purl: str) -> Component | None:
    """Minimal purl parser: pkg:type/namespace/name@version?qualifiers#subpath."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    version = ""
    if "@" in body:
        body, version = body.rsplit("@", 1)
    parts = [unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    eco = parts[0].lower()
    name = parts[-1]
    ns = "/".join(parts[1:-1])
    if eco == "pypi":
        ns = ""
    return Component(eco, ns.lower() if eco in ("maven",) else ns, normalise_name(eco, name), unquote(version))


def _walk_cdx(components: list[dict]) -> Iterable[dict]:
    for c in components or []:
        yield c
        yield from _walk_cdx(c.get("components", []))


def load_sbom(path: str | Path) -> tuple[set[Component], dict]:
    """Return (components, metadata) for a CycloneDX or SPDX JSON document."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    comps: set[Component] = set()
    meta: dict = {"path": str(path)}
    if doc.get("bomFormat") == "CycloneDX":
        meta["format"] = f"CycloneDX {doc.get('specVersion')}"
        tools = (doc.get("metadata") or {}).get("tools")
        if isinstance(tools, dict):  # CycloneDX 1.5+
            tools = tools.get("components", [])
        meta["tools"] = [f"{t.get('name')} {t.get('version', '')}".strip() for t in tools or []]
        root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
        for c in _walk_cdx(doc.get("components", [])):
            if c.get("bom-ref") == root or c.get("type") in ("file",):
                continue
            p = parse_purl(c.get("purl", ""))
            if p:
                comps.add(p)
    elif "spdxVersion" in doc:
        meta["format"] = doc["spdxVersion"]
        meta["tools"] = [c for c in (doc.get("creationInfo") or {}).get("creators", []) if c.startswith("Tool")]
        for pkg in doc.get("packages", []):
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    p = parse_purl(ref.get("referenceLocator", ""))
                    if p:
                        comps.add(p)
    else:
        raise ValueError(f"{path}: not a CycloneDX or SPDX JSON document")
    meta["n_components"] = len(comps)
    return comps, meta


def load_ground_truth(path: str | Path) -> set[Component]:
    """CSV with header ecosystem,namespace,name,version (one installed package per row)."""
    import csv
    out = set()
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            eco = row["ecosystem"].strip().lower()
            out.add(Component(eco, (row.get("namespace") or "").strip(),
                              normalise_name(eco, row["name"].strip()), row["version"].strip()))
    return out


def accuracy(found: set[Component], truth: set[Component], level: str = "version") -> dict[str, float]:
    """Precision / recall / F1 at version level (exact) or name level (ignores version)."""
    if level == "name":
        f = {c.name_key for c in found}
        t = {c.name_key for c in truth}
    else:
        f = {c.key for c in found}
        t = {c.key for c in truth}
    tp = len(f & t)
    fp = len(f - t)
    fn = len(t - f)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 1.0


def diff_report(found: set[Component], truth: set[Component]) -> dict[str, list[str]]:
    fk, tk = {c.key for c in found}, {c.key for c in truth}
    fmt = lambda k: f"{k[0]}:{(k[1] + '/') if k[1] else ''}{k[2]}@{k[3]}"
    return {"missing": sorted(fmt(k) for k in tk - fk), "extra": sorted(fmt(k) for k in fk - tk)}
