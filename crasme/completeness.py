"""Inventory completeness checks (E9-G, post-hoc; see experiments/e9_release_replay/E9G-PROTOCOL.md).

A fail-safe gate catches *missing* or *invalid* evidence. These rules target the remaining gap found in E9:
an inventory that is present and well-formed but does not represent the product. Each rule returns a
REVIEW-level reason; none can turn a release into PASS.
"""
from __future__ import annotations

import urllib.parse
from typing import Iterable

from crasme.replay import Pkg, norm_pypi

DECLARED_ECO = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io", "hex": "Hex", "c": None}
INCOMPLETE_METHODS = ("no-package-manifest", "resolve-in-ci (rebar3")
COVERAGE_MIN = 0.50
MIN_INDEPENDENT = 10
REASONS = {
    "INVENTORY_METHOD_INCOMPLETE": "inventory produced by a method known to be incomplete for this product",
    "INVENTORY_ECOSYSTEM_MISSING": "the product's declared build ecosystem contributes no components",
    "INVENTORY_CROSSCHECK_LOW": "an independent SBOM of the same checkout is mostly absent from the inventory",
}
_PURL = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io", "hex": "Hex"}


def purl_key(purl: str) -> tuple[str, str] | None:
    """(OSV ecosystem, inventory-style name) from a package URL, or None for unsupported types."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    typ, _, rest = body.partition("/")
    eco = _PURL.get(typ.lower())
    if eco is None:
        return None
    path = urllib.parse.unquote(rest.rsplit("@", 1)[0] if "@" in rest.lstrip("@") else rest)
    if eco == "npm" and path.startswith("@") is False and "/" in path and path.split("/")[0].startswith("%40"):
        path = urllib.parse.unquote(path)
    if eco == "Maven":
        parts = path.split("/")
        name = ":".join(parts[-2:]) if len(parts) >= 2 else path
    elif eco == "PyPI":
        name = norm_pypi(path)
    else:
        name = path
    return eco, name


def coverage(inventory: Iterable[Pkg], independent: Iterable[tuple[str, str]], eco: str) -> tuple[float | None, int]:
    inv = {p.name for p in inventory if p.ecosystem == eco}
    ind = {n for e, n in independent if e == eco}
    if len(ind) < MIN_INDEPENDENT:
        return None, len(ind)
    return len(ind & inv) / len(ind), len(ind)


def check(inventory_all: list[Pkg], method: str, declared: str, independent: list[tuple[str, str]]) -> list[dict]:
    """Completeness reasons for one release. `inventory_all` includes development dependencies."""
    out = []
    if method.startswith(INCOMPLETE_METHODS):
        out.append({"code": "INVENTORY_METHOD_INCOMPLETE", "detail": method})
    eco = DECLARED_ECO.get(declared)
    if eco is not None:
        n = sum(p.ecosystem == eco for p in inventory_all)
        if n == 0:
            out.append({"code": "INVENTORY_ECOSYSTEM_MISSING", "detail": eco})
        cov, n_ind = coverage(inventory_all, independent, eco)
        if cov is not None and cov < COVERAGE_MIN:
            out.append({"code": "INVENTORY_CROSSCHECK_LOW", "detail": f"{eco} coverage {cov:.2f} of {n_ind} independent components"})
    return out
