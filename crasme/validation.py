"""E9 manual validation: seeded stratified sample, blinded rater sheets, agreement and precision.

Pre-registered procedure (experiments/e9_release_replay/VALIDATION.md):

* Unit of validation = a unique (product, vulnerability, package) triple among findings that were
  *known at release* (OSV published <= release date). The same triple in later releases is the same
  question, so it is validated once, at its earliest sampled release.
* Strata: ``known_kev`` (KEV-listed by the release date) and ``known_high`` (CVSS >= 7.0, not KEV).
* n = 30 per stratum, drawn with ``random.Random(2026)``; if a stratum has fewer units, all are taken.
* Raters see neither the stratum nor the other rater's labels. Items are presented in one shared,
  seeded random order that mixes the strata.
* Labels: PLAUSIBLE (affected code plausibly reachable/shipped in the product), NOT_PLAUSIBLE
  (e.g. dev/test-only path, unused feature, platform not shipped), UNDETERMINED.
* Cohen's kappa (unweighted, 3 categories) is computed on the independent labels, before adjudication.
* Precision = PLAUSIBLE / (PLAUSIBLE + NOT_PLAUSIBLE) on adjudicated labels, per stratum, with 95 % Wilson
  CI. UNDETERMINED is reported separately; sensitivity: count UNDETERMINED as NOT_PLAUSIBLE.
"""
from __future__ import annotations

import csv
import math
import random
from collections import Counter
from pathlib import Path
from typing import Iterable

from crasme.agreement import weighted_kappa

SEED = 2026
N_PER_STRATUM = 30
HIGH = 7.0
LABELS = ("PLAUSIBLE", "NOT_PLAUSIBLE", "UNDETERMINED")
RATER_FIELDS = ["item_id", "product_id", "repo", "tag", "commit_sha", "release_date", "ecosystem", "package",
                "version", "vuln_id", "aliases", "osv_url", "source_url",
                "label", "evidence", "minutes_spent"]


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _cvss(x) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def stratum(row: dict) -> str | None:
    if row.get("status") != "known":
        return None
    if row.get("kev_added_by_release"):
        return "known_kev"
    s = _cvss(row.get("cvss"))
    if s is not None and s >= HIGH:
        return "known_high"
    return None


def units(findings: Iterable[dict], releases: Iterable[dict]) -> dict[str, list[dict]]:
    """Unique (product, vuln, package) units per stratum, at their earliest release (deterministic)."""
    rel = {(r["product_id"], r["tag"]): r for r in releases}
    best: dict[tuple, dict] = {}
    for f in findings:
        s = stratum(f)
        if s is None:
            continue
        key = (f["product_id"], f["vuln_id"], f["ecosystem"], f["package"])
        cur = best.get(key)
        # KEV wins over HIGH for the same unit; then earliest release; then tag for determinism
        rank = (0 if s == "known_kev" else 1, f["release_date"], f["tag"])
        if cur is None or rank < cur["_rank"]:
            r = rel.get((f["product_id"], f["tag"]), {})
            best[key] = {**f, "stratum": s, "_rank": rank, "repo": r.get("repo", ""), "commit_sha": r.get("commit_sha", "")}
    out: dict[str, list[dict]] = {"known_kev": [], "known_high": []}
    for key in sorted(best):
        u = best[key]
        out[u["stratum"]].append(u)
    return out


def draw(findings: Iterable[dict], releases: Iterable[dict], n: int = N_PER_STRATUM, seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    pool = units(findings, releases)
    picked = []
    for s in ("known_kev", "known_high"):          # fixed stratum order -> reproducible
        lst = pool[s]
        picked += lst if len(lst) <= n else rng.sample(lst, n)
    rng.shuffle(picked)                            # mixed, blinded presentation order
    rows = []
    for i, u in enumerate(picked, 1):
        rows.append({
            "item_id": f"V{i:03d}", "stratum": u["stratum"], "product_id": u["product_id"], "repo": u["repo"],
            "tag": u["tag"], "commit_sha": u["commit_sha"], "release_date": u["release_date"],
            "ecosystem": u["ecosystem"], "package": u["package"], "version": u["version"], "vuln_id": u["vuln_id"],
            "aliases": u["aliases"], "cvss": u.get("cvss", ""), "kev_added_by_release": u.get("kev_added_by_release", ""),
            "osv_url": f"https://osv.dev/vulnerability/{u['vuln_id']}",
            "source_url": f"https://github.com/{u['repo']}/tree/{u['commit_sha']}" if u["repo"] and u["commit_sha"] else "",
        })
    return rows


def write_kit(rows: list[dict], out: Path, raters=("A", "B")) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "sample_key.csv", "w", newline="") as fh:        # NOT given to raters (has stratum)
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["item_id"])
        w.writeheader()
        w.writerows(rows)
    for r in raters:
        with open(out / f"rater_{r}.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=RATER_FIELDS, extrasaction="ignore")
            w.writeheader()
            w.writerows([{**x, "label": "", "evidence": "", "minutes_spent": ""} for x in rows])


def _labels(path: Path) -> dict[str, str]:
    out = {}
    for r in csv.DictReader(open(path)):
        lab = (r.get("label") or "").strip().upper()
        if lab not in LABELS:
            raise ValueError(f"{path.name} {r['item_id']}: label {lab!r} not in {LABELS}")
        out[r["item_id"]] = lab
    return out


def cohen_kappa(a: list[str], b: list[str]) -> float:
    idx = {c: i for i, c in enumerate(LABELS)}
    return weighted_kappa([idx[x] for x in a], [idx[x] for x in b], categories=range(len(LABELS)), weights="none")


def kappa_ci(a: list[str], b: list[str], n_boot: int = 2000, seed: int = SEED) -> tuple[float, float]:
    rng = random.Random(seed)
    n, ks = len(a), []
    for _ in range(n_boot):
        ix = [rng.randrange(n) for _ in range(n)]
        aa, bb = [a[i] for i in ix], [b[i] for i in ix]
        if len(set(aa) | set(bb)) > 1:
            ks.append(cohen_kappa(aa, bb))
    ks.sort()
    return (ks[int(0.025 * len(ks))], ks[int(0.975 * len(ks)) - 1]) if ks else (float("nan"), float("nan"))


def score(key: Path, rater_a: Path, rater_b: Path, adjudicated: Path | None = None) -> dict:
    strata = {r["item_id"]: r["stratum"] for r in csv.DictReader(open(key))}
    la, lb = _labels(rater_a), _labels(rater_b)
    if set(la) != set(strata) or set(lb) != set(strata):
        raise ValueError("rater sheets must label exactly the items in sample_key.csv")
    ids = sorted(strata)
    a, b = [la[i] for i in ids], [lb[i] for i in ids]
    disagree = [i for i in ids if la[i] != lb[i]]
    if adjudicated is not None:
        final = _labels(adjudicated)
        if set(final) != set(strata):
            raise ValueError("adjudicated sheet must label every item")
    elif disagree:
        final = None
    else:
        final = la
    res = {"n_items": len(ids), "observed_agreement": sum(x == y for x, y in zip(a, b)) / len(ids) if ids else None,
           "cohen_kappa": cohen_kappa(a, b) if ids else None, "kappa_95ci": kappa_ci(a, b) if ids else None,
           "n_disagreements": len(disagree), "disagreements": disagree, "per_stratum": {}}
    if final is None:
        res["note"] = "disagreements present: adjudicate (adjudicated.csv) before precision is computed"
        return res
    for s in ("known_kev", "known_high", "all"):
        labs = [final[i] for i in ids if s == "all" or strata[i] == s]
        c = Counter(labs)
        k, n = c["PLAUSIBLE"], c["PLAUSIBLE"] + c["NOT_PLAUSIBLE"]
        res["per_stratum"][s] = {
            "n": len(labs), **{x: c[x] for x in LABELS},
            "precision": k / n if n else None, "precision_95ci": wilson(k, n),
            "precision_undetermined_as_not": k / len(labs) if labs else None,
            "precision_undetermined_as_not_95ci": wilson(k, len(labs)),
        }
    return res
