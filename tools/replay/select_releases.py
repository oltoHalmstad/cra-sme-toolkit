"""Freeze the E9 release sample from git history (pre-registered selection rule).

Rule (see experiments/e9_release_replay/PREREGISTRATION.md §3):
  * stable tags only: ^v?\\d+(\\.\\d+){1,3}$ (no rc/beta/alpha/dev/b.N/nightly, no vendor prefixes)
  * release date = committer date of the tagged commit (UTC)
  * window 2024-10-01 .. 2026-09-30 split into 8 calendar quarters
  * per product and quarter: the latest-dated stable tag (if any) -> max 8 releases/product

    python tools/replay/select_releases.py --mirrors /path/to/bare-mirrors --products experiments/e9_release_replay/products.yaml \
        --out experiments/e9_release_replay/releases.csv
Mirrors: `git clone --bare --filter=tree:0 <repo>` (commits + tags only, small).
"""
import argparse
import csv
import re
import subprocess
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

STABLE = re.compile(r"^v?\d+(\.\d+){1,3}$")
QUARTERS = [(y, q) for y in (2024, 2025, 2026) for q in (1, 2, 3, 4) if (2024, 4) <= (y, q) <= (2026, 3)]


def quarter(d: date) -> tuple[int, int]:
    return d.year, (d.month - 1) // 3 + 1


def tags_with_dates(mirror: Path, pattern: re.Pattern = STABLE):
    out = subprocess.run(["git", "-C", str(mirror), "for-each-ref", "--format=%(refname:short)", "refs/tags"],
                         capture_output=True, text=True, check=True).stdout.split()
    rows = []
    for t in out:
        if not pattern.match(t):
            continue
        r = subprocess.run(["git", "-C", str(mirror), "log", "-1", "--format=%H %cI", f"{t}^{{commit}}"],
                           capture_output=True, text=True)
        if r.returncode or not r.stdout.strip():
            continue
        sha, iso = r.stdout.split()
        rows.append((t, sha, datetime.fromisoformat(iso).astimezone(timezone.utc)))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mirrors", required=True)
    ap.add_argument("--products", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    products = yaml.safe_load(open(a.products))["products"]
    rows = []
    for p in products:
        mirror = Path(a.mirrors) / (p["repo"].replace("/", "_") + ".git")
        tags = tags_with_dates(mirror, re.compile(p["tag_pattern"]) if p.get("tag_pattern") else STABLE)
        best = {}
        for t, sha, dt in tags:
            q = quarter(dt.date())
            if q in QUARTERS and (q not in best or dt > best[q][2]):
                best[q] = (t, sha, dt)
        for q in QUARTERS:
            if q in best:
                t, sha, dt = best[q]
                rows.append({"product_id": p["id"], "repo": p["repo"], "ecosystem": p["ecosystem"], "quarter": f"{q[0]}Q{q[1]}",
                             "tag": t, "commit_sha": sha, "release_date_utc": dt.isoformat(timespec="seconds")})
        print(f"{p['id']:16s} stable tags={len(tags):4d} selected={sum(1 for r in rows if r['product_id'] == p['id'])}")
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} releases -> {a.out}")


if __name__ == "__main__":
    main()
