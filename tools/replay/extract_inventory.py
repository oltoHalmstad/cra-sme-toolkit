"""Extract component inventories from lockfiles at each frozen release commit.

    python tools/replay/extract_inventory.py --mirrors <bare-mirrors> \
        --products experiments/e9_release_replay/products.yaml \
        --releases experiments/e9_release_replay/releases.csv \
        --out experiments/e9_release_replay/inventories
Writes <out>/<product>/<tag>.csv (ecosystem,name,version,dev,source) and <out>/summary.csv.
Works on treeless partial clones: trees/blobs are fetched lazily from GitHub.
Dev dependencies are kept and flagged (dev=True); analysis excludes them by default.
"""
import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme.replay import parser_for  # noqa: E402


def git(mirror, *args, timeout=900, retries=3):
    """git with retries: lazy fetches from the promisor remote occasionally fail transiently."""
    for _ in range(retries):
        r = subprocess.run(["git", "-C", str(mirror), *args], capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r
    return r


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mirrors", required=True)
    ap.add_argument("--products", required=True)
    ap.add_argument("--releases", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    prods = {p["id"]: p for p in yaml.safe_load(open(a.products))["products"]}
    out = Path(a.out)
    summary = []
    for r in csv.DictReader(open(a.releases)):
        p = prods[r["product_id"]]
        mirror = Path(a.mirrors) / (p["repo"].replace("/", "_") + ".git")
        pats = [re.compile(x) for x in p.get("inventory") or []]
        status, n, files_used, err = p.get("inventory_mode", "lockfile"), 0, [], ""
        rows = []
        if pats:
            ls = git(mirror, "ls-tree", "-r", "--name-only", r["commit_sha"])
            if ls.returncode:
                status, err = "error", ls.stderr[-200:]
            else:
                files = [f for f in ls.stdout.splitlines() if any(x.search(f) for x in pats)]
                for f in files:
                    blob = git(mirror, "show", f"{r['commit_sha']}:{f}")
                    parse = parser_for(f)
                    if blob.returncode or parse is None:
                        err += f"{f}: unreadable; "
                        continue
                    try:
                        pk = parse(blob.stdout)
                    except Exception as e:  # record, do not hide
                        err += f"{f}: {type(e).__name__}; "
                        continue
                    files_used.append(f)
                    rows += [{"ecosystem": x.ecosystem, "name": x.name, "version": x.version, "dev": x.dev, "source": f} for x in pk]
                status = "lockfile" if rows else ("lockfile-missing" if not files else "lockfile-empty")
        d = out / r["product_id"]
        d.mkdir(parents=True, exist_ok=True)
        uniq = {(x["ecosystem"], x["name"], x["version"]): x for x in rows}
        with open(d / f"{r['tag']}.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["ecosystem", "name", "version", "dev", "source"])
            w.writeheader()
            w.writerows(sorted(uniq.values(), key=lambda x: (x["ecosystem"], x["name"], x["version"])))
        n = len(uniq)
        summary.append({"product_id": r["product_id"], "tag": r["tag"], "release_date_utc": r["release_date_utc"],
                        "inventory_status": status, "n_components": n,
                        "n_runtime": sum(1 for x in uniq.values() if not x["dev"]),
                        "files": ";".join(files_used), "error": err.strip()})
        print(f"{r['product_id']:15s} {r['tag']:12s} {status:38s} {n:6d}")
    with open(out / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)


if __name__ == "__main__":
    main()
