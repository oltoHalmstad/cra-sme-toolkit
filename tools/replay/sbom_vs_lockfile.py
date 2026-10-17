"""E1-at-scale: compare a generator SBOM (Syft) of each release checkout with the lockfile inventory (CI).

    python tools/replay/sbom_vs_lockfile.py --e9 experiments/e9_release_replay --product node-red --out results/
Writes sbom_vs_lockfile_<product>.csv: per release precision/recall of Syft vs lockfile (version level),
treating the lockfile inventory as the reference for the declared dependency set.
"""
import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from resolve_ci import checkout, resolve_syft  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--e9", required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workdir", default="/tmp/e9-sbom")
    a = ap.parse_args(argv)
    e9 = Path(a.e9)
    rows = []
    for r in csv.DictReader(open(e9 / "releases.csv")):
        if r["product_id"] != a.product:
            continue
        inv = e9 / "inventories" / a.product / f"{r['tag']}.csv"
        ref = {(x["ecosystem"], x["name"], x["version"]) for x in csv.DictReader(open(inv))} if inv.exists() else set()
        src = Path(a.workdir) / f"{a.product}-{r['tag']}"
        try:
            checkout(r["repo"], r["commit_sha"], src)
            pk, err = resolve_syft(src, r["release_date_utc"])
        except Exception as e:
            pk, err = None, str(e)
        got = {(p.ecosystem, p.name, p.version) for p in (pk or set())}
        tp = len(got & ref)
        rows.append({"product_id": a.product, "tag": r["tag"], "syft_status": "ok" if pk is not None else "failed",
                     "lockfile_n": len(ref), "syft_n": len(got), "both": tp,
                     "recall_vs_lockfile": tp / len(ref) if ref else "", "precision_vs_lockfile": tp / len(got) if got else "",
                     "syft_only": len(got - ref), "error": err[-200:] if err else ""})
        print(rows[-1])
    Path(a.out).mkdir(parents=True, exist_ok=True)
    with open(Path(a.out) / f"sbom_vs_lockfile_{a.product}.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
