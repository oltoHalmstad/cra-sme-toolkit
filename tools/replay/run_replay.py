"""Run the E9 replay offline from frozen inventories + cached OSV/KEV/registry data.

    python tools/replay/run_replay.py --e9 experiments/e9_release_replay --cache <cache> --out <results>
        [--include-dev] [--limit-products a,b]

Outputs (CSV):
  release_metrics.csv  one row per release: inventory status, known/later vulns, KEV, gate decisions
  findings.csv         one row per (release, affecting vulnerability)
  exposure.csv         per (product, vulnerability published after release): days until a later
                       sampled release no longer contains an affected version (quarterly granularity)
  drift.csv            Jaccard similarity of consecutive release inventories per product
  engine_reasons.csv   reason codes from the v1.2 engine per release (security scope)
"""
import argparse
import csv
import json
import sys
import tarfile
import tempfile
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme import replay as R  # noqa: E402


def load_inventory(path: Path, include_dev: bool) -> list[R.Pkg]:
    if not path.exists():
        return []
    return [R.Pkg(r["ecosystem"], r["name"], r["version"], r["dev"] == "True") for r in csv.DictReader(open(path))
            if include_dev or r["dev"] != "True"]


class OSVCache:
    def __init__(self, cache: Path):
        self.cache = cache
        self._v = {}

    def vulns_for(self, eco: str, name: str) -> list[dict]:
        idx = self.cache / "osv/index" / eco / f"{urllib.parse.quote(name, safe='')}.json"
        if not idx.exists():
            return None          # not fetched -> coverage gap, not "no vulnerabilities"
        out = []
        for i in json.loads(idx.read_text()):
            if i not in self._v:
                f = self.cache / "osv/vulns" / f"{i}.json"
                self._v[i] = json.loads(f.read_text()) if f.exists() else None
            if self._v[i] is not None:
                out.append(self._v[i])
        return out

    def versions_published(self, eco: str, name: str) -> dict:
        f = self.cache / "versions" / eco / f"{urllib.parse.quote(name, safe='')}.json"
        if not f.exists():
            return {}
        return {(eco, name, v): R._dt(t) for v, t in json.loads(f.read_text()).items() if t and v != "__error__"}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--e9", required=True)
    ap.add_argument("--cache", required=True, help="cache directory, or a .tar.gz of one")
    ap.add_argument("--out", required=True)
    ap.add_argument("--include-dev", action="store_true")
    ap.add_argument("--limit-products")
    a = ap.parse_args(argv)
    e9, cache, out = Path(a.e9), Path(a.cache), Path(a.out)
    if cache.is_file() and cache.name.endswith(".tar.gz"):   # packed cache (keeps the archive small)
        tmp = Path(tempfile.mkdtemp(prefix="e9-cache-"))
        with tarfile.open(cache) as t:
            t.extractall(tmp, filter="data")
        cache = next((d for d in tmp.iterdir() if (d / "kev.json").exists()), tmp)
    out.mkdir(parents=True, exist_ok=True)
    kev_doc = json.loads((cache / "kev.json").read_text())
    kev = R.kev_index(kev_doc)
    osv = OSVCache(cache)
    status = {(r["product_id"], r["tag"]): r for r in csv.DictReader(open(e9 / "inventories" / "summary.csv"))}
    releases = list(csv.DictReader(open(e9 / "releases.csv")))
    if a.limit_products:
        keep = set(a.limit_products.split(","))
        releases = [r for r in releases if r["product_id"] in keep]
    metrics, findings, reasons = [], [], []
    per_product = defaultdict(list)
    for rel in releases:
        pid, tag = rel["product_id"], rel["tag"]
        when = R._dt(rel["release_date_utc"])
        pkgs = load_inventory(e9 / "inventories" / pid / f"{tag}.csv", a.include_dev)
        vulns_by_pkg, vpub, unfetched, undecidable = {}, {}, 0, []
        for p in pkgs:
            vs = osv.vulns_for(p.ecosystem, p.name)
            if vs is None:
                unfetched += 1
                continue
            vulns_by_pkg[p] = vs
            vpub.update(osv.versions_published(p.ecosystem, p.name))
        rr = R.replay_release(pid, tag, when, pkgs, vulns_by_pkg, kev, vpub)
        for p, vs in vulns_by_pkg.items():
            for v in vs:
                if R.affects(v, p) is None and R.known_at(v, when):
                    undecidable.append((p, v.get("id"), frozenset(v.get("aliases") or [])))
        d = R.engine_decision(rr, pkgs, rel["commit_sha"], kev_doc, undecidable)
        if unfetched and d["decision"] == "PASS":
            # vulnerability data missing for part of the inventory: never a clean result
            d["decision"], d["reasons"] = "REVIEW_REQUIRED", d["reasons"] + ["E9_VULN_DATA_INCOMPLETE"]
        m = R.release_metrics(rr)
        st = status.get((pid, tag), {})
        m.update({"inventory_status": st.get("inventory_status", "?"), "unfetched_packages": unfetched,
                  "gate_crasme_v1_2": d["decision"], "crasme_reasons": " ".join(d["reasons"])})
        metrics.append(m)
        reasons += [{"product_id": pid, "tag": tag, "code": x["code"], "severity": x["severity"], "n_refs": len(x["refs"])}
                    for x in d["details"]]
        for kind, lst in (("known", rr.known), ("later", rr.later)):
            for f in lst:
                findings.append({"product_id": pid, "tag": tag, "release_date": when.date().isoformat(), "status": kind,
                                 "vuln_id": f.vuln_id, "aliases": " ".join(sorted(f.aliases)), "ecosystem": f.pkg.ecosystem,
                                 "package": f.pkg.name, "version": f.pkg.version,
                                 "published": f.published.date().isoformat() if f.published else "",
                                 "kev_added_by_release": f.kev_added.date().isoformat() if f.kev_added else "",
                                 "kev_added_ever": f.kev_added_ever.date().isoformat() if f.kev_added_ever else "",
                                 "cvss": f.score, "fix_available_at_release": f.fix_available_at_release})
        per_product[pid].append((when, tag, {(p.ecosystem, p.name, p.version) for p in pkgs}, rr))
        print(f"{pid:15s} {tag:12s} comps={len(pkgs):5d} known={len(rr.known):4d} kev={m['known_kev']:3d} "
              f"naive={m['gate_naive_kev']:4s} cvss7={m['gate_cvss7']:4s} crasme={d['decision']}")
    # exposure windows and drift
    exposure, drift = [], []
    for pid, seq in per_product.items():
        seq.sort(key=lambda x: x[0])
        for i in range(1, len(seq)):
            a_, b_ = seq[i - 1][2], seq[i][2]
            drift.append({"product_id": pid, "from_tag": seq[i - 1][1], "to_tag": seq[i][1],
                          "jaccard": (len(a_ & b_) / len(a_ | b_)) if (a_ | b_) else None,
                          "added": len(b_ - a_), "removed": len(a_ - b_)})
        for i, (when, tag, comps, rr) in enumerate(seq):
            for f in rr.later:
                fixed_in = next((t2 for w2, t2, c2, rr2 in seq[i + 1:]
                                 if w2 >= (f.published or w2) and not any(g.vuln_id == f.vuln_id for g in rr2.known + rr2.later)), None)
                w_fix = next((w2 for w2, t2, c2, rr2 in seq[i + 1:] if t2 == fixed_in), None)
                exposure.append({"product_id": pid, "tag": tag, "vuln_id": f.vuln_id, "package": f.pkg.name,
                                 "published": f.published.date().isoformat() if f.published else "",
                                 "kev_added": f.kev_added_ever.date().isoformat() if f.kev_added_ever else "",
                                 "first_sampled_release_without": fixed_in or "",
                                 "days_published_to_fixed_release": (w_fix - f.published).days if (w_fix and f.published) else ""})
    for name, rows in (("release_metrics", metrics), ("findings", findings), ("exposure", exposure),
                       ("drift", drift), ("engine_reasons", reasons)):
        if rows:
            with open(out / f"{name}.csv", "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
    (out / "RUN.json").write_text(json.dumps({"run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                              "releases": len(metrics), "include_dev": a.include_dev,
                                              "cache_manifest": json.loads((cache / "MANIFEST.json").read_text())
                                              if (cache / "MANIFEST.json").exists() else None}, indent=2))
    print(f"wrote results for {len(metrics)} releases -> {out}")


if __name__ == "__main__":
    main()
