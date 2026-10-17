"""Fetch and cache the external data E9 needs (run where the internet is reachable, e.g. CI).

    python tools/replay/fetch_data.py --inventories experiments/e9_release_replay/inventories \
        --cache experiments/e9_release_replay/cache [--include-dev]

Writes (all cached, re-runs only fetch what is missing):
  cache/kev.json                     CISA KEV catalogue (+ fetched_at)
  cache/osv/index/<eco>/<name>.json  OSV ids per package (package-level query, all versions)
  cache/osv/vulns/<ID>.json          full OSV records
  cache/versions/<eco>/<name>.json   {version: publish time} from the package registry
  cache/MANIFEST.json                fetch timestamps + counts (archive this with the results)
Uses only the Python standard library (HTTPS proxy honoured via env).
"""
import argparse
import concurrent.futures as cf
import csv
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

UA = {"User-Agent": "cra-sme-e9-replay/1.3 (research; https://github.com/oltoHalmstad/cra-sme-toolkit)"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def http(url, data=None, retries=4):
    for i in range(retries):
        try:
            req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                         headers={**UA, **({"Content-Type": "application/json"} if data is not None else {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if i == retries - 1:
                raise
        except Exception:
            if i == retries - 1:
                raise
        time.sleep(2 ** i)


def safe(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def packages(inv_dir: Path, include_dev: bool):
    pk = set()
    for f in inv_dir.glob("*/*.csv"):
        for row in csv.DictReader(open(f)):
            if include_dev or row["dev"] != "True":
                pk.add((row["ecosystem"], row["name"]))
    return sorted(pk)


def osv_index(cache: Path, pkgs):
    todo = [p for p in pkgs if not (cache / "osv/index" / p[0] / f"{safe(p[1])}.json").exists()]
    for i in range(0, len(todo), 500):
        chunk = todo[i:i + 500]
        queries = [{"package": {"ecosystem": e, "name": n}} for e, n in chunk]
        res = http("https://api.osv.dev/v1/querybatch", {"queries": queries})["results"]
        for (e, n), r in zip(chunk, res):
            ids = [v["id"] for v in r.get("vulns", [])]
            tok = r.get("next_page_token")
            while tok:   # paginate single query
                more = http("https://api.osv.dev/v1/query", {"package": {"ecosystem": e, "name": n}, "page_token": tok}) or {}
                ids += [v["id"] for v in more.get("vulns", [])]
                tok = more.get("next_page_token")
            p = cache / "osv/index" / e / f"{safe(n)}.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(sorted(set(ids))))
        print(f"osv index {min(i + 500, len(todo))}/{len(todo)}")


def osv_vulns(cache: Path):
    ids = set()
    for f in (cache / "osv/index").glob("*/*.json"):
        ids |= set(json.loads(f.read_text()))
    out = cache / "osv/vulns"
    out.mkdir(parents=True, exist_ok=True)
    todo = [i for i in sorted(ids) if not (out / f"{i}.json").exists()]

    def get(i):
        d = http(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(i)}")
        if d:
            (out / f"{i}.json").write_text(json.dumps(d))
    with cf.ThreadPoolExecutor(16) as ex:
        list(ex.map(get, todo))
    print(f"osv vulns fetched {len(todo)} (total {len(ids)})")


def go_escape(m: str) -> str:
    return "".join("!" + c.lower() if c.isupper() else c for c in m)


def registry_times(eco: str, name: str) -> dict:
    """{version: ISO publish time} from the ecosystem's registry (best effort)."""
    try:
        if eco == "npm":
            d = http(f"https://registry.npmjs.org/{name.replace('/', '%2F')}") or {}
            return {k: v for k, v in (d.get("time") or {}).items() if k not in ("created", "modified")}
        if eco == "PyPI":
            d = http(f"https://pypi.org/pypi/{name}/json") or {}
            return {v: files[0]["upload_time_iso_8601"] for v, files in (d.get("releases") or {}).items() if files}
        if eco == "crates.io":
            d = http(f"https://crates.io/api/v1/crates/{name}/versions") or {}
            return {v["num"]: v["created_at"] for v in d.get("versions", [])}
        if eco == "Hex":
            d = http(f"https://hex.pm/api/packages/{name}") or {}
            return {r["version"]: r["inserted_at"] for r in d.get("releases", [])}
        if eco == "Maven":
            g, a = name.split(":", 1)
            q = urllib.parse.quote(f'g:"{g}" AND a:"{a}"')
            d = http(f"https://search.maven.org/solrsearch/select?q={q}&core=gav&rows=500&wt=json") or {}
            return {x["v"]: datetime.fromtimestamp(x["timestamp"] / 1000, timezone.utc).isoformat()
                    for x in (d.get("response") or {}).get("docs", [])}
        if eco == "Go":
            return {}   # filled per fixed version below (proxy has per-version .info)
    except Exception as e:
        return {"__error__": str(e)}
    return {}


def go_version_time(module: str, version: str):
    d = http(f"https://proxy.golang.org/{go_escape(module)}/@v/{go_escape(version)}.info")
    return (d or {}).get("Time")


def versions(cache: Path, pkgs):
    """Publish times for the FIXED versions referenced by the package's OSV records."""
    vdir = cache / "osv/vulns"

    def one(p):
        e, n = p
        out = cache / "versions" / e / f"{safe(n)}.json"
        if out.exists():
            return
        idx = cache / "osv/index" / e / f"{safe(n)}.json"
        ids = json.loads(idx.read_text()) if idx.exists() else []
        if not ids:
            return
        fixed = set()
        for i in ids:
            f = vdir / f"{i}.json"
            if f.exists():
                for aff in json.loads(f.read_text()).get("affected", []):
                    if (aff.get("package") or {}).get("name") == n:
                        for r in aff.get("ranges", []):
                            fixed |= {ev["fixed"] for ev in r.get("events", []) if "fixed" in ev}
        times = registry_times(e, n)
        if e == "Go":
            times = {v: go_version_time(n, v) for v in sorted(fixed)}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({v: t for v, t in times.items() if v in fixed or v == "__error__"}))
    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(one, pkgs))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventories", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--include-dev", action="store_true")
    a = ap.parse_args(argv)
    cache = Path(a.cache)
    cache.mkdir(parents=True, exist_ok=True)
    kev = http(KEV_URL)
    if not kev or len(kev.get("vulnerabilities", [])) < 1000:
        raise SystemExit("KEV feed unavailable or implausibly small — refusing to continue (fail safe)")
    kev["_fetched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (cache / "kev.json").write_text(json.dumps(kev))
    pk = packages(Path(a.inventories), a.include_dev)
    print(f"{len(pk)} unique packages")
    osv_index(cache, pk)
    osv_vulns(cache)
    versions(cache, pk)
    (cache / "MANIFEST.json").write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "packages": len(pk),
        "osv_records": len(list((cache / "osv/vulns").glob("*.json"))), "kev_entries": len(kev["vulnerabilities"]),
        "kev_catalog_version": kev.get("catalogVersion"), "include_dev": a.include_dev}, indent=2))


if __name__ == "__main__":
    main()
