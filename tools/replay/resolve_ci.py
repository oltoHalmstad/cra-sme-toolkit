"""Resolve inventories that need a package manager, time-travelled to the release date (CI only).

    python tools/replay/resolve_ci.py --e9 experiments/e9_release_replay --product octoprint --workdir /tmp/w

Strategies (recorded in inventories/summary_ci.csv):
  pip    : uv pip compile <pyproject/setup> --exclude-newer <release date>   (resolution as of the release)
  npm    : npm install --package-lock-only --ignore-scripts --before=<release date>
  maven  : mvn -B -q dependency:list -DincludeScope=runtime (versions pinned in POMs; plugin resolution today)
  syft   : syft dir:<checkout> (C/firmware and anything else; expected to be incomplete)
Each strategy writes inventories/<product>/<tag>.csv only if the frozen inventory is empty.
"""
import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme.replay import Pkg, norm_pypi, parse_package_lock, parse_requirements  # noqa: E402


def sh(cmd, cwd=None, timeout=3600):
    print("+", " ".join(map(str, cmd)), flush=True)
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def checkout(repo, sha, dest: Path):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for c in (["git", "init", "-q"], ["git", "remote", "add", "origin", f"https://github.com/{repo}"],
              ["git", "fetch", "-q", "--depth", "1", "origin", sha], ["git", "checkout", "-q", "FETCH_HEAD"]):
        r = sh(c, cwd=dest)
        if r.returncode:
            raise RuntimeError(r.stderr[-500:])


def resolve_pip(src: Path, when: str):
    target = next((p for p in ("pyproject.toml", "setup.py", "setup.cfg") if (src / p).exists()), None)
    r = sh(["uv", "pip", "compile", target, "--exclude-newer", when, "--no-header", "-o", "resolved.txt"], cwd=src)
    return parse_requirements((src / "resolved.txt").read_text()) if r.returncode == 0 else None, r.stderr[-300:]


def resolve_npm(src: Path, when: str):
    r = sh(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", f"--before={when}"], cwd=src)
    lock = src / "package-lock.json"
    return parse_package_lock(lock.read_text()) if r.returncode == 0 and lock.exists() else None, r.stderr[-300:]


_MVN = re.compile(r"^\s*([\w.\-]+):([\w.\-]+):[\w\-]+(?::[\w\-]+)?:([\w.\-]+):(compile|runtime)", re.M)


def resolve_maven(src: Path, when: str):
    out = src / "deps.txt"
    r = sh(["mvn", "-B", "-q", "-DskipTests", "dependency:list", "-DincludeScope=runtime", f"-DoutputFile={out}",
            "-DappendOutput=true", "-Dmdep.outputScope=true"], cwd=src, timeout=5400)
    if not out.exists():
        return None, r.stderr[-300:]
    return {Pkg("Maven", f"{g}:{a}", v) for g, a, v, _ in _MVN.findall(out.read_text())}, r.stderr[-300:]


def resolve_syft(src: Path, when: str):
    r = sh(["syft", f"dir:{src}", "-o", "cyclonedx-json=syft.cdx.json", "-q"], cwd=src)
    f = src / "syft.cdx.json"
    if r.returncode or not f.exists():
        return None, r.stderr[-300:]
    eco = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io", "maven": "Maven", "hex": "Hex"}
    pk = set()
    for c in json.loads(f.read_text()).get("components", []):
        m = re.match(r"pkg:([a-z]+)/(.+)@([^?#]+)", c.get("purl", ""))
        if m and m.group(1) in eco:
            name = m.group(2).replace("%40", "@")
            if m.group(1) == "maven":
                name = name.replace("/", ":")
            if m.group(1) == "pypi":
                name = norm_pypi(name)
            pk.add(Pkg(eco[m.group(1)], name, m.group(3)))
    return pk, ""


STRATEGY = {"resolve-in-ci (pip, no lockfile)": resolve_pip, "lockfile-missing": resolve_npm,
            "resolve-in-ci (maven)": resolve_maven}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--e9", required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--workdir", default="/tmp/e9-work")
    a = ap.parse_args(argv)
    e9 = Path(a.e9)
    summary = list(csv.DictReader(open(e9 / "inventories" / "summary.csv")))
    rel = {(r["product_id"], r["tag"]): r for r in csv.DictReader(open(e9 / "releases.csv"))}
    log = []
    for s in summary:
        if s["product_id"] != a.product or s["inventory_status"] == "lockfile":
            continue
        r = rel[(s["product_id"], s["tag"])]
        fn = STRATEGY.get(s["inventory_status"], resolve_syft)
        src = Path(a.workdir) / f"{a.product}-{s['tag']}"
        try:
            checkout(r["repo"], r["commit_sha"], src)
            pk, err = fn(src, r["release_date_utc"])
        except Exception as e:
            pk, err = None, str(e)[-300:]
        status = f"ci:{fn.__name__.replace('resolve_', '')}:" + ("ok" if pk else "failed")
        if pk:
            with open(e9 / "inventories" / a.product / f"{s['tag']}.csv", "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=["ecosystem", "name", "version", "dev", "source"])
                w.writeheader()
                w.writerows(sorted(({"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "dev": p.dev,
                                     "source": status} for p in pk), key=lambda x: (x["ecosystem"], x["name"], x["version"])))
        log.append({"product_id": a.product, "tag": s["tag"], "status": status, "n": len(pk or []), "error": err})
        print(log[-1])
    p = e9 / "inventories" / f"summary_ci_{a.product}.csv"
    if log:
        with open(p, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(log[0].keys()))
            w.writeheader()
            w.writerows(log)


if __name__ == "__main__":
    main()
