#!/usr/bin/env bash
# Rebuild installed state for fixtures and regenerate ground truth from the package managers.
set -euo pipefail
FIX="${1:-$(dirname "$0")/fixtures}"
( cd "$FIX/py-app" && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt \
  && .venv/bin/pip freeze --all | grep -v -E '^(pip|setuptools|wheel)==' \
  | awk -F'==' 'BEGIN{print "ecosystem,namespace,name,version"}{print "pypi,,"$1","$2}' > ground_truth.csv )
( cd "$FIX/node-app" && npm install --no-audit --no-fund && npm ls --all --json > npm-ls.json && python3 - <<'PY'
import csv, json
s=set()
def walk(n):
    for k,v in (n.get("dependencies") or {}).items():
        if "version" in v: s.add((k, v["version"]))
        walk(v)
walk(json.load(open("npm-ls.json")))
with open("ground_truth.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["ecosystem","namespace","name","version"])
    for k,v in sorted(s):
        ns,name = k.split("/",1) if k.startswith("@") else ("",k)
        w.writerow(["npm",ns,name,v])
PY
)
echo "c-vendored ground truth is hand-curated (synthetic fixture); see fixtures/c-vendored/ground_truth.csv"
echo "NOTE: resolver output drifts over time (unpinned transitive deps). Record the date and keep ground_truth.csv with results."
