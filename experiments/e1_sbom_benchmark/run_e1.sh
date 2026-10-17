#!/usr/bin/env bash
# E1 — SBOM generator accuracy benchmark runner.
# Runs every generator that is installed against each fixture and records
# output, wall time, tool version and exit code in results/runs.csv.
# Usage: run_e1.sh <fixtures_dir> <results_dir>
# Each fixture dir must contain ground_truth.csv (ecosystem,namespace,name,version),
# produced from the package manager's *installed* set (see protocol E1 §4).
set -uo pipefail
FIX="${1:?fixtures dir}"; OUT="${2:?results dir}"; mkdir -p "$OUT"
LOG="$OUT/runs.csv"; [ -f "$LOG" ] || echo "fixture,generator,tool_version,mode,exit_code,seconds,output" > "$LOG"
have() { command -v "$1" >/dev/null 2>&1; }
run() { # fixture generator version mode outfile cmd...
  local fx="$1" gen="$2" ver="$3" mode="$4" of="$5"; shift 5
  local t0=$(date +%s.%N); "$@" >"$OUT/$fx.$gen.$mode.log" 2>&1; local rc=$?
  local t1=$(date +%s.%N); echo "$fx,$gen,$ver,$mode,$rc,$(echo "$t1 - $t0" | bc),$of" >> "$LOG"; }
for d in "$FIX"/*/; do
  fx=$(basename "$d")
  [ -f "$d/ground_truth.csv" ] || continue   # skip non-fixture dirs (e.g. results)
  if have syft; then v=$(syft version 2>/dev/null | awk '/^Version/{print $2}')
    run "$fx" syft "$v" dir "$OUT/$fx.syft.cdx.json" syft "dir:$d" -o "cyclonedx-json=$OUT/$fx.syft.cdx.json"; fi
  if have trivy; then v=$(trivy --version 2>/dev/null | awk '/^Version/{print $2}')
    run "$fx" trivy "$v" fs "$OUT/$fx.trivy.cdx.json" trivy fs --format cyclonedx --output "$OUT/$fx.trivy.cdx.json" "$d"; fi
  if have cdxgen; then v=$(cdxgen --version 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | awk '/CycloneDX Generator/{print $3}')
    run "$fx" cdxgen "$v" auto "$OUT/$fx.cdxgen.cdx.json" env FETCH_LICENSE=false CDXGEN_DEBUG_MODE= cdxgen --no-install-deps -r -o "$OUT/$fx.cdxgen.cdx.json" "$d"; fi
  if [ -f "$d/package-lock.json" ] && have cyclonedx-npm; then v=$(cyclonedx-npm --version 2>/dev/null)
    run "$fx" cyclonedx-npm "$v" installed "$OUT/$fx.cyclonedx-npm.cdx.json" sh -c "cd '$d' && cyclonedx-npm --output-format JSON --output-file '$OUT/$fx.cyclonedx-npm.cdx.json'"; fi
  if [ -f "$d/requirements.txt" ] && have cyclonedx-py; then v=$(cyclonedx-py --version 2>/dev/null)
    run "$fx" cyclonedx-py "$v" requirements "$OUT/$fx.cyclonedx-py-req.cdx.json" cyclonedx-py requirements "$d/requirements.txt" -o "$OUT/$fx.cyclonedx-py-req.cdx.json"
    if [ -x "$d/.venv/bin/python" ]; then
      run "$fx" cyclonedx-py "$v" environment "$OUT/$fx.cyclonedx-py-env.cdx.json" cyclonedx-py environment "$d/.venv/bin/python" -o "$OUT/$fx.cyclonedx-py-env.cdx.json"; fi; fi
done
echo "done -> $LOG"
