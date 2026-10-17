#!/usr/bin/env bash
# Head-to-head with OpenCRA 0.1.6 (CI, network required). Two parts:
#  A) fail-safe probes: does the tool give a clean result on broken input / missing feed?
#  B) current-knowledge decisions on each release SBOM (OpenCRA has no time-travel; compare with
#     crasme-gate run with --as-of now on the same SBOMs).
# Usage: tools/replay/opencra_compare.sh <sbom_dir_with_*.cdx.json> <out_dir>
set -uo pipefail
SB="${1:?sbom dir}"; OUT="${2:?out dir}"; mkdir -p "$OUT/probes"
python -m pip install -q "opencra==0.1.6"
opencra kev refresh || echo "kev refresh failed"
echo "case,exit_code" > "$OUT/opencra_probes.csv"
P="$OUT/probes"
python - "$P" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, open(p / "empty.cdx.json", "w"))
(p / "malformed.cdx.json").write_text('{"bomFormat":"CycloneDX","components":[{"name":"lod')
json.dump({"foo": "bar"}, open(p / "notcdx.json", "w"))
json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "name": "lodash",
           "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}]}, open(p / "known_vuln.cdx.json", "w"))
PY
for f in empty malformed notcdx known_vuln missing; do
  opencra scan "$P/$f.cdx.json" --format json --output "$P/$f.out.json" --fail-on kev >"$P/$f.log" 2>&1; echo "$f,$?" >> "$OUT/opencra_probes.csv"
done
# offline with no cache (simulates unreachable feeds)
HOME="$(mktemp -d)" opencra scan "$P/known_vuln.cdx.json" --offline --format json --output "$P/offline.out.json" --fail-on kev >"$P/offline.log" 2>&1; echo "offline_no_cache,$?" >> "$OUT/opencra_probes.csv"
echo "sbom,exit_code_fail_on_kev,exit_code_fail_on_high" > "$OUT/opencra_releases.csv"
for s in "$SB"/*.cdx.json; do
  b=$(basename "$s" .cdx.json)
  opencra scan "$s" --format json --output "$OUT/$b.opencra.json" --fail-on kev >/dev/null 2>&1; k=$?
  opencra scan "$s" --format json --output "$OUT/$b.opencra-high.json" --fail-on high >/dev/null 2>&1; h=$?
  echo "$b,$k,$h" >> "$OUT/opencra_releases.csv"
done
cat "$OUT/opencra_probes.csv"
