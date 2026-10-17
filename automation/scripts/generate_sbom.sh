#!/usr/bin/env sh
set -eu
# Requires installed Syft. Run on a trusted source snapshot; output is evidence, not conformity.
INPUT="${1:-.}"
OUT="${2:-sbom.cdx.json}"
syft "dir:$INPUT" -o "cyclonedx-json=$OUT"
printf 'SBOM created: %s\n' "$OUT"
