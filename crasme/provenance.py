"""Evidence provenance manifest generator.

Usage (in CI, after each tool run):
    python -m crasme.provenance --product DEMO-001 --build "$GITHUB_SHA" \
        --tool syft --tool-version "$(syft version -o json | jq -r .version)" \
        --evidence sbom.cdx.json --requirement V01 --out evidence-manifest.json

Appends one record per evidence file (sha256, size, tool + version, UTC time,
CI run metadata). The manifest is itself evidence and should be retained with
the technical documentation (Art. 13 retention; check current legal text).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path

from .traceability import sha256_file

CI_VARS = ["GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW", "GITHUB_REF",
           "CI_PIPELINE_ID", "CI_PROJECT_PATH"]


def record(evidence: str, product: str, build: str, tool: str, tool_version: str,
           requirements: list[str], product_version: str = "", artifact_digest: str = "",
           evidence_type: str = "", inputs: dict[str, str] | None = None) -> dict:
    """One evidence record bound to product + build (+ version/artifact when known).

    ``inputs`` maps an input name (e.g. "lockfile") to a file path; its digest is stored so
    the release-decision engine can flag the evidence as stale when that input changes.
    """
    p = Path(evidence)
    return {
        "product_id": product,
        "product_version": product_version,
        "build_sha": build,
        "build_id": build,  # v1.1 compatibility
        "artifact_digest": artifact_digest,
        "requirement_ids": requirements,
        "evidence_type": evidence_type or tool,
        "evidence_uri": p.as_posix(),
        "evidence_sha256": sha256_file(p),
        "evidence_bytes": p.stat().st_size,
        "input_digests": {k: sha256_file(v) for k, v in (inputs or {}).items()},
        "tool": tool,
        "tool_version": tool_version,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runner": {"os": platform.platform(), **{k: os.environ[k] for k in CI_VARS if k in os.environ}},
        "review_status": "unreviewed",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--product", required=True)
    ap.add_argument("--product-version", default="")
    ap.add_argument("--build", required=True)
    ap.add_argument("--artifact-digest", default="")
    ap.add_argument("--tool", required=True)
    ap.add_argument("--tool-version", default="unknown")
    ap.add_argument("--evidence-type", default="")
    ap.add_argument("--evidence", required=True, action="append")
    ap.add_argument("--requirement", action="append", default=[])
    ap.add_argument("--input", action="append", default=[], metavar="NAME=PATH",
                    help="input whose change makes this evidence stale, e.g. lockfile=package-lock.json")
    ap.add_argument("--out", default="evidence-manifest.json")
    a = ap.parse_args(argv)
    inputs = dict(i.split("=", 1) for i in a.input)
    out = Path(a.out)
    manifest = json.loads(out.read_text()) if out.exists() else {"schema": "crasme-evidence-manifest/2", "records": []}
    for r in manifest["records"]:
        if (r.get("product_id"), r.get("build_sha", r.get("build_id"))) != (a.product, a.build):
            print(f"{out} already holds evidence for another product/build; use a fresh manifest per build")
            return 3
    for ev in a.evidence:
        manifest["records"].append(record(ev, a.product, a.build, a.tool, a.tool_version, a.requirement,
                                          a.product_version, a.artifact_digest, a.evidence_type, inputs))
    out.write_text(json.dumps(manifest, indent=2))
    print(f"{len(a.evidence)} record(s) appended to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
