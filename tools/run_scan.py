"""Run (or validate) one security scan and record its execution status.

Two modes:

  # run a command, capture exit code, validate its output
  python tools/run_scan.py --manifest evidence/scan-status.json --product DEMO-001 --build "$GITHUB_SHA" \
      --name osv --tool osv-scanner --kind osv --output evidence/osv.json --input-path package-lock.json \
      --tool-version v2.6.0 --timeout 900 -- osv-scanner scan source -r --format json --output evidence/osv.json .

  # validate an output produced by a GitHub Action step (pass the step outcome)
  python tools/run_scan.py ... --name sbom --tool action --kind cyclonedx --output evidence/sbom.cdx.json \
      --step-outcome "${{ steps.sbom.outcome }}"

The script always exits 0 so later steps still run; failures are recorded as
explicit statuses and turned into REVIEW_REQUIRED by the release-decision engine.
Use --exit-on-failure to make the step itself fail as well.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from crasme import scanstatus as ss  # noqa: E402


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--build", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--kind", required=True, choices=["cyclonedx", "trivy", "osv", "sarif", "kev"])
    ap.add_argument("--output", required=True)
    ap.add_argument("--input-path", action="append", default=[])
    ap.add_argument("--tool-version", default="unknown")
    ap.add_argument("--optional", action="store_true", help="scan is not required for release")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--step-outcome", help="GitHub step outcome when validating an action's output")
    ap.add_argument("--redact-secrets", action="store_true", help="mask secret values in a Trivy report")
    ap.add_argument("--exit-on-failure", action="store_true")
    a = ap.parse_args(argv)

    mpath = Path(a.manifest)
    mpath.parent.mkdir(parents=True, exist_ok=True)
    manifest = ss.ScanManifest.load(mpath) if mpath.exists() else ss.ScanManifest(a.product, a.build)
    if (manifest.product_id, manifest.build_sha) != (a.product, a.build):
        print(f"manifest belongs to {manifest.product_id}@{manifest.build_sha}; refusing to mix builds", file=sys.stderr)
        return 3

    started = ss.now_utc()
    exit_code, timed_out = None, False
    if cmd:
        try:
            exit_code = subprocess.run(cmd, timeout=a.timeout).returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except FileNotFoundError:
            exit_code = 127
    finished = ss.now_utc()

    out = Path(a.output)
    if a.redact_secrets and out.is_file():
        try:
            doc, n = ss.redact_trivy_secrets(json.loads(out.read_text()))
            out.write_text(json.dumps(doc, indent=1))
            print(f"redacted {n} secret match(es)")
        except json.JSONDecodeError:
            pass  # classify() will report MALFORMED_JSON

    status, err, count = ss.classify(a.tool, a.kind, exit_code, out, timed_out, a.step_outcome)
    rec = ss.ScanRecord(
        name=a.name, tool=a.tool, kind=a.kind, required=not a.optional, execution_status=status,
        tool_version=a.tool_version, exit_code=exit_code, started_at=started, finished_at=finished,
        input_digest=ss.digest_paths(a.input_path) if a.input_path else None, output_path=out.as_posix(),
        output_digest=ss.sha256_bytes(out.read_bytes()) if out.is_file() else None,
        finding_count=count, error_code=err)
    manifest.upsert(rec)
    manifest.save(mpath)
    print(f"[{status}] {a.name} ({a.tool} {a.tool_version}) findings={count} error={err}")
    return 1 if (a.exit_on_failure and status != ss.OK) else 0


if __name__ == "__main__":
    raise SystemExit(main())
