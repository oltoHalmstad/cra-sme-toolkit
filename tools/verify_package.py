"""Clean-environment package verification (rec. P1-04).

Builds the wheel, checks its contents, installs it into a fresh virtualenv OUTSIDE the
repository, and runs the packaged CLI and data against the demo bundle.
    python tools/verify_package.py [--constraints constraints-ci.txt]
"""
import argparse
import json
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_IN_WHEEL = ["crasme/gate.py", "crasme/scanstatus.py", "crasme/_data/cra_requirements_catalogue.csv",
                     "crasme/_data/trace_unit.schema.json", "crasme/_data/release_decision.schema.json",
                     "crasme/_data/product.schema.json"]


def run(cmd, **kw):
    print("+", " ".join(map(str, cmd)))
    return subprocess.run(cmd, check=False, **kw)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--constraints")
    a = ap.parse_args(argv)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        r = run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", td / "dist", ROOT])
        if r.returncode:
            return 1
        whl = next((td / "dist").glob("crasme-*.whl"))
        names = zipfile.ZipFile(whl).namelist()
        missing = [n for n in REQUIRED_IN_WHEEL if n not in names]
        if missing:
            print("wheel missing:", missing)
            return 1
        venv.create(td / "venv", with_pip=True)
        py = td / "venv" / "bin" / "python"
        cmd = [py, "-m", "pip", "install", "-q", str(whl)]
        if a.constraints:
            cmd += ["-c", str(Path(a.constraints).resolve())]
        if run(cmd).returncode:
            return 1
        out = td / "decision.json"
        r = run([td / "venv" / "bin" / "crasme-gate", "--bundle", ROOT / "examples" / "demo-release",
                 "--as-of", "2027-12-20T12:00:00Z", "--out", out], cwd=td)
        d = json.loads(out.read_text())
        ok = r.returncode == 2 and d["decision"] == "REVIEW_REQUIRED" and d["reasons"] == ["LEGAL_MAPPING_REVIEW_PENDING"]
        r2 = run([py, "-c", "from crasme.traceability import load_catalogue, SCHEMA_PATH; "
                            "assert len(load_catalogue()) == 46; assert '_data' in str(SCHEMA_PATH); print('packaged data OK')"],
                 cwd=td)
        print("clean-install verification:", "OK" if ok and r2.returncode == 0 else "FAILED")
        return 0 if ok and r2.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
