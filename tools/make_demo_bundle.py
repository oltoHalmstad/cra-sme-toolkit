"""Regenerate examples/demo-release/ (SYNTHETIC) and its release decision.

The bundle is internally consistent, but the shipped catalogue is legally *unverified*, so the
honest decision is REVIEW_REQUIRED (LEGAL_MAPPING_REVIEW_PENDING) — exactly what a real SME
would see until legal review is done.
"""
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from crasme.demo import AS_OF, build_baseline  # noqa: E402
from crasme.gate import evaluate, render_markdown  # noqa: E402

out = ROOT / "examples" / "demo-release"
shutil.rmtree(out, ignore_errors=True)
b, _verified_cat, policy, as_of = build_baseline(out)
d = evaluate(b, policy, AS_OF)          # shipped (unverified) catalogue
d["timestamp_utc"] = "2027-12-20T12:00:00+00:00"   # fixed for reproducible example
(out / "decision.json").write_text(json.dumps(d, indent=2))
(out / "decision.md").write_text(render_markdown(d))
(out / "README.md").write_text(
    "# Demo release bundle (SYNTHETIC)\n\nAll identifiers, findings and the KEV entry are invented. "
    "Regenerate with `python tools/make_demo_bundle.py`; evaluate with\n`python -m crasme.gate --bundle examples/demo-release "
    "--as-of 2027-12-20T12:00:00Z --out /tmp/decision.json`.\n\nExpected decision: **REVIEW_REQUIRED** because the shipped "
    "obligation catalogue has not been legally reviewed (all rows `unverified`). With a verified catalogue the same bundle "
    "is PASS (see `tests/test_gate.py`).\n")
print(d["decision"], d["reasons"])
