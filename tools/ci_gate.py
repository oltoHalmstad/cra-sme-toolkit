"""CI entry point for the v1.2 release-decision engine (wrapper around `python -m crasme.gate`).

    python tools/ci_gate.py --bundle evidence --policy policy.yaml --report evidence/decision.md
Exit codes: 0 PASS · 1 FAIL · 2 REVIEW_REQUIRED · 3 engine error.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from crasme.gate import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
