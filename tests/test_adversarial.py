"""Regression: the independent reviewer's attack set must yield no false PASS, except the one
case judged correct behaviour (a revocation for a *different* build does not block this build)."""
import subprocess
import sys

import pytest

from conftest import ROOT

ACCEPTED = {"approvals: good + revoked for OTHER build same role"}


@pytest.mark.slow
def test_no_false_pass_in_review_attacks():
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "adversarial_review_attacks.py")],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr[-2000:]
    false_pass = {l.split("PASS", 2)[-1].strip().rsplit("  ", 1)[0].strip()
                  for l in r.stdout.splitlines() if l.startswith("FALSE-PASS")}
    assert false_pass <= ACCEPTED, false_pass
    assert "ERR" not in r.stdout
