"""Execute all notebooks end-to-end. Opt-in: RUN_NOTEBOOKS=1 pytest tests/test_notebooks.py"""
import os
import subprocess
import sys

import pytest

from conftest import ROOT


@pytest.mark.slow
@pytest.mark.skipif(os.environ.get("RUN_NOTEBOOKS") != "1", reason="set RUN_NOTEBOOKS=1 to execute notebooks")
def test_all_notebooks_execute():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "run_notebooks.py")], capture_output=True, text=True, timeout=3600)
    assert r.returncode == 0, r.stdout + r.stderr
