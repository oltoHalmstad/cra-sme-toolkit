"""Execute notebooks in place with nbclient (no nbconvert needed).
Usage: python tools/run_notebooks.py [notebooks/*.ipynb]"""
import sys
from pathlib import Path

import nbformat
from nbclient import NotebookClient

root = Path(__file__).resolve().parent.parent
paths = [Path(p) for p in sys.argv[1:]] or sorted((root / "notebooks").glob("*.ipynb"))
failed = 0
for p in paths:
    nb = nbformat.read(p, as_version=4)
    try:
        NotebookClient(nb, timeout=900, kernel_name="python3", resources={"metadata": {"path": str(p.parent)}}).execute()
        nbformat.write(nb, p)
        print("OK  ", p.name)
    except Exception as e:  # report and continue
        failed += 1
        print("FAIL", p.name, "\n", str(e)[-1500:])
sys.exit(1 if failed else 0)
