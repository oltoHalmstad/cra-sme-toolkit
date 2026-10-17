"""Check that release metadata is consistent across all files.

    python tools/check_release.py            # consistency only (CI)
    python tools/check_release.py --strict   # also fail on placeholders (run before tagging)
"""
import json
import re
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDERS = ["OWNER/", "example.invalid", "0000-0000-0000-0000"]
META_FILES = ["pyproject.toml", "CITATION.cff", ".zenodo.json", "codemeta.json", "SECURITY.md",
              ".github/ISSUE_TEMPLATE/config.yml", "README.md"]


def collect():
    versions = {
        "pyproject.toml": tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"],
        "CITATION.cff": str(yaml.safe_load((ROOT / "CITATION.cff").read_text())["version"]),
        ".zenodo.json": json.loads((ROOT / ".zenodo.json").read_text())["version"],
        "codemeta.json": json.loads((ROOT / "codemeta.json").read_text())["version"],
        "crasme/__init__.py": re.search(r'__version__ = "([^"]+)"', (ROOT / "crasme/__init__.py").read_text()).group(1),
        "CHANGELOG.md": re.search(r"^## (\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?)", (ROOT / "CHANGELOG.md").read_text(), re.M).group(1),
    }
    dates = {
        "CITATION.cff": str(yaml.safe_load((ROOT / "CITATION.cff").read_text())["date-released"]),
        ".zenodo.json": json.loads((ROOT / ".zenodo.json").read_text())["publication_date"],
        "codemeta.json": json.loads((ROOT / "codemeta.json").read_text())["datePublished"],
    }
    return versions, dates


def placeholders():
    hits = []
    for f in META_FILES:
        p = ROOT / f
        if p.exists():
            for ph in PLACEHOLDERS:
                if ph in p.read_text():
                    hits.append(f"{f}: '{ph}'")
    return hits


def main(argv=None):
    strict = "--strict" in (argv if argv is not None else sys.argv[1:])
    versions, dates = collect()
    errors = []
    if len(set(versions.values())) != 1:
        errors.append(f"version mismatch: {versions}")
    if len(set(dates.values())) != 1:
        errors.append(f"release date mismatch: {dates}")
    z = json.loads((ROOT / ".zenodo.json").read_text())
    for k in ("title", "creators", "description", "license", "upload_type"):
        if not z.get(k):
            errors.append(f".zenodo.json missing {k}")
    ph = placeholders()
    print(f"version {versions['pyproject.toml']} · date {dates['CITATION.cff']}")
    for e in errors:
        print("ERROR", e)
    for h in ph:
        print("PLACEHOLDER" if strict else "warning: placeholder", h)
    return 1 if errors or (strict and ph) else 0


if __name__ == "__main__":
    raise SystemExit(main())
