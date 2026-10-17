"""Write Zenodo DOIs into README, CITATION.cff, .zenodo.json and codemeta.json.

    python tools/set_doi.py --concept 10.5281/zenodo.NNNN [--version 10.5281/zenodo.MMMM]
README badge/citation use the concept DOI (always latest); CITATION.cff `doi` = concept DOI and the
version DOI is listed under `identifiers`. With only --version, that DOI is used everywhere.
"""
import argparse
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DOI = re.compile(r"^10\.5281/zenodo\.\d+$")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--concept")
    ap.add_argument("--version")
    a = ap.parse_args(argv)
    main_doi = a.concept or a.version
    if not main_doi or not all(DOI.match(d) for d in filter(None, (a.concept, a.version))):
        ap.error("give --concept and/or --version as 10.5281/zenodo.<number>")
    readme = ROOT / "README.md"
    s = re.sub(r"10\.5281/zenodo\.\d+|ZENODO-DOI-PLACEHOLDER", main_doi, readme.read_text())
    readme.write_text(s)
    c = yaml.safe_load((ROOT / "CITATION.cff").read_text())
    c["doi"] = main_doi
    ids = [{"type": "doi", "value": main_doi, "description": "Zenodo concept DOI (all versions)" if a.concept else "Zenodo DOI"}]
    if a.concept and a.version:
        ids.append({"type": "doi", "value": a.version, "description": f"Zenodo version DOI ({c.get('version')})"})
    c["identifiers"] = ids
    (ROOT / "CITATION.cff").write_text(yaml.safe_dump(c, sort_keys=False, allow_unicode=True, width=100))
    z = json.loads((ROOT / ".zenodo.json").read_text())
    rel = [r for r in z.get("related_identifiers", []) if "zenodo" not in r.get("identifier", "")]
    if a.concept and a.version:
        rel.append({"identifier": a.concept, "relation": "isVersionOf", "resource_type": "software"})
    z["related_identifiers"] = rel
    (ROOT / ".zenodo.json").write_text(json.dumps(z, indent=2, ensure_ascii=False) + "\n")
    cm = json.loads((ROOT / "codemeta.json").read_text())
    cm["identifier"] = f"https://doi.org/{main_doi}"
    (ROOT / "codemeta.json").write_text(json.dumps(cm, indent=2, ensure_ascii=False) + "\n")
    print(f"DOI set: {main_doi}" + (f" (version DOI {a.version})" if a.concept and a.version else ""))


if __name__ == "__main__":
    main()
