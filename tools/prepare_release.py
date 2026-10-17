"""Fill in repository owner, ORCID, affiliation and security contact in all metadata files.

    python tools/prepare_release.py --owner my-github-user --orcid 0000-0002-1825-0097 \
        --affiliation "University X" --security-email security@my-domain.eu
Then: python tools/check_release.py --strict
"""
import argparse
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True, help="GitHub user or organisation")
    ap.add_argument("--repo", default="cra-sme-toolkit")
    ap.add_argument("--orcid")
    ap.add_argument("--affiliation")
    ap.add_argument("--security-email")
    a = ap.parse_args(argv)
    for f in ["pyproject.toml", "CITATION.cff", ".zenodo.json", "codemeta.json", "README.md",
              ".github/ISSUE_TEMPLATE/config.yml"]:
        p = ROOT / f
        p.write_text(p.read_text().replace("OWNER/cra-sme-toolkit", f"{a.owner}/{a.repo}"))
    if a.security_email:
        p = ROOT / "SECURITY.md"
        p.write_text(p.read_text().replace("SECURITY-CONTACT@example.invalid", a.security_email)
                     .replace(" (**replace before publishing**)", ""))
    # creators / authors
    z = json.loads((ROOT / ".zenodo.json").read_text())
    c = yaml.safe_load((ROOT / "CITATION.cff").read_text())
    cm = json.loads((ROOT / "codemeta.json").read_text())
    if a.orcid:
        z["creators"][0]["orcid"] = a.orcid
        c["authors"][0]["orcid"] = f"https://orcid.org/{a.orcid}"
        cm["author"][0]["@id"] = f"https://orcid.org/{a.orcid}"
    if a.affiliation:
        z["creators"][0]["affiliation"] = a.affiliation
        c["authors"][0]["affiliation"] = a.affiliation
        cm["author"][0]["affiliation"] = {"@type": "Organization", "name": a.affiliation}
    (ROOT / ".zenodo.json").write_text(json.dumps(z, indent=2, ensure_ascii=False) + "\n")
    (ROOT / "CITATION.cff").write_text(yaml.safe_dump(c, sort_keys=False, allow_unicode=True, width=100))
    (ROOT / "codemeta.json").write_text(json.dumps(cm, indent=2, ensure_ascii=False) + "\n")
    print("Updated. Now run: python tools/check_release.py --strict")


if __name__ == "__main__":
    main()
