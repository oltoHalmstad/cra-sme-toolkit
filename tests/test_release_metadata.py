import json
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "tools"))
import check_release  # noqa: E402


def test_metadata_consistent():
    assert check_release.main([]) == 0


def test_zenodo_json_fields():
    z = json.loads((ROOT / ".zenodo.json").read_text())
    assert z["upload_type"] == "software"
    assert z["license"] == "apache-2.0"
    assert z["creators"] and all("name" in c for c in z["creators"])
    assert z["access_right"] == "open"


def test_licence_files_present():
    for f in ("LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/CC-BY-4.0.txt", "NOTICE", "CITATION.cff"):
        assert (ROOT / f).stat().st_size > 200, f
    assert "Apache License" in (ROOT / "LICENSE").read_text()
    assert "Attribution 4.0 International" in (ROOT / "LICENSES/CC-BY-4.0.txt").read_text()


def test_repo_workflows_pinned():
    import re
    import yaml
    sha = re.compile(r"@[0-9a-f]{40}$")
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        d = yaml.safe_load(wf.read_text())
        for job in d["jobs"].values():
            for st in job.get("steps", []):
                if "uses" in st:
                    assert sha.search(st["uses"]), f"{wf.name}: {st['uses']}"


def test_packaged_data_matches_repo_copies():
    pairs = [("schemas/trace_unit.schema.json", "crasme/_data/trace_unit.schema.json"),
             ("data/cra_requirements_catalogue.csv", "crasme/_data/cra_requirements_catalogue.csv")]
    for a, b in pairs:
        assert (ROOT / a).read_bytes() == (ROOT / b).read_bytes(), f"{b} out of sync with {a}"
