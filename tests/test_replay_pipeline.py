"""End-to-end E9 pipeline on the SYNTHETIC cache (offline)."""
import csv
import subprocess
import sys

from conftest import ROOT


def test_run_replay_on_synthetic_cache(tmp_path):
    out = tmp_path / "res"
    r = subprocess.run([sys.executable, str(ROOT / "tools/replay/run_replay.py"), "--e9", str(ROOT / "experiments/e9_release_replay"),
                        "--cache", str(ROOT / "tests/fixtures/e9_synthetic_cache.tar.gz"), "--out", str(out),
                        "--limit-products", "headscale,mosquitto,zwave-js-ui"], capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-2000:]
    m = {(x["product_id"], x["tag"]): x for x in csv.DictReader(open(out / "release_metrics.csv"))}
    assert len(m) == 18
    # C firmware without a manifest: baselines silently pass, CRA-SME v1.2 does not
    for k, x in m.items():
        if k[0] == "mosquitto":
            assert x["gate_naive_kev"] == "PASS" and x["gate_cvss7"] == "PASS" and x["gate_crasme_v1_2"] == "REVIEW_REQUIRED"
    # time travel: the synthetic KEV entry (dateAdded 2025-03-01) only affects releases after that date
    hs = sorted((x for k, x in m.items() if k[0] == "headscale"), key=lambda x: x["release_date"])
    assert hs[0]["known_kev"] == "0" and all(x["known_kev"] == "1" for x in hs[1:])
    assert all(x["gate_crasme_v1_2"] != "PASS" for x in hs)
    assert (out / "exposure.csv").exists() and (out / "drift.csv").exists()


def test_fetch_data_refuses_without_kev(monkeypatch, tmp_path):
    sys.path.insert(0, str(ROOT / "tools" / "replay"))
    import fetch_data
    monkeypatch.setattr(fetch_data, "http", lambda *a, **k: {"vulnerabilities": []})
    import pytest
    with pytest.raises(SystemExit):
        fetch_data.main(["--inventories", str(tmp_path), "--cache", str(tmp_path / "c")])


def test_e9_workflow_pinned_and_present():
    import yaml
    wf = yaml.safe_load((ROOT / ".github/workflows/e9-replay.yml").read_text())
    assert set(wf["jobs"]) == {"resolve", "sbom", "replay"}
    assert len(wf["jobs"]["sbom"]["strategy"]["matrix"]["product"]) == 20
