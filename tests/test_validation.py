"""E9 manual validation kit: sampling is seeded, deduplicated, stratified and blinded; scoring is correct."""
import csv
import subprocess
import sys

import pytest

from conftest import ROOT
from crasme import validation as V


def _f(pid, tag, date, vid, pkg, cvss="", kev="", status="known"):
    return {"product_id": pid, "tag": tag, "release_date": date, "status": status, "vuln_id": vid, "aliases": "",
            "ecosystem": "npm", "package": pkg, "version": "1.0.0", "cvss": cvss, "kev_added_by_release": kev}


REL = [{"product_id": "p", "tag": t, "repo": "o/p", "commit_sha": "a" * 40} for t in ("1", "2")]


def test_wilson_known_value():
    lo, hi = V.wilson(8, 10)
    assert round(lo, 4) == 0.4902 and round(hi, 4) == 0.9433
    assert V.wilson(0, 0) != V.wilson(0, 0)  # nan


def test_strata_and_dedup_earliest_release():
    fs = [_f("p", "2", "2025-06-01", "X", "a", cvss="9.8"), _f("p", "1", "2025-01-01", "X", "a", cvss="9.8"),
          _f("p", "1", "2025-01-01", "K", "b", kev="2024-01-01", cvss="5"),
          _f("p", "1", "2025-01-01", "L", "c", cvss="4.0"),                 # low: not sampled
          _f("p", "1", "2025-01-01", "M", "d", cvss="9.0", status="later")]  # not known at release
    u = V.units(fs, REL)
    assert [x["vuln_id"] for x in u["known_high"]] == ["X"] and u["known_high"][0]["tag"] == "1"
    assert [x["vuln_id"] for x in u["known_kev"]] == ["K"]


def test_draw_is_seeded_capped_and_mixed():
    fs = [_f("p", "1", "2025-01-01", f"H{i}", f"h{i}", cvss="8") for i in range(50)]
    fs += [_f("p", "1", "2025-01-01", f"K{i}", f"k{i}", kev="2024-01-01") for i in range(10)]
    a, b = V.draw(fs, REL), V.draw(fs, REL)
    assert a == b                                     # reproducible
    assert sum(r["stratum"] == "known_kev" for r in a) == 10 and sum(r["stratum"] == "known_high" for r in a) == 30
    assert [r["stratum"] for r in a] != sorted(r["stratum"] for r in a)   # strata interleaved
    assert V.draw(fs, REL, seed=1) != a


def test_rater_sheets_are_blinded(tmp_path):
    fs = [_f("p", "1", "2025-01-01", "K", "k", kev="2024-01-01", cvss="9.8")]
    V.write_kit(V.draw(fs, REL), tmp_path)
    hdr = next(csv.reader(open(tmp_path / "rater_A.csv")))
    assert "stratum" not in hdr and "kev_added_by_release" not in hdr and "cvss" not in hdr
    assert "stratum" in next(csv.reader(open(tmp_path / "sample_key.csv")))


def _sheet(path, labels):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["item_id", "label"])
        w.writeheader()
        w.writerows({"item_id": f"V{i:03d}", "label": x} for i, x in enumerate(labels, 1))


def test_score_kappa_precision_and_adjudication(tmp_path):
    with open(tmp_path / "k.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["item_id", "stratum"])
        w.writeheader()
        w.writerows({"item_id": f"V{i:03d}", "stratum": "known_kev" if i <= 4 else "known_high"} for i in range(1, 9))
    A = ["PLAUSIBLE", "PLAUSIBLE", "NOT_PLAUSIBLE", "UNDETERMINED", "PLAUSIBLE", "NOT_PLAUSIBLE", "PLAUSIBLE", "PLAUSIBLE"]
    B = ["PLAUSIBLE", "NOT_PLAUSIBLE", "NOT_PLAUSIBLE", "UNDETERMINED", "PLAUSIBLE", "NOT_PLAUSIBLE", "PLAUSIBLE", "PLAUSIBLE"]
    _sheet(tmp_path / "a.csv", A)
    _sheet(tmp_path / "b.csv", B)
    r = V.score(tmp_path / "k.csv", tmp_path / "a.csv", tmp_path / "b.csv")
    assert r["n_disagreements"] == 1 and r["per_stratum"] == {} and "adjudicate" in r["note"]
    # hand computation: po = 7/8; pA = (5,2,1)/8, pB = (4,3,1)/8; pe = (20+6+1)/64
    assert r["cohen_kappa"] == pytest.approx((7 / 8 - 27 / 64) / (1 - 27 / 64))
    _sheet(tmp_path / "adj.csv", A)
    r = V.score(tmp_path / "k.csv", tmp_path / "a.csv", tmp_path / "b.csv", tmp_path / "adj.csv")
    kev = r["per_stratum"]["known_kev"]
    assert kev["PLAUSIBLE"] == 2 and kev["NOT_PLAUSIBLE"] == 1 and kev["UNDETERMINED"] == 1
    assert kev["precision"] == pytest.approx(2 / 3) and kev["precision_undetermined_as_not"] == pytest.approx(0.5)
    assert r["per_stratum"]["known_high"]["precision"] == pytest.approx(3 / 4)


def test_score_rejects_bad_or_missing_labels(tmp_path):
    with open(tmp_path / "k.csv", "w", newline="") as fh:
        fh.write("item_id,stratum\nV001,known_kev\nV002,known_high\n")
    _sheet(tmp_path / "a.csv", ["PLAUSIBLE", "maybe"])
    _sheet(tmp_path / "b.csv", ["PLAUSIBLE", "PLAUSIBLE"])
    with pytest.raises(ValueError):
        V.score(tmp_path / "k.csv", tmp_path / "a.csv", tmp_path / "b.csv")
    _sheet(tmp_path / "a.csv", ["PLAUSIBLE"])          # missing item
    with pytest.raises(ValueError):
        V.score(tmp_path / "k.csv", tmp_path / "a.csv", tmp_path / "b.csv")


def test_cli_end_to_end_on_synthetic_replay(tmp_path):
    res = tmp_path / "res"
    subprocess.run([sys.executable, str(ROOT / "tools/replay/run_replay.py"), "--e9", str(ROOT / "experiments/e9_release_replay"),
                    "--cache", str(ROOT / "tests/fixtures/e9_synthetic_cache.tar.gz"), "--out", str(res)],
                   check=True, capture_output=True, timeout=600)
    out = tmp_path / "val"
    r = subprocess.run([sys.executable, str(ROOT / "tools/replay/validation.py"), "sample", "--results", str(res),
                        "--e9", str(ROOT / "experiments/e9_release_replay"), "--out", str(out)],
                       capture_output=True, text=True, check=True)
    assert '"seed": 2026' in r.stdout
    assert (out / "rater_A.csv").exists() and (out / "rater_B.csv").exists() and (out / "SAMPLE.json").exists()


def test_kev_mirror_fallback(monkeypatch, tmp_path):
    sys.path.insert(0, str(ROOT / "tools" / "replay"))
    import fetch_data

    def fake(url, data=None, retries=4):
        if url == fetch_data.KEV_URL:
            raise OSError("403 from cisa.gov")
        if url == fetch_data.KEV_MIRROR:
            return {"catalogVersion": "x", "vulnerabilities": [{"cveID": f"CVE-1-{i}"} for i in range(1200)]}
        return {"results": []}
    monkeypatch.setattr(fetch_data, "http", fake)
    (tmp_path / "inv").mkdir()
    fetch_data.main(["--inventories", str(tmp_path / "inv"), "--cache", str(tmp_path / "c")])
    import json
    assert json.loads((tmp_path / "c" / "MANIFEST.json").read_text())["kev_source"] == fetch_data.KEV_MIRROR
