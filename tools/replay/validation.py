"""E9 manual validation kit (pre-registered procedure: experiments/e9_release_replay/VALIDATION.md).

    # 1. after the e9-replay run: draw the seeded sample and create blinded rater sheets
    python tools/replay/validation.py sample --results e9-results --e9 experiments/e9_release_replay \
        --out experiments/e9_release_replay/validation
    # 2. give rater_A.csv and rater_B.csv to the two raters (NOT sample_key.csv); they fill label/evidence
    # 3. agreement (before adjudication); then adjudicate disagreements into adjudicated.csv and re-run
    python tools/replay/validation.py score --dir experiments/e9_release_replay/validation [--adjudicated]
"""
import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme import validation as V  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--results", required=True)
    s.add_argument("--e9", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--n", type=int, default=V.N_PER_STRATUM)
    s.add_argument("--seed", type=int, default=V.SEED)
    c = sub.add_parser("score")
    c.add_argument("--dir", required=True)
    c.add_argument("--adjudicated", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "sample":
        findings = list(csv.DictReader(open(Path(a.results) / "findings.csv")))
        releases = list(csv.DictReader(open(Path(a.e9) / "releases.csv")))
        rows = V.draw(findings, releases, a.n, a.seed)
        V.write_kit(rows, Path(a.out))
        pool = V.units(findings, releases)
        meta = {"seed": a.seed, "n_per_stratum": a.n, "units_available": {k: len(v) for k, v in pool.items()},
                "sampled": {k: sum(r["stratum"] == k for r in rows) for k in pool}}
        (Path(a.out) / "SAMPLE.json").write_text(json.dumps(meta, indent=2))
        print(json.dumps(meta, indent=2))
    else:
        d = Path(a.dir)
        res = V.score(d / "sample_key.csv", d / "rater_A.csv", d / "rater_B.csv",
                      d / "adjudicated.csv" if a.adjudicated else None)
        (d / "SCORE.json").write_text(json.dumps(res, indent=2))
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
