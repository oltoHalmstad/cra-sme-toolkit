"""Run the seeded-fault suite against the v1.2 engine and the legacy v1.1 gate.

    python tools/mutation_suite.py --out experiments/e4_e7_gate_mutation
Writes results.csv (one row per mutation) and summary.json.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from crasme.mutation import run_suite  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/e4_e7_gate_mutation")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    r = run_suite(out / "results.csv")
    (out / "summary.json").write_text(json.dumps(r["summary"], indent=2))
    s = r["summary"]
    print(f"mutations={s['mutations']}  v1.2 false-green={s['false_green']} ({s['false_green_rate']:.0%})  "
          f"legacy v1.1 false-green={s['legacy_v11_false_green']} ({s['legacy_v11_false_green_rate']:.0%})  "
          f"freshness recall v1.2={s['freshness_recall']:.0%} v1.1={s['legacy_v11_freshness_recall']:.0%}")
    return 0 if s["false_green"] == 0 and s["baseline_decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
