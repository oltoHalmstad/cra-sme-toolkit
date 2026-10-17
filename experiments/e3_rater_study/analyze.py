"""Pre-registered E3 analysis. Input: ratings CSV (data-templates/e3_ratings.csv columns) and a
reference CSV (scenario_id,reference) from the expert panel.
    python experiments/e3_rater_study/analyze.py ratings.csv reference.csv
    python experiments/e3_rater_study/analyze.py --simulate        # dry run on synthetic data"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme import e3  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("ratings", nargs="?")
ap.add_argument("reference", nargs="?")
ap.add_argument("--simulate", action="store_true")
ap.add_argument("--n-boot", type=int, default=1000)
a = ap.parse_args()
if a.simulate:
    alloc = e3.allocate([f"R{i}" for i in range(9)], [f"S{i:02d}" for i in range(48)])
    df, ref = e3.simulate(alloc)
    print("SYNTHETIC DRY RUN")
else:
    df = pd.read_csv(a.ratings)
    ref = pd.read_csv(a.reference).set_index("scenario_id")["reference"]
res = {"alpha_by_condition": e3.alpha_by_condition(df),
       "E3-1": e3.delta_alpha(df, "B", "A", n_boot=a.n_boot),
       "E3-2": e3.delta_alpha(df, "C", "B", n_boot=a.n_boot),
       "E3-3": e3.deviation_model(df, ref)}
print(json.dumps(res, indent=2))
