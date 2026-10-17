"""Generate the E3 Latin-square allocation sheet.
    python experiments/e3_rater_study/allocate.py --raters 9 --scenarios 48 --seed 2026 --out allocation.csv
Record the seed in the pre-registration."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme.e3 import allocate, check_balance  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--raters", type=int, default=9)
ap.add_argument("--scenarios", type=int, default=48)
ap.add_argument("--seed", type=int, default=2026)
ap.add_argument("--out", default="allocation.csv")
a = ap.parse_args()
alloc = allocate([f"R{i+1:02d}" for i in range(a.raters)], [f"SC{i+1:02d}" for i in range(a.scenarios)], a.seed)
print(check_balance(alloc))
alloc.to_csv(a.out, index=False)
print(f"{len(alloc)} rating tasks -> {a.out}")
