"""EXPLORATORY (not registered) re-analyses of the registered E9 run, added after peer feedback.

    python tools/replay/analyze_e9_posthoc.py --results experiments/e9_release_replay/results/run-39047161461 \
        --e9 experiments/e9_release_replay > POSTHOC.json

1. H9d with censoring handled explicitly: time to first observed absence (TFOA) in a sampled release.
   Interval censoring: absence happened in (last sampled release still containing, first sampled release without].
   Right censoring: still present in the last sampled release. Kaplan-Meier medians for the upper (right
   endpoint) and lower (left endpoint) bounds, with product-cluster bootstrap CIs.
2. Product-cluster bootstrap 95% CIs (20 clusters, 5000 resamples, seed 2026) for every primary proportion.
3. Named, distinct definitions for the fix-availability statistics (any known vs. high/critical known).
4. Sensitivity: exclude Mosquitto (did not meet the activity criterion).
"""
import argparse
import csv
import json
import random
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme.validation import wilson  # noqa: E402

GATES = ["gate_none", "gate_naive_kev", "gate_cvss7", "gate_crasme_v1_2"]
INCOMPLETE = ("no-package-manifest", "resolve-in-ci (rebar3")
SEED, B = 2026, 5000


def d(s):
    return date.fromisoformat(s[:10])


def cluster_ci(rows, stat, key="product_id"):
    by = defaultdict(list)
    for r in rows:
        by[r[key]].append(r)
    prods = sorted(by)
    rng = random.Random(SEED)
    vals = []
    for _ in range(B):
        v = stat([r for p in (rng.choice(prods) for _ in prods) for r in by[p]])
        if v is not None:
            vals.append(v)
    vals.sort()
    if not vals:
        return None
    return [round(vals[int(0.025 * len(vals))], 4), round(vals[int(0.975 * len(vals)) - 1], 4)]


def prop(rows, pred):
    k, n = sum(map(pred, rows)), len(rows)
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "p": round(k / n, 4) if n else None, "wilson95": [round(lo, 4), round(hi, 4)] if n else None,
            "clusters": len({r["product_id"] for r in rows}),
            "product_bootstrap95": cluster_ci(rows, lambda s: sum(map(pred, s)) / len(s) if s else None)}


def km_median(times_events):
    """Kaplan-Meier median from (time, event) pairs; None if the curve never reaches 0.5."""
    pts = sorted(times_events)
    n = len(pts)
    if not n:
        return None
    s, i = 1.0, 0
    while i < n:
        t = pts[i][0]
        deaths = sum(1 for tt, e in pts[i:] if tt == t and e)
        at_risk = n - i
        tied = sum(1 for tt, _ in pts[i:] if tt == t)
        if deaths:
            s *= 1 - deaths / at_risk
            if s <= 0.5:
                return t
        i += tied
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--e9", required=True)
    a = ap.parse_args(argv)
    R = Path(a.results)
    M = list(csv.DictReader(open(R / "release_metrics.csv")))
    F = list(csv.DictReader(open(R / "findings.csv")))
    X = list(csv.DictReader(open(R / "exposure.csv")))
    rel_date = {(m["product_id"], m["tag"]): d(m["release_date"]) for m in M}
    for m in M:
        m["_strict"] = m["inventory_ok"] != "True" or int(m["unfetched_packages"]) > 0
        m["_declared"] = m["_strict"] or m["inventory_status"].startswith(INCOMPLETE)
    out = {"label": "EXPLORATORY, not registered; added after peer feedback (18 Oct 2026)"}

    # ---- 1. TFOA with censoring --------------------------------------------------------------------
    present = defaultdict(list)                       # unit -> dates of sampled releases that contain it
    for f in F:
        present[(f["product_id"], f["vuln_id"], f["package"])].append(d(f["release_date"]))
    units = {}
    for x in X:                                       # earliest exposed release first (file order = date order)
        units.setdefault((x["product_id"], x["vuln_id"], x["package"]), x)
    last_rel = defaultdict(lambda: date.min)
    for (p, _), dt in rel_date.items():
        last_rel[p] = max(last_rel[p], dt)
    rows = []
    for k, u in units.items():
        pub = d(u["published"])
        last_present = max(present.get(k, [pub]))
        if u["first_sampled_release_without"]:
            upper = int(u["days_published_to_fixed_release"])
            lower = max(0, (last_present - pub).days)
            rows.append({"product_id": k[0], "upper": upper, "lower": min(lower, upper), "event": True})
        else:
            c = max(0, (last_present - pub).days)
            rows.append({"product_id": k[0], "upper": c, "lower": c, "event": False})

    def km(rs, which):
        return km_median([(r[which], r["event"]) for r in rs])
    out["H9d_tfoa"] = {
        "estimand": "time from OSV publication to first OBSERVED absence in a SAMPLED release (not fix or deployment time)",
        "units": len(rows), "observed_absence": sum(r["event"] for r in rows),
        "right_censored": sum(not r["event"] for r in rows),
        "conditional_median_upper_observed_only": sorted(r["upper"] for r in rows if r["event"])[sum(r["event"] for r in rows) // 2],
        "km_median_upper_bound_days": km(rows, "upper"),
        "km_median_lower_bound_days": km(rows, "lower"),
        "km_median_upper_product_bootstrap95": cluster_ci(rows, lambda s: km(s, "upper")),
        "km_median_lower_product_bootstrap95": cluster_ci(rows, lambda s: km(s, "lower")),
        "share_over_30_days_upper_among_observed": prop([r for r in rows if r["event"]], lambda r: r["upper"] > 30),
        "share_over_30_days_lower_among_observed": prop([r for r in rows if r["event"]], lambda r: r["lower"] > 30),
    }

    # ---- 2./3. primary proportions with product-cluster CIs ----------------------------------------
    strict = [m for m in M if m["_strict"]]
    declared = [m for m in M if m["_declared"]]
    present_incomplete = [m for m in declared if not m["_strict"]]
    assess = [m for m in M if not m["_declared"]]
    hi_fix = {(f["product_id"], f["tag"]) for f in F if f["status"] == "known" and f["cvss"] and float(f["cvss"]) >= 7
              and f["fix_available_at_release"] == "True"}
    out["primary"] = {
        "H9a_pass_strict": {g: prop(strict, lambda m, g=g: m[g] == "PASS") for g in GATES},
        "H9a_pass_declared": {g: prop(declared, lambda m, g=g: m[g] == "PASS") for g in GATES},
        "H9a_pass_present_but_incomplete": {g: prop(present_incomplete, lambda m, g=g: m[g] == "PASS") for g in GATES},
        "H9b_known_kev": prop(assess, lambda m: int(m["known_kev"]) > 0),
        "known_any": prop(assess, lambda m: int(m["known_vulns"]) > 0),
        "known_high_or_critical": prop(assess, lambda m: int(m["known_high"]) > 0),
        "known_any_with_fix_available": prop(assess, lambda m: int(m["known_fix_available"]) > 0),
        "known_high_or_critical_with_fix_available": prop(assess, lambda m: (m["product_id"], m["tag"]) in hi_fix),
        "H9e_crasme_review": prop(M, lambda m: m["gate_crasme_v1_2"] == "REVIEW_REQUIRED"),
        "H9e_cvss7_fail": prop(M, lambda m: m["gate_cvss7"] == "FAIL"),
        "note_zero_events": "for 0/n outcomes every bootstrap resample is 0, so the cluster interval degenerates to [0, 0]; "
                            "the Wilson upper bound is the informative one",
    }
    D = list(csv.DictReader(open(R / "drift.csv")))
    lock = {m["product_id"] for m in M if m["inventory_status"] == "lockfile"}
    Dl = [r for r in D if r["product_id"] in lock and r["jaccard"] not in ("", "None")]
    out["primary"]["H9c_share_below_0.9"] = prop(Dl, lambda r: float(r["jaccard"]) < 0.9)

    # ---- 4. sensitivity: exclude Mosquitto ---------------------------------------------------------
    Mx = [m for m in M if m["product_id"] != "mosquitto"]
    out["sensitivity_exclude_mosquitto"] = {
        "n_releases": len(Mx),
        "H9a_pass_strict": {g: prop([m for m in Mx if m["_strict"]], lambda m, g=g: m[g] == "PASS") for g in GATES},
        "H9a_pass_declared": {g: prop([m for m in Mx if m["_declared"]], lambda m, g=g: m[g] == "PASS") for g in GATES},
        "H9e_crasme_review": prop(Mx, lambda m: m["gate_crasme_v1_2"] == "REVIEW_REQUIRED"),
        "H9e_cvss7_fail": prop(Mx, lambda m: m["gate_cvss7"] == "FAIL"),
        "note": "Mosquitto contributes no assessable release, so H9b-H9d are unchanged",
    }
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
