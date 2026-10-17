"""Pre-registered E9 analysis (PREREGISTRATION.md §7) on a results folder from the e9-replay workflow.

    python tools/replay/analyze_e9.py --results experiments/e9_release_replay/results/run-<id> \
        --e9 experiments/e9_release_replay > ANALYSIS.json

Every proportion: 95 % Wilson CI, plus a product-level cluster bootstrap (resample products, 5000x, seed 2026).
No significance tests between gates (decisions are deterministic functions of the same data).
"""
import argparse
import csv
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from crasme.validation import wilson  # noqa: E402

GATES = ["gate_none", "gate_naive_kev", "gate_cvss7", "gate_crasme_v1_2"]
# inventory classes the registration declares unassessable or expected-incomplete (§4)
INCOMPLETE_STATUSES = ("no-package-manifest", "resolve-in-ci (rebar3")


def prop(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "p": round(k / n, 4) if n else None, "wilson95": [round(lo, 4), round(hi, 4)] if n else None}


def cluster_boot(rows, pred, seed=2026, B=5000):
    by = defaultdict(list)
    for r in rows:
        by[r["product_id"]].append(r)
    prods = sorted(by)
    rng = random.Random(seed)
    vals = []
    for _ in range(B):
        s = [r for p in (rng.choice(prods) for _ in prods) for r in by[p]]
        vals.append(sum(map(pred, s)) / len(s))
    vals.sort()
    return [round(vals[int(0.025 * B)], 4), round(vals[int(0.975 * B) - 1], 4)]


def p_and_boot(rows, pred):
    d = prop(sum(map(pred, rows)), len(rows))
    d["product_bootstrap95"] = cluster_boot(rows, pred) if rows else None
    return d


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--e9", required=True)
    a = ap.parse_args(argv)
    R, E = Path(a.results), Path(a.e9)
    M = list(csv.DictReader(open(R / "release_metrics.csv")))
    F = list(csv.DictReader(open(R / "findings.csv")))
    X = list(csv.DictReader(open(R / "exposure.csv")))
    D = list(csv.DictReader(open(R / "drift.csv")))
    eco = {p["id"]: p["ecosystem"] for p in yaml.safe_load(open(E / "products.yaml"))["products"]}
    for m in M:
        m["_unassessed_strict"] = m["inventory_ok"] != "True" or int(m["unfetched_packages"]) > 0
        m["_incomplete_declared"] = m["_unassessed_strict"] or m["inventory_status"].startswith(INCOMPLETE_STATUSES)
        m["_undecidable"] = int(m["undecidable"]) > 0
    out = {"n_releases": len(M), "n_products": len({m["product_id"] for m in M}),
           "manifest": json.loads((R / "MANIFEST.json").read_text()) if (R / "MANIFEST.json").exists() else None}

    out["gate_decisions"] = {g: dict(Counter(m[g] for m in M)) for g in GATES}
    out["gate_crosstab_cvss7_vs_crasme"] = {f"{k[0]}|{k[1]}": v for k, v in
                                           Counter((m["gate_cvss7"], m["gate_crasme_v1_2"]) for m in M).items()}

    # H9a: silent PASS on releases whose inventory could not be assessed
    strict = [m for m in M if m["_unassessed_strict"]]
    declared = [m for m in M if m["_incomplete_declared"]]
    out["H9a"] = {
        "definition_strict": "inventory empty/invalid or vulnerability data incomplete",
        "strict": {g: prop(sum(m[g] == "PASS" for m in strict), len(strict)) for g in GATES},
        "definition_declared": "strict OR inventory class declared unassessable/expected-incomplete in the registration (§4: C/firmware without package manifest; rebar3 without lock)",
        "declared": {g: prop(sum(m[g] == "PASS" for m in declared), len(declared)) for g in GATES},
        "crasme_pass_on_declared": [f'{m["product_id"]} {m["tag"]} ({m["n_components"]} components)'
                                    for m in declared if m["gate_crasme_v1_2"] == "PASS"],
    }

    # H9b: assessable releases that shipped a vulnerability already KEV-listed at release
    assess = [m for m in M if not m["_incomplete_declared"]]
    kev_possible = [m for m in assess if "KEV_TRIAGE_PENDING" in m["crasme_reasons"].split()]
    out["H9b"] = {"known_kev_decided": p_and_boot(assess, lambda m: int(m["known_kev"]) > 0),
                  "known_kev_including_possibly_affected": prop(sum(int(m["known_kev"]) > 0 or m in kev_possible for m in assess), len(assess)),
                  "possibly_affected_releases": [f'{m["product_id"]} {m["tag"]}' for m in kev_possible],
                  "later_kev_listed_while_shipped": p_and_boot(assess, lambda m: int(m["later_kev"]) > 0),
                  "known_high": p_and_boot(assess, lambda m: int(m["known_high"]) > 0),
                  "known_any": p_and_boot(assess, lambda m: int(m["known_vulns"]) > 0),
                  "known_with_fix_available": p_and_boot(assess, lambda m: int(m["known_fix_available"]) > 0),
                  "ever_kev_listed_vulns": sorted({f["vuln_id"] + " (" + f["package"] + ", KEV " + f["kev_added_ever"] + ")"
                                                  for f in F if f["kev_added_ever"]})}

    # H9c: drift
    def drift(rows):
        j = [float(r["jaccard"]) for r in rows if r["jaccard"] not in ("", "None")]
        return {"transitions": len(j), "median_jaccard": round(statistics.median(j), 4) if j else None,
                "share_below_0.9": prop(sum(x < 0.9 for x in j), len(j))}
    lock_products = {m["product_id"] for m in M if m["inventory_status"] == "lockfile"}
    out["H9c"] = {"lockfile_products": drift([r for r in D if r["product_id"] in lock_products]),
                  "all_with_inventory": drift(D)}

    # H9d: exposure windows, one unit per (product, vuln, package)
    units = {}
    for x in X:
        k = (x["product_id"], x["vuln_id"], x["package"])
        units.setdefault(k, x)
    fixed = [int(u["days_published_to_fixed_release"]) for u in units.values() if u["days_published_to_fixed_release"] != ""]
    out["H9d"] = {"units": len(units), "fixed_within_window": len(fixed), "censored_not_fixed_in_window": len(units) - len(fixed),
                  "median_days_upper_bound": statistics.median(fixed) if fixed else None,
                  "quartiles": statistics.quantiles(fixed, n=4) if len(fixed) > 3 else None,
                  "share_over_30_days": prop(sum(d > 30 for d in fixed), len(fixed)),
                  "kev_listed_units": sum(bool(u["kev_added"]) for u in units.values())}

    # H9e: review burden
    out["H9e"] = {"crasme_review": p_and_boot(M, lambda m: m["gate_crasme_v1_2"] == "REVIEW_REQUIRED"),
                  "crasme_fail": prop(sum(m["gate_crasme_v1_2"] == "FAIL" for m in M), len(M)),
                  "cvss7_fail": p_and_boot(M, lambda m: m["gate_cvss7"] == "FAIL"),
                  "naive_kev_fail": prop(sum(m["gate_naive_kev"] == "FAIL" for m in M), len(M)),
                  "reason_codes_releases": dict(Counter(c for m in M for c in m["crasme_reasons"].split()).most_common())}

    # H9f: OpenCRA fail-safe probes and decisions on the release SBOMs
    oc = R / "opencra"
    if (oc / "opencra_probes.csv").exists():
        probes = {r["case"]: int(r["exit_code"]) for r in csv.DictReader(open(oc / "opencra_probes.csv"))}
        rel = list(csv.DictReader(open(oc / "opencra_releases.csv")))
        out["H9f"] = {"opencra_probe_exit_codes": probes,
                      "clean_exit_on_broken_input": [c for c in ("empty", "malformed") if probes.get(c) == 0],
                      "opencra_releases_scanned": len(rel),
                      "opencra_fail_on_kev_nonzero": sum(r["exit_code_fail_on_kev"] != "0" for r in rel),
                      "opencra_fail_on_high_nonzero": sum(r["exit_code_fail_on_high"] != "0" for r in rel)}

    # registered sensitivity: exclude releases with undecidable matches
    s = [m for m in M if not m["_undecidable"]]
    out["sensitivity_exclude_undecidable"] = {"n": len(s), "excluded": sorted({m["product_id"] for m in M if m["_undecidable"]}),
                                              "crasme_review": prop(sum(m["gate_crasme_v1_2"] == "REVIEW_REQUIRED" for m in s), len(s)),
                                              "cvss7_fail": prop(sum(m["gate_cvss7"] == "FAIL" for m in s), len(s))}

    # E1 at scale: Syft vs lockfile
    rows = [r for f in sorted(R.glob("sbom_vs_lockfile_*.csv")) for r in csv.DictReader(open(f))]
    by_eco = defaultdict(list)
    for r in rows:
        if r.get("recall_vs_lockfile") not in (None, "", "None"):
            by_eco[eco.get(r["product_id"], "?")].append(float(r["recall_vs_lockfile"]))
    out["E1_syft_recall_vs_lockfile"] = {e: {"releases": len(v), "median_recall": round(statistics.median(v), 4),
                                             "min": round(min(v), 4)} for e, v in sorted(by_eco.items())}
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
