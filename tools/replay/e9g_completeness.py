"""E9-G (POST-HOC, EXPLORATORY): completeness-aware gating. Protocol: experiments/e9_release_replay/E9G-PROTOCOL.md

    python tools/replay/e9g_completeness.py --e9 experiments/e9_release_replay \
        --results experiments/e9_release_replay/results/run-39047161461 \
        --cache <e9-osv-cache dir> --independent <dir with <product>-<tag>.opencra.json> --out <dir>
"""
import argparse
import csv
import json
import random
import sys
import tarfile
import tempfile
import time
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from crasme import completeness as C  # noqa: E402
from crasme import replay as R  # noqa: E402
from crasme.validation import wilson  # noqa: E402
from run_replay import OSVCache  # noqa: E402

SEED = 2026
FAULTS = ["F1_remove50", "F2_remove90", "F3_devonly", "F4_drop_ecosystem", "F5_two_components", "F6_strip_versions"]


def evaluate(pid, tag, when, sha, pkgs, osv, kev, kev_doc):
    vulns_by_pkg, vpub, unfetched, undecidable = {}, {}, 0, []
    for p in pkgs:
        vs = osv.vulns_for(p.ecosystem, p.name)
        if vs is None:
            unfetched += 1
            continue
        vulns_by_pkg[p] = vs
        vpub.update(osv.versions_published(p.ecosystem, p.name))
    rr = R.replay_release(pid, tag, when, pkgs, vulns_by_pkg, kev, vpub)
    for p, vs in vulns_by_pkg.items():
        for v in vs:
            if R.affects(v, p) is None and R.known_at(v, when):
                undecidable.append((p, v.get("id"), frozenset(v.get("aliases") or [])))
    d = R.engine_decision(rr, pkgs, sha, kev_doc, undecidable)
    g2 = d["decision"]
    if unfetched and g2 == "PASS":
        g2 = "REVIEW_REQUIRED"
    return {"G1": R.GATES["cvss7"](rr), "G2": g2}


def g3(g2, reasons):
    return "REVIEW_REQUIRED" if (g2 == "PASS" and reasons) else g2


def mutate(fault, inv_all, eco, rng):
    rt = [p for p in inv_all if not p.dev]
    if fault == "F1_remove50":
        return rng.sample(rt, len(rt) // 2) + [p for p in inv_all if p.dev]
    if fault == "F2_remove90":
        return rng.sample(rt, len(rt) // 10) + [p for p in inv_all if p.dev]
    if fault == "F3_devonly":
        dev = [replace(p, dev=False) for p in inv_all if p.dev]
        return dev or None
    if fault == "F4_drop_ecosystem":
        return [p for p in inv_all if p.ecosystem != eco]
    if fault == "F5_two_components":
        return rng.sample(rt, min(2, len(rt)))
    if fault == "F6_strip_versions":
        return [replace(p, version="") for p in inv_all]
    raise ValueError(fault)


def prop(rows, pred):
    k, n = sum(map(pred, rows)), len(rows)
    lo, hi = wilson(k, n)
    by = defaultdict(list)
    for r in rows:
        by[r["product_id"]].append(r)
    prods = sorted(by)
    rng = random.Random(SEED)
    vals = sorted(sum(map(pred, s)) / len(s) for s in
                  ([r for p in (rng.choice(prods) for _ in prods) for r in by[p]] for _ in range(5000)) if s) if prods else []
    return {"k": k, "n": n, "p": round(k / n, 4) if n else None, "wilson95": [round(lo, 4), round(hi, 4)] if n else None,
            "clusters": len(prods), "product_bootstrap95": [round(vals[124], 4), round(vals[4874], 4)] if vals else None}


def main(argv=None):
    ap = argparse.ArgumentParser()
    for a in ("--e9", "--results", "--cache", "--independent", "--out"):
        ap.add_argument(a, required=True)
    a = ap.parse_args(argv)
    E, Rd, out = Path(a.e9), Path(a.results), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="e9g-"))
    with tarfile.open(Rd / "inventories-as-run.tar.gz") as t:
        t.extractall(tmp, filter="data")
    inv_dir = tmp / "inventories"
    osv = OSVCache(Path(a.cache))
    kev_doc = json.loads((Path(a.cache) / "kev.json").read_text())
    kev = R.kev_index(kev_doc)
    eco_of = {p["id"]: p["ecosystem"] for p in yaml.safe_load(open(E / "products.yaml"))["products"]}
    rels = {(r["product_id"], r["tag"]): r for r in csv.DictReader(open(E / "releases.csv"))}
    M = {(m["product_id"], m["tag"]): m for m in csv.DictReader(open(Rd / "release_metrics.csv"))}

    def load(pid, tag):
        f = inv_dir / pid / f"{tag}.csv"
        if not f.exists():
            return []
        return [R.Pkg(r["ecosystem"], r["name"], r["version"], r["dev"] == "True") for r in csv.DictReader(open(f))]

    def independent(pid, tag):
        f = Path(a.independent) / f"{pid}-{tag}.opencra.json"
        if not f.exists():
            return None
        comps = json.loads(f.read_text())["sbom"]["components"]
        return [k for k in (C.purl_key(c.get("purl") or "") for c in comps) if k]

    # ---------------- Evaluation A: natural historical releases ----------------
    natural, timing = [], []
    for (pid, tag), m in M.items():
        inv_all = load(pid, tag)
        ind = independent(pid, tag) or []
        t0 = time.perf_counter()
        reasons = C.check(inv_all, m["inventory_status"], eco_of[pid], ind)
        timing.append(time.perf_counter() - t0)
        rt_n = sum(not p.dev for p in inv_all)
        natural.append({"product_id": pid, "tag": tag, "inventory_status": m["inventory_status"], "runtime_components": rt_n,
                        "independent_components": len(ind), "G1": m["gate_cvss7"], "G2": m["gate_crasme_v1_2"],
                        "G3": g3(m["gate_crasme_v1_2"], reasons), "completeness_reasons": " ".join(r["code"] for r in reasons),
                        "detail": "; ".join(r["detail"] for r in reasons)})
    strict = lambda r: M[(r["product_id"], r["tag"])]["inventory_ok"] != "True"  # noqa: E731
    declared_present = [r for r in natural if r["inventory_status"].startswith(C.INCOMPLETE_METHODS) and not strict(r)]
    tb_partial = [r for r in natural if r["product_id"] == "thingsboard" and r["tag"] in ("v3.9", "v3.9.1", "v4.0.1", "v4.2")]
    known_incomplete = declared_present + tb_partial
    controls_nat = [r for r in natural if r["inventory_status"] == "lockfile"]
    with open(out / "e9g_natural.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(natural[0]))
        w.writeheader()
        w.writerows(natural)
    A = {"known_incomplete_n": len(known_incomplete),
         "pass_on_known_incomplete": {g: prop(known_incomplete, lambda r, g=g: r[g] == "PASS") for g in ("G1", "G2", "G3")},
         "complete_controls_n": len(controls_nat),
         "G2_pass_controls": sum(r["G2"] == "PASS" for r in controls_nat),
         "unnecessary_review_on_controls": prop([r for r in controls_nat if r["G2"] == "PASS"], lambda r: r["G3"] != "PASS"),
         "review_rate_all": {g: prop(natural, lambda r, g=g: r[g] == "REVIEW_REQUIRED") for g in ("G2", "G3")},
         "reasons_all": {c: sum(c in r["completeness_reasons"].split() for r in natural) for c in C.REASONS},
         "c_rules_ms_per_release_median": round(sorted(timing)[len(timing) // 2] * 1000, 3),
         "c_rules_ms_per_release_max": round(max(timing) * 1000, 3)}

    # ---------------- Evaluation B: seeded faults on complete controls ----------------
    controls = [r for r in controls_nat if r["G2"] == "PASS"]
    rng = random.Random(SEED)
    seeded, consistency = [], []
    for c in controls:
        pid, tag = c["product_id"], c["tag"]
        rel = rels[(pid, tag)]
        when = R._dt(rel["release_date_utc"])
        inv_all = load(pid, tag)
        ind = independent(pid, tag) or []
        eco = C.DECLARED_ECO.get(eco_of[pid])
        base = evaluate(pid, tag, when, rel["commit_sha"], [p for p in inv_all if not p.dev], osv, kev, kev_doc)
        consistency.append(base["G2"] == c["G2"] and base["G1"] == c["G1"])
        for f in FAULTS:
            mut = mutate(f, inv_all, eco, rng)
            if mut is None:
                continue
            rt = [p for p in mut if not p.dev]
            d = evaluate(pid, tag, when, rel["commit_sha"], rt, osv, kev, kev_doc)
            reasons = C.check(mut, c["inventory_status"], eco_of[pid], ind)
            seeded.append({"product_id": pid, "tag": tag, "fault": f, "runtime_components_after": len(rt),
                           "G1": d["G1"], "G2": d["G2"], "G3": g3(d["G2"], reasons),
                           "completeness_reasons": " ".join(r["code"] for r in reasons)})
    with open(out / "e9g_seeded.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(seeded[0]))
        w.writeheader()
        w.writerows(seeded)
    Bres = {"controls": len(controls), "controls_products": len({c["product_id"] for c in controls}),
            "baseline_reproduces_registered_decisions": f"{sum(consistency)}/{len(consistency)}",
            "faulty_inventories": len(seeded),
            "false_pass_all_faults": {g: prop(seeded, lambda r, g=g: r[g] == "PASS") for g in ("G1", "G2", "G3")},
            "false_pass_by_fault": {f: {g: prop([r for r in seeded if r["fault"] == f], lambda r, g=g: r[g] == "PASS")
                                        for g in ("G1", "G2", "G3")} for f in FAULTS},
            "c_rule_detection_recall": prop(seeded, lambda r: bool(r["completeness_reasons"])),
            "c_rule_detection_by_fault": {f: prop([r for r in seeded if r["fault"] == f], lambda r: bool(r["completeness_reasons"]))
                                          for f in FAULTS}}
    res = {"label": "E9-G POST-HOC / EXPLORATORY (protocol committed 39cc882 before implementation)",
           "rules": {"coverage_min": C.COVERAGE_MIN, "min_independent": C.MIN_INDEPENDENT, "reasons": C.REASONS},
           "A_natural": A, "B_seeded": Bres}
    (out / "E9G.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
