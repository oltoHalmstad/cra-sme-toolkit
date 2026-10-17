"""Regenerate notebooks/ from source cells. Usage: python tools/build_notebooks.py notebooks && python tools/run_notebooks.py"""
import sys
from pathlib import Path
import nbformat as nbf

OUT = Path(sys.argv[1])
SETUP = """import sys, pathlib
ROOT = pathlib.Path.cwd().resolve().parent if pathlib.Path.cwd().name == 'notebooks' else pathlib.Path.cwd().resolve()
sys.path.insert(0, str(ROOT))
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from crasme import plotting; plotting.use()
pd.set_option('display.precision', 3); pd.set_option('display.width', 140)"""


def nb(name, cells):
    n = nbf.v4.new_notebook()
    n.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
    out = []
    for kind, src in cells:
        out.append(nbf.v4.new_markdown_cell(src.strip()) if kind == "md" else nbf.v4.new_code_cell(src.strip()))
    n.cells = out
    nbf.write(n, OUT / name)


M, C = "md", "code"

# ---------------------------------------------------------------- 01
nb("01_risk_model_sensitivity.ipynb", [
(M, """# 01 · Risk model: properties, sensitivity and an uncertainty-aware alternative
**Supports:** RQ3, concept note §7, experiment **E3** (design input).
**Data:** workbook DEMO rows + a *synthetic* 20-scenario register (seeded). Nothing here is an observation of a real product.

Questions this notebook answers before any SME data is collected:
1. What are the arithmetic properties of the v1.0 score `L × I × E` (ties, band coverage)?
2. How stable is the ranking under realistic assessor noise, and do other aggregations do better?
3. How sensitive is the residual score to the (often unverified) effectiveness assumption?
4. Does an uncertainty-aware Monte Carlo (FAIR-inspired) ranking agree with the ordinal ranking?"""),
(C, SETUP + "\nfrom crasme import risk as r"),
(M, "## 1 · Parity with the workbook\nThe Python model reproduces the Excel formulas exactly (also enforced by `tests/test_workbook.py` via LibreOffice recalculation)."),
(C, """demo = [r.RiskRow('DEMO-R01','DEMO-001','Unauthenticated management endpoint',4,5,4,0.5,0.2,150000),
        r.RiskRow('DEMO-R02','DEMO-001','Outdated dependency exploited',3,4,4,0.4,0.1,80000)]
pd.DataFrame([{ 'risk': d.risk_id, 'inherent': d.inherent, 'band': d.inherent_band, 'residual': d.residual,
               'res_band': d.residual_band, 'ALE €': d.inherent_ale, 'residual ALE €': d.residual_ale} for d in demo])"""),
(M, "## 2 · Arithmetic properties of L × I × E\nOnly **30 distinct values** exist out of 125 cells, so ties are frequent; bands cover unequal shares of the cube."),
(C, """vals = r.distinct_lie_scores()
print(len(vals), 'distinct scores:', vals)
dist = r.band_distribution(); print({k: f'{v:.0%}' for k, v in dist.items()})
grid = np.array([[l*i for i in range(1,6)] for l in range(1,6)])
fig, axes = plt.subplots(1, 3, figsize=(11, 3.4), sharey=True)
for ax, e in zip(axes, (1, 3, 5)):
    im = ax.imshow(grid*e, origin='lower', cmap='Blues', vmin=1, vmax=125)
    for (a, b), v in np.ndenumerate(grid*e):
        ax.text(b, a, f'{v}\\n{r.band(v)[0]}', ha='center', va='center', fontsize=7,
                color='white' if v > 70 else plotting.INK)
    ax.set_title(f'Exposure = {e}'); ax.set_xticks(range(5), range(1,6)); ax.set_yticks(range(5), range(1,6))
    ax.set_xlabel('Impact'); ax.grid(False)
axes[0].set_ylabel('Likelihood'); fig.suptitle('Inherent score and band (L/M/H/C) by cell', y=1.02); plt.show()"""),
(M, "## 3 · Synthetic register and ranking stability under assessor noise\nNoise model: each 1–5 rating moves ±1 with probability *p* (an assumption to be replaced by the E3 empirical noise estimate). We compare Kendall τ-b against the noise-free ranking and the share of the true top-3 retained."),
(C, """rng = np.random.default_rng(42)
lie = rng.integers(1, 6, size=(20, 3))
rows = []
for agg in r.AGGREGATORS:
    for p in (0.1, 0.2, 0.3, 0.5):
        s = r.ranking_stability(lie, agg, p_shift=p, n_sim=400, seed=1)
        rows.append({'aggregator': agg, 'p_shift': p, **s})
stab = pd.DataFrame(rows)
stab.pivot(index='aggregator', columns='p_shift', values='tau_mean')"""),
(C, """fig, axes = plt.subplots(1, 2, figsize=(10, 3.4))
for ax, metric, title in [(axes[0], 'tau_mean', 'Mean Kendall τ-b vs noise-free'), (axes[1], 'topk_overlap', 'Share of true top-3 retained')]:
    for i, agg in enumerate(['product', 'sum', 'max']):   # 3 series max; others in table above
        d = stab[stab.aggregator == agg]
        ax.plot(d.p_shift, d[metric], marker='o', color=plotting.SERIES[i], label=agg)
    ax.set_title(title); ax.set_xlabel('P(rating shifts ±1)'); ax.set_ylim(0, 1.02)
axes[0].legend(); plt.tight_layout(); plt.show()
print('Tie share among 20 synthetic risks (product):', round(r.tie_share([a*b*c for a,b,c in lie]), 3),
      '| max:', round(r.tie_share([max(x) for x in lie]), 3))"""),
(M, "**Reading:** with even modest noise the ordinal ranking degrades quickly — this motivates E3 (measure real inter-rater noise) and the rule that **release blockers must not depend on the score**."),
(M, "## 4 · Sensitivity of the residual score to the effectiveness assumption"),
(C, """eff = np.linspace(0, 0.9, 10)
fig, ax = plt.subplots(figsize=(6.5, 3.4))
for i, d in enumerate(demo):
    ax.plot(eff, [r.residual_score(d.inherent, e) for e in eff], marker='o', color=plotting.SERIES[i], label=d.risk_id)
for thr, lbl in [(75,'Critical'),(40,'High'),(15,'Medium')]:
    ax.axhline(thr, color=plotting.GRID, lw=1); ax.text(0.905, thr+1, lbl, fontsize=8, color=plotting.INK2)
ax.set_xlabel('Assumed verified control effectiveness'); ax.set_ylabel('Residual score'); ax.legend(); ax.set_title('Band changes driven purely by an assumption'); plt.show()"""),
(M, "## 5 · Uncertainty-aware Monte Carlo (FAIR-inspired)\nRanges replace point estimates: frequency as Beta-PERT(min, mode, max) events/year, loss per event as a lognormal fitted to an elicited 90 % CI, annual loss = Σ Poisson(freq) events. Values are synthetic."),
(C, """sc = [r.UncertainScenario(f'S{i:02d}', *sorted(rng.uniform(0.01, 1.2, 3)),
        *(lambda lo: (lo, lo*rng.uniform(3, 30)))(rng.uniform(2e3, 6e4)), 0.2, 0.6) for i in range(20)]
res = [r.simulate_annual_loss(s, n=20000, seed=i) for i, s in enumerate(sc)]
mc = pd.DataFrame({'risk': [x.risk_id for x in res], 'mean_€': [x.mean for x in res],
                   'p90_€': [x.quantile(.9) for x in res], 'P(>100k)': [x.prob_exceed(1e5) for x in res]})
top = r.rank_probability(res, top_k=3); mc['P(top-3)'] = mc.risk.map(top)
from scipy.stats import kendalltau
print('Kendall τ mean-ALE vs P90:', round(kendalltau(mc['mean_€'], mc['p90_€']).statistic, 3))
mc.sort_values('mean_€', ascending=False).head(8)"""),
(C, """d = mc.sort_values('mean_€')
fig, ax = plt.subplots(figsize=(7, 5))
lo = [x.quantile(.05) for x in res]; hi = [x.quantile(.95) for x in res]
q = pd.DataFrame({'risk': mc.risk, 'lo': lo, 'hi': hi, 'mean': mc['mean_€']}).set_index('risk').loc[d.risk]
ax.hlines(range(len(q)), q.lo, q.hi, color=plotting.SERIES[0], lw=2)
ax.plot(q['mean'], range(len(q)), 'o', color=plotting.SERIES[0], markeredgecolor=plotting.SURFACE, markeredgewidth=2)
ax.set_yticks(range(len(q)), q.index); ax.set_xscale('symlog', linthresh=1e3)
ax.set_xlabel('Annual loss € (5th–95th percentile, dot = mean)'); ax.set_title('Uncertainty ranges overlap heavily'); plt.show()"""),
(M, """## 6 · Take-aways to carry into the manuscript
* `L×I×E` is a usable *triage* aid but has coarse resolution (30 values) and is sensitive to ±1 rating noise.
* Residual bands can be moved across thresholds by the effectiveness assumption alone → record the evidence ID for every effectiveness value (new workbook column AH).
* Monte Carlo output exposes overlap between risks that point scores hide; report `P(top-k)` rather than a single rank.
* **Hypothesis for E3:** explicit, evidence-linked assumptions increase inter-rater agreement more than the choice of numeric model."""),
])

# ---------------------------------------------------------------- 02
nb("02_inter_rater_agreement_E3.ipynb", [
(M, """# 02 · Inter-rater agreement analysis and sample-size planning (E3)
**Supports:** RQ3. **Design:** blinded assessors rate the same scenarios under condition **A** (qualitative, v1.0 sheet only) and **B** (structured: explicit assumptions, evidence links, ranges).
This notebook (1) shows the exact analysis that will be run on `experiments/data-templates/e3_ratings.csv`, and (2) simulates how many raters × scenarios are needed to detect a difference in agreement. **All data below is simulated.**"""),
(C, SETUP + "\nfrom crasme import agreement as a"),
(M, "## 1 · Analysis pipeline on a simulated dataset (long format, same columns as the data template)"),
(C, """rng = np.random.default_rng(7)
def simulate(n_items=24, n_raters=6, noise=0.9, cond='A'):
    truth = rng.normal(3, 1.1, n_items)
    rows = []
    for rt in range(n_raters):
        bias = rng.normal(0, 0.3)
        for it in range(n_items):
            v = int(np.clip(np.rint(truth[it] + bias + rng.normal(0, noise)), 1, 5))
            rows.append({'condition': cond, 'rater_id': f'R{rt+1}', 'scenario_id': f'SC{it+1:02d}', 'dimension': 'likelihood', 'rating': v})
    return pd.DataFrame(rows)
df = pd.concat([simulate(noise=0.95, cond='A'), simulate(noise=0.6, cond='B')])
df.head()"""),
(C, """def agreement(d):
    m = d.pivot(index='rater_id', columns='scenario_id', values='rating').to_numpy(float)
    alpha = a.bootstrap_ci(lambda x: a.krippendorff_alpha(x, 'ordinal'), m, n_boot=1000, axis=1)
    icc = a.bootstrap_ci(lambda x: a.icc(x, 'ICC2_1'), m.T, n_boot=1000, axis=0)
    return pd.Series({'alpha_ord': alpha[0], 'alpha_lo': alpha[1], 'alpha_hi': alpha[2],
                      'icc21': icc[0], 'icc_lo': icc[1], 'icc_hi': icc[2], 'icc_label': a.interpret_icc(icc[0])})
summary = df.groupby('condition').apply(agreement, include_groups=False); summary"""),
(C, """fig, ax = plt.subplots(figsize=(6, 2.6))
for i, (cond, row) in enumerate(summary.iterrows()):
    ax.errorbar(row.alpha_ord, i, xerr=[[row.alpha_ord-row.alpha_lo], [row.alpha_hi-row.alpha_ord]], fmt='o',
                color=plotting.SERIES[i], capsize=0, lw=2)
    ax.text(row.alpha_hi + 0.01, i, f'{cond}: α={row.alpha_ord:.2f}', va='center', fontsize=9, color=plotting.INK2)
ax.set_yticks([0, 1], ['A qualitative', 'B structured']); ax.set_xlim(0, 1)
for t in (0.667, 0.8): ax.axvline(t, color=plotting.GRID, lw=1)
ax.set_xlabel("Krippendorff's α (ordinal), 95% bootstrap CI"); ax.set_title('Simulated agreement by condition'); plt.show()"""),
(M, "Thresholds drawn at α = 0.667 and 0.8 (Krippendorff's conventional limits for tentative and reliable conclusions). Pairwise weighted κ (quadratic) is also reported for 2-rater subsets:"),
(C, """d = df[df.condition=='A'].pivot(index='scenario_id', columns='rater_id', values='rating')
print('Quadratic-weighted κ R1 vs R2 (A):', round(a.weighted_kappa(d.R1, d.R2, range(1,6)), 3))"""),
(M, "## 2 · Sample-size planning\nHow often does the 95 % CI of the α difference (B − A) exclude 0, for a given number of raters and scenarios? (Noise levels 0.95 → 0.6 correspond to α ≈ 0.55 → 0.75; replace with pilot estimates.)"),
(C, """def power(n_items, n_raters, sims=60):
    hits = 0
    for s in range(sims):
        A = simulate(n_items, n_raters, 0.95, 'A'); B = simulate(n_items, n_raters, 0.6, 'B')
        ma = A.pivot(index='rater_id', columns='scenario_id', values='rating').to_numpy(float)
        mb = B.pivot(index='rater_id', columns='scenario_id', values='rating').to_numpy(float)
        diffs = []
        for _ in range(150):
            idx = rng.integers(0, n_items, n_items)
            diffs.append(a.krippendorff_alpha(mb[:, idx], 'ordinal') - a.krippendorff_alpha(ma[:, idx], 'ordinal'))
        hits += np.quantile(diffs, 0.025) > 0
    return hits / sims
grid = pd.DataFrame([{'scenarios': n, 'raters': k, 'power': power(n, k)} for n in (12, 24, 48) for k in (3, 6, 9)])
grid.pivot(index='scenarios', columns='raters', values='power')"""),
(M, """**Planning reading:** choose the smallest design with power ≥ 0.8 under the noise measured in the first 1–2 pilot sessions. Under these assumed effects even 48 scenarios × 9 raters may fall short — agreement differences of ~0.2 in α need many more scenarios than a typical SME pilot provides, so plan E3 as a **pooled cross-SME rater study** (practitioners from several pilots rating a shared scenario bank), not as a per-SME measurement. Pre-register the noise estimate and the decision rule (`experiments/protocols/PREREGISTRATION-template.md`)."""),
])

# ---------------------------------------------------------------- 03
nb("03_sbom_and_scanner_benchmark_E1_E2.ipynb", [
(M, """# 03 · SBOM generator accuracy (E1 — real pilot run) and scanner agreement (E2 — synthetic)
**Supports:** RQ4, Annex I Part II(1), traceability metric *SBOM completeness*.

**E1 pilot (real):** run on 17 Oct 2026 in a sandbox with three generators that were installable offline (cdxgen 12.8.6, cyclonedx-py 7.5.0, cyclonedx-npm 6.0.1) against three fixtures. Ground truth = the package manager's *installed* set (`pip freeze` in the venv, `npm ls --all`); the `c-vendored` fixture is a hand-curated synthetic case (vendored zlib header + Conan manifest).
Syft and Trivy are in the runner but could not be installed in the sandbox; run `experiments/e1_sbom_benchmark/run_e1.sh` in your environment to add them.

**E2 (synthetic):** the scanner JSON files are constructed to exercise the analysis; CVE IDs are real advisories for those package versions, but which scanner reports what is invented."""),
(C, SETUP + "\nfrom crasme import sbom, vulns\nE1 = ROOT/'experiments'/'e1_sbom_benchmark'; E2 = ROOT/'experiments'/'e2_scanner_agreement'/'synthetic'"),
(C, """runs = pd.read_csv(E1/'pilot-results'/'runs.csv')
rows = []
for _, run in runs.iterrows():
    truth = sbom.load_ground_truth(E1/'fixtures'/run.fixture/'ground_truth.csv')
    found, meta = sbom.load_sbom(E1/'pilot-results'/pathlib.Path(run.output).name)
    v = sbom.accuracy(found, truth); n = sbom.accuracy(found, truth, 'name')
    rows.append({'fixture': run.fixture, 'generator': f'{run.generator} ({run['mode']})', 'version': run.tool_version,
                 'format': meta['format'], 'truth_n': len(truth), 'found_n': len(found),
                 'precision': v['precision'], 'recall': v['recall'], 'f1': v['f1'], 'name_recall': n['recall'], 'seconds': run.seconds})
e1 = pd.DataFrame(rows); e1"""),
(C, """fig, ax = plt.subplots(figsize=(7.5, 3.4))
lab = e1.fixture + ' · ' + e1.generator
y = np.arange(len(e1))
ax.barh(y, e1.recall, color=plotting.SERIES[0], height=0.55)
for i, (rc, pr) in enumerate(zip(e1.recall, e1.precision)):
    ax.text(rc + 0.01, i, f'recall {rc:.2f} · precision {pr:.2f}', va='center', fontsize=8, color=plotting.INK2)
ax.set_yticks(y, lab); ax.set_xlim(0, 1.45); ax.set_xlabel('Version-level recall vs installed ground truth'); ax.set_title('E1 pilot: what each generator found'); plt.show()"""),
(C, """for _, run in runs.iterrows():
    truth = sbom.load_ground_truth(E1/'fixtures'/run.fixture/'ground_truth.csv')
    found, _ = sbom.load_sbom(E1/'pilot-results'/pathlib.Path(run.output).name)
    d = sbom.diff_report(found, truth)
    if d['missing'] or d['extra']:
        print(f'{run.fixture:10s} {run.generator:13s} {run['mode']:12s} missing={d["missing"]} extra={d["extra"]}')"""),
(M, """### E1 pilot findings (n = 3 fixtures — illustrative, not generalisable)
1. **Mode matters more than tool:** `cyclonedx-py requirements` (manifest-only) found 4/12 packages; the same tool in `environment` mode found 12/12. A CI job that SBOMs a manifest instead of the built artefact silently under-reports transitive dependencies — directly relevant to Annex I Part II(1).
2. **Ground-truth definition is a validity threat:** both environment-aware tools listed `pip` itself (counted as a false positive here). The protocol must fix *what counts as a product component* before scoring.
3. **Vendored C code is invisible** to manifest-based generators (`zlib` 1.2.11 missed; Conan dependency found) — the expected weak spot for embedded/IoT SMEs, so E1 must include firmware/C fixtures and binary-analysis tools.
4. Node lockfile-based tools were exact on this small tree."""),
(M, "## E2 · Scanner agreement on the same dependency tree (synthetic outputs)"),
(C, """by = {s: vulns.load_findings(E2/f'node-app.{s}.json', s) for s in ('trivy', 'grype', 'osv-scanner')}
print({s: len(v) for s, v in by.items()})
pd.DataFrame(vulns.agreement_table(by))"""),
(C, """allkeys = sorted(set().union(*[{f.key for f in v} for v in by.values()]))
mat = pd.DataFrame({s: [k in {f.key for f in v} for k in allkeys] for s, v in by.items()},
                   index=[f'{k[0]} {k[1]}' for k in allkeys]).astype(int)
fig, ax = plt.subplots(figsize=(5.5, 4.2))
ax.imshow(mat.to_numpy(), cmap='Blues', vmin=0, vmax=1.4, aspect='auto')
ax.set_xticks(range(3), mat.columns); ax.set_yticks(range(len(mat)), mat.index, fontsize=8); ax.grid(False)
for (i, j), v in np.ndenumerate(mat.to_numpy()): ax.text(j, i, '✓' if v else '–', ha='center', va='center', fontsize=9, color='white' if v else plotting.INK2)
ax.set_title('Which scanner reports which finding'); plt.tight_layout(); plt.show()
sev = pd.DataFrame([{'key': f'{f.package} {f.vuln_id}', 'scanner': f.scanner, 'severity': f.severity} for v in by.values() for f in v])
sev.pivot(index='key', columns='scanner', values='severity').query('trivy != grype')"""),
(M, """**E2 analysis plan (real data):** union of findings → expert adjudication sample (true/false positive, reachable or not) → per-scanner precision/recall against adjudicated set; severity disagreement rate; time-to-triage per finding with/without VEX. Consensus (≥2 scanners) is a triage heuristic only, never ground truth."""),
])

# ---------------------------------------------------------------- 04
nb("04_traceability_evidence_E4.ipynb", [
(M, """# 04 · Evidence traceability, freshness and the score-independent release gate (E4)
**Supports:** RQ1, RQ4, O3. Builds the traceability units for the DEMO product from the 46-row obligation catalogue, then injects lifecycle events (dependency bump, new exploited CVE, evidence tampering) and shows what the metrics and the gate do. **Synthetic product.**"""),
(C, SETUP + "\nfrom crasme import traceability as t\nimport json, copy"),
(C, """cat = pd.DataFrame(t.load_catalogue())
print(len(cat), 'obligations'); cat.groupby(['gate', 'mandatory']).size().unstack(fill_value=0)"""),
(M, "## 1 · A plausible mid-implementation state\nRandomly (seeded) assign status to obligations to mimic an SME at week 8 of the playbook."),
(C, """rng = np.random.default_rng(3)
units = []
for _, row in cat.iterrows():
    applicable = not (row.req_id in ('OSS-01', 'P1-m', 'REP-04'))
    st = rng.choice(['verified', 'implemented', 'in_progress', 'not_started'], p=[.45, .2, .2, .15]) if applicable else 'not_applicable'
    done = st == 'verified'
    units.append(t.TraceUnit('DEMO-001', 'build-41', row.req_id, applicable,
        'Applies to connected gateway' if applicable else ('Not an open-source steward' if row.req_id=='OSS-01' else ''),
        st, control_id=f'C-{row.req_id}' if st != 'not_started' else '', test_id=f'T-{row.req_id}' if done else '',
        evidence_uri=f'evidence/{row.req_id}.json' if done else '', evidence_sha256=('ab'*32) if done else '',
        evidence_generated_at=f'2026-10-{rng.integers(1,15):02d}T09:00:00Z' if done else '',
        owner='team' if st != 'not_started' else '', reviewer='sec-lead' if done or not applicable else '',
        reviewed_at='2026-10-15T10:00:00Z' if done else ''))
errs = t.validate_units([u.to_dict() for u in units]); print('schema errors:', errs[:3])
cov = t.coverage(units, set(cat.req_id)); {k: cov[k] for k in ('obligations','applicable','complete','coverage','unjustified_not_applicable')}"""),
(M, "The schema rejects a *not applicable* decision without justification (P1-m, REP-04 above) — this is the intended behaviour: an N/A without rationale is a finding."),
(C, """by_gate = (pd.DataFrame([{**u.to_dict(), 'gate': g} for u, g in zip(units, cat.gate)])
           .assign(complete=[u.is_complete() for u in units]).query('applicable')
           .groupby('gate').complete.mean())
fig, ax = plt.subplots(figsize=(5.5, 2.4))
ax.barh(by_gate.index, by_gate.values, color=plotting.SERIES[0], height=0.5)
for i, v in enumerate(by_gate.values): ax.text(v + 0.01, i, f'{v:.0%}', va='center', fontsize=9, color=plotting.INK2)
ax.set_xlim(0, 1); ax.set_xlabel('Complete, reviewed traces'); ax.set_title('Traceability coverage by gate'); plt.show()"""),
(M, "## 2 · Lifecycle events"),
(C, """# Event 1: dependency bump on 2026-10-16 -> evidence generated before it is stale
affected = {'P2-1', 'P2-2', 'P2-3', 'SC-01', 'P1-a'}   # evidence a dependency bump invalidates
fr = t.freshness(units, '2026-10-16T00:00:00Z', affected); print('stale among affected:', fr['stale'], '| stale share:', round(fr['stale_share'], 2), '| median lag days:', round(fr['median_lag_days'], 1))
# Event 2: release gate for build-42 with an exploited CVE open
mandatory = set(cat.query("mandatory == 'Y' and gate == 'pre-market'").req_id)
gate = t.release_gate(units, mandatory, [{'id': 'CVE-2021-44906', 'known_exploited': True}], 'build-42')
print('release allowed:', gate['release_allowed'], '| blockers:', len(gate['blockers'])); gate['blockers'][:6]"""),
(C, """# Event 3: evidence tampering is detected by hash verification
import tempfile, pathlib as pl
tmp = pl.Path(tempfile.mkdtemp()); (tmp/'evidence').mkdir()
f = tmp/'evidence'/'P2-1.json'; f.write_text('{"sbom": "v1"}')
u = copy.deepcopy(units[0]); u.requirement_id='P2-1'; u.evidence_uri='evidence/P2-1.json'; u.evidence_sha256=t.sha256_file(f)
print('before:', t.verify_hashes([u], tmp)); f.write_text('{"sbom": "edited"}'); print('after edit:', t.verify_hashes([u], tmp))"""),
(M, """## 3 · E4 experiment design (to run on pilot repositories)
Inject scripted change events into a forked pilot repo (dependency bump, new CVE published against a component, config change, support-period change) and measure **detection latency** (event → evidence marked stale), **re-evidencing effort** and **gate decisions** with and without the CRA-SME pipeline. Metrics map 1:1 to concept note §8 (*evidence freshness*, *requirements traceability*, *false assurance*)."""),
])

# ---------------------------------------------------------------- 05
nb("05_article14_tabletop_E5.ipynb", [
(M, """# 05 · Article 14 reporting: deadline engine, tabletop scoring and staffing simulation (E5)
**Supports:** RQ1, concept note §8 *reporting preparedness*. The 24 h / 72 h / final-report clocks follow Art. 14(2) and 14(4); "without undue delay" is stricter than the outer limit and is **not** modelled. Planning aid, not legal advice."""),
(C, SETUP + "\nfrom datetime import datetime, timedelta, timezone\nfrom crasme.reporting import *"),
(M, "## 1 · Inject set (facilitator answer key reviewed by a legal specialist before use)"),
(C, """T0 = datetime(2026, 11, 6, 16, 40, tzinfo=timezone.utc)   # Friday afternoon on purpose
injects = [
  Inject('I1', 'Customer forwards logs showing exploitation of auth bypass in gateway fw 2.3', True, EventType.EXPLOITED_VULNERABILITY, T0, T0+timedelta(days=4)),
  Inject('I2', 'Researcher reports XSS with PoC; no evidence of exploitation', False, None, T0+timedelta(hours=2)),
  Inject('I3', 'Update server compromised; malicious firmware signed and pushed to 3% of fleet', True, EventType.SEVERE_INCIDENT, T0+timedelta(hours=20)),
  Inject('I4', 'Upstream library maintainer publishes advisory; CISA KEV lists it as exploited; library used in product', True, EventType.EXPLOITED_VULNERABILITY, T0+timedelta(hours=30), T0+timedelta(days=9)),
  Inject('I5', 'Internal pentest finds hard-coded debug credential in unreleased build', False, None, T0+timedelta(hours=40)),
]
pd.DataFrame([{'id': i.inject_id, 'reportable (key)': i.reportable, 'type': i.event_type.value if i.event_type else '-', 'description': i.description} for i in injects])"""),
(M, "Note for I5: not a reportable event (product not made available), but it is a release blocker under Annex I Part I(2)(a). I4 also triggers Art. 13(6) (report to maintainer is moot — already public — but due diligence and user information apply)."),
(C, """resp = [
  TeamResponse('I1', True, T0+timedelta(hours=5), {'early_warning': T0+timedelta(hours=22), 'notification': T0+timedelta(hours=70), 'final_report': T0+timedelta(days=15)}, 9, 12),
  TeamResponse('I2', True, T0+timedelta(hours=3)),
  TeamResponse('I3', True, T0+timedelta(hours=26), {'early_warning': T0+timedelta(hours=47), 'notification': T0+timedelta(hours=95)}, 7, 12),
  TeamResponse('I4', True, T0+timedelta(hours=33), {'early_warning': T0+timedelta(hours=50), 'notification': T0+timedelta(hours=99), 'final_report': T0+timedelta(days=20)}, 10, 12),
  TeamResponse('I5', False, T0+timedelta(hours=41)),
]
score = score_tabletop(injects, resp)
print('decision accuracy', score['decision_accuracy'], '| stage timeliness', round(score['stage_timeliness'], 2))
pd.DataFrame(score['rows'])"""),
(C, """fig, ax = plt.subplots(figsize=(8, 2.8))
for k, inj in enumerate([i for i in injects if i.reportable]):
    r = next(x for x in resp if x.inject_id == inj.inject_id)
    clk = ReportingClock(inj.event_type, inj.released_at, inj.corrective_measure_at, r.submissions.get('notification'))
    for j, (stage, due) in enumerate(clk.deadlines().items()):
        if due is None: continue
        h = lambda d: (d - T0).total_seconds()/3600
        ax.plot([h(inj.released_at), h(due)], [k + j*0.22]*2, color=plotting.SERIES[j], lw=2, label=stage if k == 0 else None)
        if stage in r.submissions:
            sub = h(r.submissions[stage]); late = r.submissions[stage] > due
            ax.plot(sub, k + j*0.22, 'X' if late else 'o', color=plotting.INK if late else plotting.SERIES[j], markersize=8, markeredgecolor=plotting.SURFACE)
ax.set_yticks([0.22, 1.22, 2.22], ['I1', 'I3', 'I4']); ax.set_xlabel('Days from first inject (line = window, ● on time, ✕ late)')
ax.set_xlim(0, 24*22); ax.set_xticks(range(0, 24*22+1, 48), [f'd{d}' for d in range(0, 23, 2)]); ax.legend(loc='lower right', fontsize=8); ax.set_title('Reporting windows vs simulated team submissions'); plt.show()"""),
(M, "## 2 · Staffing simulation: probability of missing the 24 h early warning\nAssumptions (replace with pilot measurements): awareness time uniform over the week; triage starts at next working hour (no on-call) or within ~1 h (on-call); triage + drafting ~ lognormal with median 4 h."),
(C, """rng = np.random.default_rng(11)
def miss_rate(on_call, n=20000):
    start = rng.uniform(0, 7*24, n)                      # hour of week, Mon 00:00 = 0
    def next_working(h):
        day, hr = int(h // 24), h % 24
        if on_call: return h + rng.exponential(1.0)
        while True:
            if day % 7 < 5 and 8 <= hr < 17: return day*24 + hr
            if day % 7 < 5 and hr < 8: return day*24 + 8
            day, hr = day + 1, 0.0
    begin = np.array([next_working(h) for h in start])
    work = rng.lognormal(np.log(4), 0.6, n)
    return float(((begin - start + work) > 24).mean())
res = pd.DataFrame({'model': ['office hours only', 'on-call rota'], 'P(miss 24 h)': [miss_rate(False), miss_rate(True)]}); res"""),
(M, "**Use in the paper:** compare simulated miss-rates with observed tabletop timeliness per SME; the staffing variable is a candidate explanatory factor for RQ5."),
])

# ---------------------------------------------------------------- 06
nb("06_pilot_evaluation_analysis.ipynb", [
(M, """# 06 · SME pilot evaluation analysis plan (Phase 4) — on a SYNTHETIC dataset
**Supports:** RQ2, RQ4, RQ5; concept note §8 metrics. The dataset is generated here so the full analysis can be pre-registered and tested before any pilot data exists. Replace with `experiments/data-templates/pilot_metrics.csv`.
Principles from the concept note: effect sizes with CIs, case-wise reporting, no causal claim from before/after alone."""),
(C, SETUP + "\nfrom crasme import stats as s"),
(C, """rng = np.random.default_rng(2026)
n = 8
smes = pd.DataFrame({'sme': [f'SME{i+1}' for i in range(n)],
                     'product_type': rng.choice(['software', 'iot', 'embedded'], n),
                     'ci_maturity': rng.integers(1, 5, n)})
smes['trace_before'] = rng.uniform(0.1, 0.45, n)
smes['trace_after'] = np.clip(smes.trace_before + rng.normal(0.3, 0.12, n), 0, 1)
smes['remed_days_before'] = rng.lognormal(np.log(30), 0.5, n)
smes['remed_days_after'] = smes.remed_days_before * rng.lognormal(np.log(0.75), 0.35, n)
smes['hours_per_release_before'] = rng.uniform(10, 40, n)
smes['hours_per_release_after'] = smes.hours_per_release_before * rng.lognormal(np.log(0.85), 0.3, n)
smes.round(2)"""),
(C, """out = {}
for m, better in [('trace', 'higher'), ('remed_days', 'lower'), ('hours_per_release', 'lower')]:
    r = s.paired_summary(smes[f'{m}_before'], smes[f'{m}_after'], better=better)
    out[m] = {**r, 'better_if': better}
pd.DataFrame(out).T[['n', 'median_diff', 'median_diff_ci95', 'hedges_gz', 'wilcoxon_p', 'improved_cases', 'worse_cases', 'better_if']]"""),
(C, """fig, axes = plt.subplots(1, 3, figsize=(11, 3.4))
for ax, (m, lbl) in zip(axes, [('trace', 'Traceability coverage'), ('remed_days', 'Median remediation days'), ('hours_per_release', 'Staff hours / release')]):
    for i, row in smes.iterrows():
        ax.plot([0, 1], [row[f'{m}_before'], row[f'{m}_after']], color=plotting.GRID, lw=1.5)
    ax.plot(np.zeros(n), smes[f'{m}_before'], 'o', color=plotting.SERIES[1], label='baseline', markeredgecolor=plotting.SURFACE)
    ax.plot(np.ones(n), smes[f'{m}_after'], 'o', color=plotting.SERIES[0], label='post-pilot', markeredgecolor=plotting.SURFACE)
    ax.set_xticks([0, 1], ['baseline', 'post']); ax.set_title(lbl); ax.set_xlim(-0.3, 1.3)
axes[0].legend(fontsize=8); plt.suptitle('Case-wise change (synthetic data)', y=1.02); plt.tight_layout(); plt.show()"""),
(M, "## Stratification (RQ5) — descriptive only with n ≈ 8"),
(C, """smes['trace_gain'] = smes.trace_after - smes.trace_before
smes.groupby('product_type').agg(n=('sme', 'count'), median_gain=('trace_gain', 'median'), min_gain=('trace_gain', 'min'), max_gain=('trace_gain', 'max'))"""),
(M, "## Power for a paired Wilcoxon test at the planned sample sizes\nWith 6–10 SMEs only large effects are detectable; this justifies the concept note's emphasis on effect sizes and qualitative evidence."),
(C, """pw = pd.DataFrame([{'n_sme': k, 'dz': dz, 'power': s.power_paired_wilcoxon(k, dz, n_sim=1500)} for k in (6, 8, 10) for dz in (0.5, 0.8, 1.2)])
pw.pivot(index='n_sme', columns='dz', values='power')"""),
(M, "## Staggered roll-out (if recruitment allows)\nThree waves start the intervention in different months; a two-way fixed-effects estimate is shown with its known caveat."),
(C, """rows = []
start = dict(zip(smes.sme, rng.choice([2, 3, 4], n)))
for sme, st in start.items():
    base = rng.uniform(0.15, 0.4)
    for p in range(1, 6):
        tr = int(p >= st)
        rows.append({'sme': sme, 'period': p, 'treated': tr, 'trace': base + 0.02*p + 0.25*tr + rng.normal(0, 0.04)})
panel = pd.DataFrame(rows); s.staggered_did(panel, 'trace')"""),
])

# ---------------------------------------------------------------- 07
nb("07_release_gate_mutation_E4_E7.ipynb", [
(M, """# 07 · Release-decision engine: seeded-fault evaluation (E4/E7, v1.2)
**Supports:** RQ4 (false assurance), recommendations P0-01, P0-02 and P0-04. Each of 69 synthetic faults is planted, one at a time, into a valid **synthetic** bundle. Every faulty bundle is then evaluated by the v1.2 engine (`crasme.gate`) and by the legacy v1.1 CI gate.
*This verifies engine logic against anticipated faults. It does not estimate real-world fault prevalence.*"""),
(C, SETUP + "\nfrom crasme.mutation import run_suite\nres = run_suite()\npd.Series(res['summary'])"),
(C, """df = pd.DataFrame(res['rows'])
tab = df.groupby('category').agg(n=('mutation','count'), v12_false_green=('false_green','sum'),
                                 v11_false_green=('legacy_v11_false_green','sum'), v12_code_ok=('code_reported','sum'))
tab"""),
(C, """fig, ax = plt.subplots(figsize=(7, 3.2))
y = np.arange(len(tab))
ax.barh(y + 0.18, tab.v11_false_green / tab.n, height=0.34, color=plotting.SERIES[1], label='legacy v1.1 gate')
ax.barh(y - 0.18, tab.v12_false_green / tab.n, height=0.34, color=plotting.SERIES[0], label='v1.2 engine')
for i, (a, b, n) in enumerate(zip(tab.v12_false_green, tab.v11_false_green, tab.n)):
    ax.text(b / n + 0.01, i + 0.18, f'{b}/{n}', va='center', fontsize=8, color=plotting.INK2)
    ax.text(a / n + 0.01, i - 0.18, f'{a}/{n}', va='center', fontsize=8, color=plotting.INK2)
ax.set_yticks(y, tab.index); ax.set_xlim(0, 1.15); ax.set_xlabel('False-green rate (PASS despite planted blocker)')
ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.22), ncol=2, fontsize=8); ax.set_title('Planted faults that would have been released'); plt.show()"""),
(C, """df[['mutation','category','description','decision','expected_code','legacy_v11_decision']]"""),
(M, """**Provenance of the faults.** M01–M37 were written by the authors. M38–M45 came from their own follow-up review. M46–M69 came from an independent adversarial review, which found 30 false-PASS inputs in the first v1.2 draft; all have since been fixed.

**Reading.** v1.1 blocked only on KEV hits and treated missing or empty inputs as clean. As a result, 63 of 69 planted blockers would have passed, including every stale-evidence case. v1.2 detects all 69 faults, with the expected FAIL/REVIEW split and reason code in each case.

**Next (pilot E4):**
- apply the same mutation operators to forks of pilot repositories
- measure reviewer time per evidence package
- add faults the authors did *not* anticipate, contributed by external reviewers"""),
])

print("notebooks written")
