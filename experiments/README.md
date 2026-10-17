# CRA-SME experiment programme (proposal v1.1)

Eight experiments operationalise RQ1–RQ5 and the §8 metrics of the concept note. E1, E2, E4 and E5 can begin in the lab before any SME is recruited. E3 and E6–E8 need participants.

| ID | Experiment | RQ | Type | Primary measure | Notebook | Status |
|---|---|---|---|---|---|---|
| E1 | SBOM generator accuracy against installed ground truth | RQ4 | Lab benchmark | Version-level precision/recall, BSI TR-03183-2 field conformance | 03 | **Pilot run done** (3 fixtures, 3 tools) |
| E2 | Vulnerability-scanner agreement and false assurance | RQ4 | Lab benchmark + expert adjudication | Pairwise Jaccard; adjudicated precision/recall; severity disagreement | 03 | Analysis code ready; outputs synthetic |
| E3 | Blinded inter-rater study: qualitative vs structured vs Monte Carlo risk assessment | RQ3 | Controlled within-subject experiment | Krippendorff α (ordinal), ICC(2,1), ranking stability | 01, 02 | Power simulation done |
| E4 | Evidence freshness and traceability under injected lifecycle events | RQ1, RQ4 | Lab, then pilot repos | Detection latency, coverage, stale share, gate correctness | 04 | Engine and tests ready |
| E5 | Article 14 reporting tabletop exercise | RQ1, RQ5 | Facilitated exercise per SME | Decision accuracy, stage timeliness, SRP field completeness | 05 | Inject set + scoring ready |
| E6 | Effort / cost time-and-motion study | RQ2 | Pilot, baseline vs post | Staff hours per product and per release; setup cost | 06 | Data template ready |
| E7 | Seeded-vulnerability false-assurance study | RQ4 | Lab, deliberately vulnerable targets | Share of seeded Annex I violations missed by automated pass | — | Protocol |
| E8 | Usability and adoption (SUS, interviews, UTAUT constructs) | RQ5 | Mixed methods | SUS, task success, coded themes | 06 | Instruments ready |

Common rules for every experiment:
- Pin tool versions and record provenance with `crasme.provenance`. Scan only assets you own or are authorised to test.
- Synthetic data is labelled as synthetic in file names and notebook headers. Never mix it into results.
- Register hypotheses and analysis decisions before data collection (`protocols/PREREGISTRATION-template.md`).
- Before/after comparisons are not causal evidence. Use staggered roll-out where recruitment allows (notebook 06).

## Materials index
- `protocols/E1…E8-*.md`: one protocol per experiment
- `protocols/PREREGISTRATION-template.md`
- `protocols/interview-guide.md`: baseline and follow-up interviews (E8, RQ5)
- `data-templates/*.csv`: collection sheets, with the column names the notebooks expect
- `e1_sbom_benchmark/`: runner, fixtures, ground truth and **real pilot results**
- `e2_scanner_agreement/synthetic/`: analysis fixtures (synthetic)
- `e5_tabletop/injects.yaml`: inject set with answer key and SRP fields
