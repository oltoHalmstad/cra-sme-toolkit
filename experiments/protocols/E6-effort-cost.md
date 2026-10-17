# E6 — Effort and cost (time-and-motion)
**RQ2** · Template `../data-templates/effort_timelog.csv` · Notebook 06

- **Unit of analysis:** product × release.
- **Baseline period:** 1–2 releases before training.
- **Post period:** 2–3 releases after training.
- Time is logged per task category from a fixed taxonomy: classification, threat modelling, risk register, SBOM, scanning and triage, remediation, documentation, reporting drill, review/sign-off, and tooling setup.

## Hypotheses
- **H6a:** Hours per release on repeated tasks (SBOM, triage, documentation update) fall after setup.
- **H6b:** One-off setup cost is recovered within 3 releases. This is reported as a break-even estimate with a CI, not as a test.

## Collection
- Participants log time weekly in 15-minute granularity, through a form or spreadsheet. Two random weeks are checked against the issue tracker and CI logs to estimate logging accuracy.
- Direct costs are recorded: tools, licences, external consultants and notified-body quotes.

## Analysis
- Paired median difference with a bootstrap CI for each task category.
- Case-wise plots.
- Stratification by product type and CI maturity.
- A staggered roll-out, if feasible.
- **Confounders:** release size (story points or changed LOC), team turnover, and concurrent certification work. Collect them, and adjust only if they are defensible at the sample size.
