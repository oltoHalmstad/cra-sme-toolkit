# Data-collection templates
Header-only CSVs (UTF-8, comma-separated, ISO-8601 UTC timestamps). Column names match the notebooks.

| File | Experiment | Notes |
|---|---|---|
| `e2_adjudication.csv` | E2 | `vex_status` ∈ affected, not_affected, fixed, under_investigation (OpenVEX vocabulary) |
| `e3_ratings.csv` | E3 | One row per rater × scenario × dimension. `condition` ∈ A, B, C. `range_low` and `range_high` are used only in condition C |
| `e5_tabletop_log.csv` | E5 | Facilitator log; timestamps on the simulated clock |
| `e7_seeds.csv` | E7 | Pre-filled seed key for DEMO-001; keep it hidden from the expert reviewers |
| `effort_timelog.csv` | E6 | `task_category` ∈ classification, threat_model, risk_register, sbom, scan_triage, remediation, documentation, reporting_drill, review_signoff, tooling_setup |
| `pilot_metrics.csv` | Phase 4 | One row per SME × product × period |
| `sus_responses.csv` | E8 | SUS items 1–5 on a Likert scale. Score = 2.5 × (Σ(odd − 1) + Σ(5 − even)) |

Pseudonymise people and products before files leave the SME. Keep the key in a separate, access-controlled file.
