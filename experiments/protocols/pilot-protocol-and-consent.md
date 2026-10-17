# SME pilot protocol, consent and data governance (rec. P2-04; v2.0 pilot gate)

## Design
- **Sample.** 6–10 SMEs, stratified by product type (software / IoT / embedded) and size (micro / small / medium). Each SME brings one product.
- **Phases:**
  1. Baseline, 1–2 releases: current practice; measure E6 effort, the E5 tabletop (set A) and the evidence-package review.
  2. Training (half a day).
  3. Assisted phase, 2–3 releases: CRA-SME workflow and decision engine.
  4. Follow-up: tabletop set B, E8 usability, interview.
- **Comparison.** Staggered start across SMEs where recruitment allows (notebook 06); otherwise the results are reported as observational.

## Outcomes (defined in the v1.2 recommendations §5)
| Outcome | Definition |
|---|---|
| Evidence completeness | Verified applicable obligation–evidence links ÷ applicable obligations (independent audit) |
| Evidence freshness recall | Stale links detected ÷ seeded stale links (mutation operators applied to a fork) |
| False-green rate | Incorrect PASS ÷ cases with planted blockers |
| Reviewer time | Minutes to check a standardised evidence package, baseline vs assisted |
| Scan availability | Successful required scans ÷ scheduled scans (from `scan-status.json`) |
| Reporting preparedness | Correct decisions and deadlines in tabletop sets A and B |
| SME effort | Setup hours, plus hours per release, plus maintenance hours per month |
| Usability | SUS score and task success (E8) |

## Ethics and consent
- **Ethics approval.** Obtain institutional ethics review, or a documented exemption, before recruitment.
- **Organisational agreement** with each SME, covering:
  - scope and duration
  - which systems may be scanned, with written authorisation and test environments only
  - confidentiality and publication review: the SME may check outputs for confidential information, but not suppress findings
  - handling of any vulnerability found, under the SME's own CVD process
  - data retention and deletion
- **Individual consent** from every participant, covering:
  - the purpose of the study
  - voluntariness and the right to withdraw
  - recording of interviews
  - pseudonymisation
  - what is published (aggregate and anonymised results only)
  - a contact person

  Keep signed forms separate from the research data.
- **Data protection.** Run a DPIA screening if personal data beyond participant contact details is processed. Store data in an access-controlled location within the EU. Pseudonymisation keys are held only by the PI.
- **Evidence data.** Follow `docs/evidence-data-governance.md`. Run `tools/redact_check.py` before anything leaves the SME.

## Limitations to report
- Small *n* and self-selection bias, since motivated SMEs volunteer.
- Learning effects between phases.
- Researcher involvement acting as an intervention in itself.
- Product-specific legal applicability: the study does not establish conformity.
- Synthetic versus real data must be kept separate throughout the analysis.
