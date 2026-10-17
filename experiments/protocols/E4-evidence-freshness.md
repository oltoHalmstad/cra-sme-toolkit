# E4 — Evidence freshness and traceability under injected lifecycle events
**RQ1, RQ4 · O3** · Code `crasme.traceability`, `schemas/trace_unit.schema.json` · Notebook 04

## Hypotheses
- **H4a:** With the CRA-SME pipeline, the median latency from a change event to evidence being flagged stale is under one CI run. Without it, evidence is flagged at the next manual review.
- **H4b:** Traceability coverage, measured by an independent audit, is higher with the pipeline. The audit counts the share of applicable obligations that have a reviewed control, test, hashed evidence and an owner.
- **H4c:** The release gate makes no false "allowed" decisions on the scripted blocker events.

## Event script (applied to a fork of each pilot repository, or to the demo product)
| # | Event | Expected effect |
|---|---|---|
| 1 | Bump a direct dependency | P2-1, SC-01 and P1-a evidence becomes stale; SBOM regenerated |
| 2 | Publish a new CVE against a transitive component (simulated feed) | New triage item; P2-2 is opened |
| 3 | Component enters KEV (simulated feed) | Gate blocks; Art. 14 candidate is flagged for the human decision |
| 4 | Change the default configuration (e.g. open debug port) | P1-b and P1-j evidence becomes stale |
| 5 | Shorten the support period in the product register | SUP-01 is re-review required |
| 6 | Tamper with a stored evidence file | Hash verification fails |
| 7 | Mark an obligation N/A without a justification | Schema rejects it; coverage lists the gap |

## Measures
- Detection latency (event commit → stale flag)
- Re-evidencing effort (minutes)
- Coverage before and after
- Gate confusion matrix against the scripted ground truth

## Comparison condition
The same events run with the v1.0 workflow and the spreadsheet only.
