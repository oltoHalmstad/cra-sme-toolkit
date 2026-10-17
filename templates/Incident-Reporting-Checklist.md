# CRA Article 14 reporting and escalation checklist
**Awareness** = the point at which the manufacturer has information giving reasonable grounds to conclude a reportable event occurred; record what that information was. Do not wait for forensic certainty.

**Activate on suspected actively exploited vulnerability OR severe product-security incident; determine statutory thresholds, not just severity labels.**
- [ ] Record first awareness instant (UTC), source, triage owner, affected product/version and evidence.
- [ ] Assess whether vulnerability is actively exploited, or incident meets CRA severe incident threshold. Record grounds and reviewer.
- [ ] If reportable, use ENISA CRA Single Reporting Platform and retain receipt. Notify without undue delay, no later than 24 h after becoming aware.
- [ ] Update notification without undue delay, no later than 72 h after awareness.
- [ ] For actively exploited vulnerability: final report no later than 14 days after corrective/mitigating measure available.
- [ ] For severe incident: final report within one month from 72-hour incident notification.
- [ ] Inform impacted users, and where appropriate all users, about the vulnerability/incident and mitigations (Art. 14(8)); record date and channel.
- [ ] If the vulnerability is in an integrated component, report it to the component maintainer (Art. 13(6)).
- [ ] Keep users informed as required; coordinate mitigation, patch and advisory, preserving confidentiality and evidence.
- [ ] Record submission IDs, deadlines, changes in facts, approver, contacts and follow-up.
- [ ] If nonreportable, document decision and schedule reassessment when new evidence emerges.
**Source** https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
**Note:** Deadlines and reporting content depend on CRA Article 14; use official platform guidance. This is not a legal reporting form.

Full per-event record: `Article14-Reporting-Record.md`. SRP required fields: see `experiments/e5_tabletop/injects.yaml` (from ENISA SRP Glossary v1.5; re-check before use).
