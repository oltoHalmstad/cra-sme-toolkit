# Article 14 reporting record — template (one per event)
> Distinguish **(A) actively exploited vulnerability** (Art. 14(1)-(2)) from **(B) severe incident having an impact on the security of the product** (Art. 14(3)-(4)). Not every vulnerability or incident is reportable. Verify current official instructions (ENISA Single Reporting Platform) before use.

## 1. Awareness
- Event ID · product(s)/version(s) affected:
- **Awareness timestamp (UTC)** and what information triggered awareness (source, evidence):
- Person recording / triage owner:
## 2. Reportability determination
- Category: A / B / neither / undetermined
- Rationale (exploitation evidence, impact on product security, severity criteria considered):
- Reviewer(s) and time of decision:
- If not reportable: re-assessment trigger and date:
## 3. Deadlines (computed with `crasme.reporting.ReportingClock`)
| Stage | Outer limit | Submitted (UTC) | SRP receipt / reference | Submitted by |
|---|---|---|---|---|
| Early warning | awareness + 24 h | | | |
| Notification | awareness + 72 h | | | |
| Final report | A: 14 days after corrective/mitigating measure available · B: one month after notification | | | |
"Without undue delay" applies within these outer limits.
## 4. Required content prepared (SRP field groups — check current glossary)
- [ ] Early warning: type, title, summary, Member States where available, product name, version (+ A: awareness time; B: suspected malicious act, detection time)
- [ ] Notification: general information / nature of incident, exploitation or occurrence time, initial assessment, mitigation
- [ ] Final report: fix/update details, severity, impact, root cause (B), corrective measures, user measures
## 5. Users and upstream
- [ ] Impacted users (and where appropriate all users) informed — Art. 14(8): date, channel, content
- [ ] Vulnerability in integrated component reported to its maintainer — Art. 13(6): date, contact
- [ ] CVD coordination with reporter; public advisory after fix (Annex I Part II(4))
## 6. Escalation and follow-up log
| Time (UTC) | Action | By | Notes |
|---|---|---|---|
