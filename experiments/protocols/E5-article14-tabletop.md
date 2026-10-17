# E5 — Article 14 reporting tabletop exercise
**RQ1, RQ5 · metric "reporting preparedness"** · Code `crasme.reporting` · Notebook 05 · Injects `../e5_tabletop/injects.yaml`

Design follows NIST SP 800-84 (tabletop exercises). Outcome data are collected systematically, which addresses a gap noted by Vykopal et al. 2024.

## Participants and roles (per SME)
The product owner, the vulnerability-response lead, the person authorised to submit SRP reports, and a manager. The facilitator and a legal observer are from the research team.

## Format
A 3-hour session, run on a simulated clock (1 real minute = 1 simulated hour, with pauses). Injects are released on a schedule. The team works with its own procedures in the baseline session and with the CRA-SME checklist and SRP field sheet in the follow-up session, using a different but equivalent inject set (parallel forms).

## Answer key
For each inject: reportable (Y/N), event type, awareness time, and the deadline for each stage. The key is reviewed by a legal specialist before use. Ambiguous injects are included **on purpose**, because they test the awareness-decision record.

## Measures
- Reportability decision accuracy
- Decision latency
- Stage timeliness (24 h / 72 h / final), with margins
- Completeness of the draft SRP form against the required-field list (Glossary v1.5: EW requires notification type, title ≤255, summary ≤4000, Member States, product name and version; the vulnerability EW requires awareness time; the incident EW requires suspected malicious act and detection time)
- Art. 14(8) user-information draft present (Y/N)
- Upstream report under Art. 13(6) where relevant (Y/N)
- Self-efficacy questionnaire, before and after

## Staffing model
Notebook 05 simulates the probability of missing the 24 h window under office-hours staffing versus an on-call rota. Compare the simulated rate with the observed timeliness.

## Debrief
Use a structured hot-wash with three questions: what slowed you, what information was missing, and what you would change. Record it, code the transcript, and feed the results into RQ5.

## Safety
No real submission is ever made to the SRP. Use printed or offline forms only.
