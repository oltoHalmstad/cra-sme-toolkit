# EU Cyber Resilience Act — Practical Implementation

## Question

What does practical implementation of the EU Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) look like for manufacturers and other economic operators today, and what should companies do now?

## Executive Summary

1. **The CRA is in its phased implementation phase.** It entered into force on 10 December 2024; vulnerability/incident reporting obligations have applied since 11 September 2026; and the bulk of obligations (essential requirements, conformity assessment, CE marking) apply from 11 December 2027.
2. **Reporting is already live.** Since 11 September 2026, manufacturers must report actively exploited vulnerabilities and severe incidents via ENISA's Single Reporting Platform (SRP), on a 24-hour early warning / 72-hour notification / final-report rhythm (final report within 14 days of a fix for vulnerabilities, within a month of the 72-hour notification for incidents).
3. **The Commission's first official application guidance landed 27 July 2026** (Communication C(2026) 5252, with a detailed annex of 67 practical examples, use cases and flowcharts). It clarifies scope, free and open-source software, substantial modification, support periods and reporting, and is aimed especially at SMEs.
4. **Harmonised standards are still in the pipeline.** Standardisation request M/606 covers ~41 standards (15 horizontal, rest vertical). The two core horizontal standards (secure development, vulnerability handling) were pushed to 31 October 2026; vertical product standards to 31 December 2026; the rest to 30 October 2027. None are yet cited in the Official Journal, so presumption of conformity is not yet available.
5. **Penalties are significant:** up to €15 million or 2.5% of total worldwide annual turnover (whichever is higher) for breaches of essential requirements or core manufacturer obligations.
6. **The Act applies to non-EU manufacturers selling into the EU** and requires an EU-based responsible economic operator; remote data-processing necessary to a product's function is treated as part of the product.
7. **The practical takeaway across sources:** companies that map their products, build secure-by-design processes, organise documentation and set up vulnerability handling now will be well positioned; those waiting for 2027 risk a costly scramble — especially since reporting duties already apply to products on the market today.

## Methodology

Searches targeted: (1) the official Commission CRA pages and reporting-obligations page, (2) implementation timelines and state-of-play trackers, (3) the July 2026 Commission guidance and legal analyses of it, (4) standards and ENISA infrastructure. Primary/official sources (European Commission, ENISA) were prioritised, cross-checked against law-firm and tracker analyses. Limitation: the harmonised standards and Commission FAQ are living documents; deadlines cited reflect status as of October 2026 and may shift.

## Findings

### 1. Scope and who is affected

- The CRA (Regulation (EU) 2024/2847) is the first EU-wide law setting mandatory cybersecurity requirements for products with digital elements — hardware and software — across their entire lifecycle.
- It applies regardless of where the manufacturer is established; non-EU sellers into the Union must ensure an EU economic operator carries the relevant obligations. Remote data-processing solutions necessary for the product's functions are covered as part of the product.
- If a product contains software or firmware and is made available on the EU market with a direct or indirect data connection, it is very likely in scope.
- Products are classified into classes: "important" products may use harmonised standards or a notified body; "critical" products require third-party certification; default products may self-assess (Module A) with an EU declaration of conformity and CE marking.

### 2. Implementation timeline (staged, not a single compliance date)

| Date | Milestone |
|---|---|
| 10–11 Dec 2024 | Entry into force |
| 11 June 2026 | Chapter IV applies — conformity-assessment bodies can be notified |
| 11 Sep 2026 | **Reporting obligations apply** (Art. 14); ENISA Single Reporting Platform operational |
| 31 Oct 2026 | Core horizontal standards due (secure development, vulnerability handling) |
| 31 Dec 2026 | Vertical product standards due |
| 30 Oct 2027 | Remaining horizontal standards due (~1 year before full application) |
| 11 Dec 2027 | **Full application**: essential requirements, conformity assessment, CE marking; open-source steward reporting duties (Art. 24(3)) |

Note: the Commission's July 2026 draft amendment to M/606 pushed standards deadlines back two months from earlier dates; earlier secondary sources citing "30 August 2026" for horizontal type-A standards reflect the pre-amendment schedule.

### 3. Reporting obligations in practice (already binding)

- Reportable events: actively exploited vulnerabilities and severe incidents affecting the security of products with digital elements, including products already placed on the market before December 2027 (Art. 69(3)).
- Rhythm: early warning within 24 hours of awareness; fuller notification within 72 hours; final report within 14 days after a corrective measure is available (vulnerabilities) or within a month of the 72-hour notification (severe incidents). The reporting clock starts when the manufacturer becomes aware of the vulnerability or incident.
- Channel: one notification via ENISA's CRA Single Reporting Platform (SRP, live at portal.cra-srp.enisa.europa.eu), routed to the CSIRT of the manufacturer's main establishment and simultaneously to ENISA; the coordinating CSIRT disseminates to other affected Member States' CSIRTs.
- Manufacturers must also inform impacted users, and where appropriate all users (Art. 14(8)).
- A December 2025 delegated act specifies exceptional circumstances in which a CSIRT may withhold/delay dissemination on cybersecurity grounds.

### 4. The Commission's 2026 application guidance (C(2026) 5252)

- Published 27 July 2026 as a Communication plus detailed annex; required by Article 26; developed via the Commission's expert group on cybersecurity of products with digital elements and a public consultation in 2026.
- Covers the CRA's hardest concepts: product scope, free and open-source software (FOSS) treatment, substantial modification, support periods, and vulnerability reporting. Contains 67 practical examples, use cases, flowcharts and diagrams, with micro-enterprises and SMEs named as the priority audience.
- Non-binding (authoritative interpretation rests with the CJEU), but market surveillance authorities and notified bodies look to it for a harmonised reading.
- Following stakeholder pressure (e.g., a cybersecurity coalition), the final guidance broadened the FOSS definition's flexibility and allows flexible vulnerability-reporting methods, including established coordinated disclosure processes.
- Key practical point from legal analyses: the cybersecurity risk assessment under Art. 13(2) must drive which Annex I essential requirements apply — it is a product-security design tool, not a separate corporate exercise. Products designed before full application but placed on the market after it must still comply.
- A living FAQ on CRA implementation (first published 3 December 2025, updated 2 July 2026) supplements the guidance.

### 5. Standards and conformity

- Annex I essential requirements are outcome-based; once a harmonised standard is cited in the Official Journal, following it gives presumption of conformity.
- Standardisation request M/606 (accepted by CEN, CENELEC, ETSI in 2025) covers ~41 standards; as of late 2026, 17 ETSI vertical drafts are under public enquiry and no horizontal standards are yet OJ-cited.
- Some products of particular cybersecurity relevance require third-party assessment by a notified body before being placed on the EU market.
- ENISA and the Joint Research Centre have published a CRA requirements–standards mapping to help organisations plan compliance against candidate standards.

### 6. Support for SMEs and open-source stewards

- ENISA published an SME Cyber Resilience Maturity Assessment Model (13 July 2026) usable by manufacturers, integrators and service providers to assess product-security practices.
- The CRA takes a special approach to free and open-source software given its central role; open-source stewards face reporting and other duties from 11 December 2027, and the Open Regulatory Compliance Working Group maintains implementation resources for open-source projects.

### 7. Enforcement and penalties

- Breach of essential requirements or core manufacturer obligations: fines up to €15 million or 2.5% of total worldwide annual turnover, whichever is higher; lower ceilings apply to other infringements and to supplying incorrect information.
- Member States play an essential role via market surveillance authorities; Germany's BSI, for example, publishes its own CRA implementation guidance for manufacturers.

### 8. What practical preparation looks like (consensus across sources)

1. Map the product portfolio and determine which products are in scope and in which class.
2. Run/document the Art. 13(2) cybersecurity risk assessment to drive which Annex I requirements apply.
3. Establish secure-by-design development processes and vulnerability handling across the lifecycle, including for products designed before December 2027 but sold after.
4. Define and publish support periods; assess whether planned changes count as "substantial modification" (re-triggering obligations).
5. Stand up Art. 14 reporting capability: monitoring/awareness processes, the 24h/72h/14-day workflow, SRP account, and user-notification procedures.
6. Secure contractual visibility into third-party/supply-chain information (SBOMs, coordinated disclosure channels).
7. Track harmonised standards as they are cited in the OJ, and ENISA/Commission FAQ updates.

## Source Notes

| Source | Credibility | Last updated |
|---|---|---|
| [European Commission — Cyber Resilience Act (official policy page)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) | 5/5 | 2026 |
| [European Commission — CRA Reporting obligations](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 5/5 | 2026 |
| [European Commission — Guidance publication announcement (C(2026) 5252)](https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation) | 5/5 | 27 Jul 2026 |
| [ENISA — CRA Single Reporting Platform launch](https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched) | 5/5 | Sep 2026 |
| [ENISA/JRC — CRA Requirements Standards Mapping](https://www.enisa.europa.eu/publications/cyber-resilience-act-requirements-standards-mapping) | 5/5 | - |
| [cyberresilienceact.eu — CRA Explained: scope, classes & deadlines](https://www.cyberresilienceact.eu/explained.html) | 4/5 | 2026 |
| [cyberresilienceact.eu — State of Play & Timeline 2026](https://www.cyberresilienceact.eu/state-of-play.html) | 4/5 | 2026 |
| [cyberresilienceact.eu — Commission Guidance overview](https://www.cyberresilienceact.eu/commission-guidance.html) | 4/5 | Jul 2026 |
| [ORCWG — CRA implementation resources for open source](https://orcwg.org/cra/) | 4/5 | 2026 |
| [Kennedys — What the Commission's 2026 guidance means for manufacturers](https://www.kennedyslaw.com/en/thought-leadership/article/2026/eu-cyber-resilience-act-what-the-european-commission-s-2026-guidance-means-for-manufacturers/) | 4/5 | 2026 |
| [Center for Cybersecurity Policy — Final CRA implementation guidance analysis](https://www.centerforcybersecuritypolicy.org/insights-and-research/european-commission-publishes-final-cyber-resilience-act-implementation-guidance-addresses-concerns-raised-by-cybersecurity-coalition) | 3/5 | Jul/Aug 2026 |
| [HLC — Reporting obligations now apply; SRP live](https://www.hlc.com/en/publications/eu-cyber-resilience-act-vulnerability-and-incident-reporting-obligations-now-apply) | 4/5 | Sep 2026 |
| [BSI (Germany) — Cyber Resilience Act guidance](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Cyber_Resilience_Act/cyber_resilience_act_node.html) | 5/5 | 2026 |
| [Lawgent (SE) — What companies need to know](https://lawgent.se/eu-cyber-resilience-act-what-companies-need-to-know/) | 3/5 | 2026 |
| [Teldat — CRA timeline 2024–2027](https://www.teldat.com/glossary/cyber-resilience-act-timeline-2024-2027-key-dates/) | 3/5 | 2026 |
| [GMA Labs — CRA Implementation Guidance summary](https://www.gmalabs.com/post/european-union-cyber-resilience-act-implementation-guidance) | 3/5 | 2026 |

**Conflicts and caveats:** Sources disagree marginally on entry-into-force date (10 vs 11 December 2024 — the regulation entered into force 10 December 2024 and became applicable the day after). Standards deadlines shifted by two months in July 2026; older sources citing "30 August 2026" are superseded. Guidance is non-binding; only the CJEU can authoritatively interpret the regulation.

## Open Questions

- Exactly which harmonised standards will be cited in the Official Journal, and when — until then, no presumption of conformity is available.
- How national market surveillance authorities will actually enforce Art. 14 reporting in practice (first precedents not yet visible).
- Treatment of remaining edge cases in FOSS stewardship and "substantial modification" beyond the 2026 guidance examples.
- Whether the December 2027 full-application date will be accompanied by further Commission simplification measures under its implementation agenda.

## Recommendations / Next Steps

1. **Treat reporting as now-binding**: verify your product portfolio is in scope, and confirm awareness-monitoring and the 24h/72h/final-report workflow, including SRP registration.
2. **Read the Commission guidance (C(2026) 5252 annex) and FAQ** — especially the scope, FOSS, substantial-modification and support-period sections — as the working reference for compliance programmes.
3. **Run the Art. 13(2) risk assessment per product** and use it to drive Annex I implementation and documentation.
4. **Track OJ citations of the harmonised standards** (expected from late 2026 through October 2027) and gap-check your development and vulnerability-handling processes against the two core horizontal standards.
5. **Use ENISA's SME maturity model** for a structured self-assessment if you are a smaller manufacturer.
6. **Review supplier contracts** for SBOM, vulnerability-disclosure and support-period commitments, since lifecycle obligations depend on third-party facts.