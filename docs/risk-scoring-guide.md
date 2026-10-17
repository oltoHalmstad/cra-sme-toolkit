# Risk scoring guide: anchored ratings with uncertainty (v1.2, recommendation P1-01)

The ordinal score `L × I × E` (1–125) is kept as a **prioritisation and teaching baseline only**.

- It is **not a probability**. Multiplying ordinal ranks produces only 30 distinct values (notebook 01).
- It is **not a CRA metric**, and it **never** waives an obligation: release blockers come from the decision engine (`crasme.gate`), which does not read risk scores.
- **Financial estimates** (ALE, Monte Carlo) are a separate, optional analysis. Use them only where frequency and loss ranges can be defended, and label them *illustrative* when they rest on assumptions.

## How to rate
For every dimension, record **low / central / high** ratings, the **evidence** used, and a one-line **justification**. If you cannot cite evidence for a rating, use a wide range rather than a confident point. `crasme.risk.RatingRange` enforces `low ≤ central ≤ high`, and `score_range()` gives the inherent-score range.

### Likelihood of exploitation (L) over the support period
| Level | Anchor | Credible evidence |
|---|---|---|
| 1 Rare | No known technique; strong preconditions such as physical access plus insider knowledge | Design review; no public research |
| 2 Unlikely | Technique known in principle; no public exploit; non-default configuration needed | CVE without exploit; EPSS < 1% |
| 3 Possible | Public PoC, or a weakness class commonly exploited in comparable products | PoC published; EPSS 1–10%; similar incidents in the sector |
| 4 Likely | Exploit tooling available; reachable in default configuration | Metasploit/nuclei module; EPSS 10–50%; reachability confirmed |
| 5 Almost certain | Actively exploited in the wild against this component or product class | **KEV listing**, vendor or CSIRT exploitation reports → also triggers an Art. 14 assessment |

### Impact on users, safety and operations (I)
| Level | Anchor |
|---|---|
| 1 Negligible | No user data or functions affected; cosmetic |
| 2 Minor | Limited degradation; no personal data; easy recovery |
| 3 Moderate | Loss of a non-essential function, or limited exposure of non-sensitive data; recovery within days |
| 4 Major | Loss of essential functions (Annex I Part I(2)(h)); personal or sensitive data exposed; impact on other devices or networks ((2)(i)) |
| 5 Severe | Safety impact, fleet-wide compromise (e.g. malicious update), or large-scale sensitive data exposure; potential severe incident under Art. 14(3) |

### Exposure (E)
| Level | Anchor |
|---|---|
| 1 | Isolated, with no network interface in intended use |
| 2 | Local or physical interface only, behind authentication |
| 3 | LAN or adjacent network, authenticated |
| 4 | LAN unauthenticated, or internet-facing behind authentication |
| 5 | Internet-facing and reachable without authentication, or through the update or cloud channel |

## Separate dimensions to record (not multiplied)
Record each of these as its own field rather than folding it into the score:
- exploitation evidence (KEV, EPSS, CVSS vector)
- vulnerability maturity
- existing mitigations, each with its *evidence ID*
- consequence type (user, safety, operations, data)
- uncertainty width

In the workbook (v1.2), these are columns W–AH of the Risk Register; the anchors are in the *Scoring anchors* sheet.

## Calibration and agreement
- Calibrate raters on 10 worked examples (planned for v1.3, from the E3 scenario bank) before the first live assessment.
- Measure agreement with Krippendorff's α and ICC (`crasme.agreement`), and ranking stability under ±1 noise (notebook 01).
- The research comparison is set out in protocol E3: the baseline ordinal model, versus the anchored model with ranges, versus the probabilistic (Monte Carlo) model. The outcomes are agreement, ranking stability, time per scenario and, where a reference exists, decision quality.
