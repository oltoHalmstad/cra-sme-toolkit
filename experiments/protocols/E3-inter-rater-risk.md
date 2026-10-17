# E3 — Blinded inter-rater study of risk prioritisation
**RQ3 · concept note §7** · Notebooks 01 and 02 · Template `../data-templates/e3_ratings.csv`

## Hypotheses (pre-register)
- **H3a:** Agreement under condition **B**, a structured template with explicit assumptions, an evidence link per rating and ranges, exceeds agreement under **A**, the v1.0 qualitative 1–5 sheet. The measure is Δα (ordinal) > 0, with the 95% bootstrap CI excluding 0.
- **H3b:** Condition **C**, a FAIR-style range estimate run through Monte Carlo, does not add agreement beyond **B** on the *ranking*. Its ICC(2,1) on log-ALE is moderate (0.5–0.75), following Koo & Li.
- **H3c:** Rankings in B and C are more stable than in A under the noise level measured in A (notebook 01 method).

## Materials
- **Scenario bank:** 36–48 product-risk scenarios from 3 product archetypes (web app, IoT gateway, PLC firmware). Each scenario has an architecture sketch, the attack path and the available evidence (CVSS, EPSS, KEV, exposure). The bank is written and piloted by 2 authors, and an independent expert sets the reference ranking.
- **Rating packs** for conditions A, B and C.
- **Calibration exercise for C:** 10 trivia-style interval questions, after Hubbard & Seiersen.

## Design
- **Participants and allocation:** within-subject; 9 or more raters (SME engineers pooled across pilots, plus students as a secondary sample, following Allodi et al. 2020).
- **Counterbalancing:** each rater sees each scenario in only one condition, using a Latin-square allocation.
- **Order:** condition order is randomised and a washout task is used.
- **Power:** notebook 02 shows that 24 scenarios × 6 raters is under-powered for Δα ≈ 0.2. Plan for 48 scenarios × 9 raters, or pool across waves.

## Measures
- Krippendorff α (ordinal) per dimension and on the composite rank
- ICC(2,1) for continuous estimates
- Quadratic-weighted κ against the reference ranking
- Kendall τ against the reference ranking
- Time per scenario
- Justification completeness (rubric 0–3)
- Confidence

## Analysis
Report α and ICC with percentile bootstrap CIs, resampling scenarios. Use a mixed model of absolute deviation from the reference with random effects for rater and scenario. Run sensitivity analyses that exclude low-calibration raters.

## Threats
- Learning effects, mitigated by the Latin square.
- Reference-ranking bias, mitigated by having an expert panel set it.
- Scenario realism, mitigated by deriving scenarios from anonymised pilot risk registers.
