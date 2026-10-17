# E2 — Vulnerability-scanner agreement and adjudicated accuracy
**RQ4 · Annex I Part I(2)(a), Part II(2)** · Code `crasme.vulns`, `crasme.gate` · Notebook 03

## Hypotheses
- **H2a:** Pairwise Jaccard between scanners on identical SBOMs is below 0.7, consistent with Imtiaz et al. 2021 and Boles et al. 2024.
- **H2b:** After expert adjudication, more than 50% of findings in reachable-code-agnostic scans are not exploitable in the product context. Zhou et al. 2025 report scanner false-positive rates of about 92%.
- **H2c:** Adding VEX statements reduces triage time per finding without increasing missed exploitable findings.

## Design
Use the SBOMs from E1 plus 6 pilot-product SBOMs. Scanners are Trivy, Grype, OSV-Scanner and Dependency-Track (pinned DB snapshot date). Take the union of normalised findings (`package@version`, with the vulnerability ID canonicalised to its CVE alias) and draw a stratified adjudication sample: all KEV findings, all CRITICAL findings, and a random 30% of the rest.

**Adjudication:** two security engineers label each finding independently as *affected / not affected / under investigation*, using the VEX status vocabulary and recording a justification. Report Cohen's κ, then resolve disagreements in a third-person review. Each label serves as an Annex I Part I(2)(a) decision record.

## Measures
- Per-scanner precision and recall against the adjudicated set
- Severity disagreement rate
- Time to triage per finding, with and without VEX/consensus hints (within-subject, counterbalanced)
- **False-assurance cases:** adjudicated *affected* findings that a scanner missed

## Ethics
Real vulnerabilities in pilot products are handled under the CVD policy. They are never published, and only aggregated, anonymised counts are reported.

## Note on the current fixtures
`../e2_scanner_agreement/synthetic/` exists only to test the analysis. Run the real scanners in CI, where the vulnerability databases are reachable.
