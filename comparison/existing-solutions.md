# Comparison with existing solutions: positioning CRA-SME (as of 17 Oct 2026)

Each item was checked against a live public page on 17 Oct 2026, unless it is marked *unverified*. Coverage codes: **S** scope/classification · **R** risk assessment · **B** SBOM · **V** vulnerability handling · **A** Art. 14 reporting · **T** technical documentation · **E** evidence traceability/provenance · **M** SME focus. Y = covered, P = partial, – = not covered.

## 1. Nearest neighbours: the manuscript must compare against these explicitly

| Solution | Type | S | R | B | V | A | T | E | M | Why it matters |
|---|---|---|---|---|---|---|---|---|---|---|
| **ENISA SME Cyber Resilience Maturity Assessment Model** (13 Jul 2026) | Official maturity model with an .xlsx tool: 5 domains, 25 questions, 1–5 scale, 3 profiles, an Annex D mapping to the CRA | P | P | P | Y | P | P | – | **Y** | Overlaps with our Readiness sheet. **Use it as the external baseline** in every pilot, rather than competing with it |
| **OCCTET toolkit** (Eclipse Foundation, EU-funded, released 10 Sep 2026) | Open-source SME toolkit: self-assessment portal, Apoapsis (SBOM), Curator (VEX), federated assessment database | P? | ? | Y | Y | ? | ? | ? | **Y** | Closest open-source competitor. *occtet.eu could not be reached, so its licence and exact coverage are unverified.* Fetch and compare before submission |
| **OpenChain CRA Compliance Checklist** v1.0 | Checklist aligned with ISO/IEC 5230, ISO/IEC 18974 and BSI TR-03183 | P | – | Y | Y | Y | Y | P | P | Already covers governance through to the technical file, so a checklist alone is not novel |
| **Koutidis et al. 2026**, arXiv:2610.07873 | Academic SME case study: scoping, assets, evidence, obligation mapping, gap analysis, audit package | P | P | – | P | P | Y | P | Y | Closest *academic* work. It has one case and no quantitative evaluation |
| **OpenCRA** (crwncode, 0.1.6) and **wardex** (GitHub) | CLI / GitHub Action: SBOM, OSV and KEV checks producing an "Art. 14 candidate" | – | – | Y | Y | P | – | – | P | KEV-based Art. 14 candidate detection is **not** novel. Our contribution there is the awareness decision record, SRP field drafting and the deadline engine |
| **OSCAL / compliance-trestle** v5.0.0 | Compliance-as-code framework | – | – | – | – | – | Y | **Y** | – | The closest model to our evidence graph. **Recommendation:** export trace units as OSCAL assessment results in v2 |

## 2. Frameworks, standards and official guidance (inputs to the framework, not competitors)

| Item | Status in 2026 | Role for CRA-SME |
|---|---|---|
| NIST SSDF SP 800-218 | v1.1 is final. Rev. 1 (v1.2) is an initial public draft from 17 Dec 2025, and no final version was found | Map Annex I Part II to SSDF practices in the requirements model |
| OWASP SAMM v2.0 / BSIMM16 (Feb 2026) | Current | Process-maturity comparators. Neither has a CRA legal mapping |
| IEC 62443-4-1 | Ed. 1 (2018); an amendment is in progress (DIN project, 2025) | Required for industrial pilot products |
| ETSI EN 303 645 V3.1.3 | Current | Consumer-IoT pilot products |
| CRA harmonised standards (prEN 40000-x, prEN 50770 …) | None cited in the OJ. Horizontal deadline 31 Oct 2026, vertical 31 Dec 2026 | Gap-check once published. No presumption of conformity before then |
| JRC/ENISA CRA requirements–standards mapping (2024) | Not updated since | Seed for the provenance column of the catalogue |
| **BSI TR-03183-2 v2.1.0** (20 Aug 2025) | CycloneDX ≥ 1.6 or SPDX ≥ 3.0.1, hashes, SPDX licence IDs, recursive dependency depth | **Conformance target for E1 (H1c)** |
| CISA 2025 SBOM Minimum Elements | Draft of Aug 2025; final version *unverified* | Secondary SBOM checklist |
| SLSA v1.2 (Nov 2025), in-toto | Current | Provenance model for the evidence manifest and attestation |
| ENISA CRA Single Reporting Platform (live 11 Sep 2026) | No API, English only, EU Login, Assigned Representative roles. Field list in Glossary v1.5 | Field schema used in E5 |

## 3. Open-source tools (integrate with these, do not rebuild them)
Syft v1.52.0 · Grype v0.119.0 · Trivy v0.76.0 · OSV-Scanner v2.6.0 · cdxgen · Semgrep v1.181.0 · Gitleaks v8.30.1 · Dependency-Track 5.1.0 (KEV, CycloneDX 1.7) · DefectDojo · Secvisogram / gocsaf (CSAF 2.0) · vexctl (OpenVEX) · OpenSSF Scorecard. Versions are taken from GitHub release pages on 17 Oct 2026; some pages show no year.

## 4. Commercial platforms (verified CRA claims only)
| Vendor | Verified CRA-related features | Not found |
|---|---|---|
| ONEKEY | Firmware SBOM, monitoring, a "Compliance Wizard" covering CRA, IEC 62443-4-2 and EN 303 645 | Art. 14 submission workflow |
| Anchore Enterprise v6 | SBOM, VEX, third-party SBOM import, compliance view citing Annex I | Art. 14, technical file |
| Keysight SBOM Manager | SBOM "aligned with EU CRA", VEX, monitoring | — |
| Finite State | CRA managed services: SBOM, monitoring, risk assessment | Art. 14 and technical-file features (page returned 404) |
| Black Duck, Snyk, Codenotary | Marketing or blog content only | CRA-specific modules |
| TÜV Rheinland | Fixed-price CRA check consultancy, including product classification | Tooling |

None of the commercial tools we could verify offers product classification with a recorded rationale, uncertainty-aware risk quantification, or SRP-ready Art. 14 drafting. All are priced for enterprises.

## 5. Positioning statement (for the manuscript)
> Existing CRA support for SMEs is either **assessment-oriented** (ENISA maturity model, OpenChain checklist, OCCTET self-assessment) or **tool-oriented** (SBOM/SCA/VEX scanners, commercial platforms). Neither kind produces a **reproducible, provenance-linked trace** from a specific product build to each applicable CRA obligation, and none has been **empirically evaluated** for evidence quality, effort or false assurance in SMEs. CRA-SME contributes (i) a versioned obligation catalogue whose applicability decisions are machine-checkable, (ii) an evidence schema with hashes and freshness, tested against injected lifecycle events, (iii) a release gate kept separate from risk scores, and (iv) a multi-experiment evaluation (E1–E8).

**Claims to avoid:** being first to offer a CRA checklist, SBOM automation, KEV-based reporting triggers or an SME maturity self-assessment. All of these already exist.

**Claims to make only after the systematic review (concept note Phase 1):** that no empirical multi-SME evaluation exists. The literature search found none (see `related-work.md`), but that search was not systematic.

## 6. Comparison experiments this implies
1. **ENISA model vs CRA-SME readiness score** in each pilot: correlation and disagreements, with each disagreement case reviewed qualitatively.
2. **CRA-SME pipeline vs OCCTET (Apoapsis/Curator) vs OpenCRA** on the E1/E2 fixtures: SBOM recall, VEX handling and KEV detection. Use the same fixtures and pinned versions.
3. **Trace export as OSCAL** and import into compliance-trestle: test interoperability (pass/fail plus field-loss count).
4. **Commercial firmware analyser** (if academic licence available) on the E1 C/firmware stratum: tests H1b.
