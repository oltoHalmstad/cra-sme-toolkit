# Zenodo upload: CRA-SME Toolkit 1.3.0rc1

**DOI (confirmed):** 10.5281/zenodo.23437353 · **GitHub:** https://github.com/oltoHalmstad/cra-sme-toolkit
**File to upload:** `cra-sme-toolkit-v1.3.0rc1.zip` (a `git archive` of tag `v1.3.0rc1`; it contains no caches, mirrors or git history)

> **Important (avoid a duplicate DOI).** You are uploading by hand to the record that already holds DOI 23437353. Do **not** switch on the Zenodo↔GitHub integration for this repository yet. If it is on, the GitHub release `v1.3.0rc1` would mint a *second*, unrelated record. Switch it on later, only if you want future GitHub releases to become new versions automatically. Even then, Zenodo will create a new concept, so it is usually simpler to keep using "New version" by hand on this record.

## 1. Push to GitHub first (so the links in the description resolve)
```bash
git clone cra-sme-toolkit-v1.3.0rc1.bundle cra-sme-toolkit && cd cra-sme-toolkit
git remote add origin https://github.com/oltoHalmstad/cra-sme-toolkit.git
git push -u origin main --tags
```
Then, on GitHub, create a release from tag **v1.3.0rc1** and tick *"Set as a pre-release"*. Turn on Settings → Code security → *Private vulnerability reporting*, because SECURITY.md relies on it.

## 2. Zenodo form: field by field
| Field | Enter |
|---|---|
| Files | upload `cra-sme-toolkit-v1.3.0rc1.zip` |
| DOI | keep the reserved/assigned **10.5281/zenodo.23437353** ("Do you already have a DOI?" → No; Zenodo reserves it) |
| Resource type | **Software** |
| Title | CRA-SME Toolkit: a risk-driven, evidence-based research toolkit for EU Cyber Resilience Act implementation in SMEs |
| Publication date | 2026-10-17 |
| Creators | **Torstensson, Olga**. Role: Researcher. Add your ORCID and affiliation (not included in the repository files, because they were not provided) |
| Description | paste §3 (plain text) or §4 (HTML, using the editor's source view) |
| Licences | **Apache License 2.0** and **Creative Commons Attribution 4.0 International**. If only one can be chosen, pick Apache-2.0; the description states the split |
| Keywords / subjects | Cyber Resilience Act; Regulation (EU) 2024/2847; SME; SBOM; software supply chain security; compliance as code; release gate; cybersecurity risk assessment; evidence traceability; vulnerability disclosure; Article 14 reporting; CISA KEV; OSV; design science research |
| Version | **1.3.0rc1** |
| Language | English |
| Publisher | Zenodo |
| Related works | *Is supplement to* → https://github.com/oltoHalmstad/cra-sme-toolkit/tree/v1.3.0rc1 (Software) · *References* → https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng (Publication / Other) |
| Additional description, type "Notes" | Version 1.3.0rc1 (release candidate). E9 vulnerability replay results pending; to be added in 1.3.0. Obligation catalogue legally unverified. Synthetic data labelled. |
| Funding | add any project or grant if applicable; otherwise leave empty |
| Communities (optional) | e.g. a software-engineering, cybersecurity or institutional community you belong to |

Click **Preview**, check that the description renders, then **Publish**. After publishing, files are fixed. Metadata can still be corrected with *Edit → Publish* without a new DOI.

## 3. Description: plain text (paste into the editor)
CRA-SME is an open research toolkit for implementing and evaluating the EU Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) in small and medium-sized enterprises. It connects product risks, software supply-chain evidence, vulnerability data and CRA obligations in a traceable chain: obligation → risk → control → test → evidence → reviewer decision. Each link is bound to a specific product build.

Main components

- CRA obligation catalogue (46 rows, CSV). Each row gives the article/annex reference, application date, gate, evidence type and legal-review status. Every row is currently unverified, pending review by a qualified legal reviewer.

- Release-decision engine (crasme-gate). It returns PASS / FAIL / REVIEW_REQUIRED with 65 reason codes and fails safe on missing, failed, stale or tampered evidence. PASS means only "eligible for human conformity review": the tool never determines legal conformity, and risk scores are not an input.

- Tested Python package crasme. It provides fail-safe scanner status records; build-bound evidence manifests; ordinal and Monte Carlo risk models with anchored ratings; inter-rater agreement statistics; SBOM and scanner accuracy metrics; Article 14 reporting clocks and tabletop scoring; and lockfile parsers with vulnerability "time-travel" (OSV and CISA KEV as of a given date).

- SHA-pinned GitHub Actions workflows: a product evidence workflow, CI, and the E9 replay workflow.

- Risk and evidence workbook (xlsx), templates for the CRA lifecycle and Article 14, and governance documentation.

- Nine experiment protocols (E1–E9), a pre-registration template, data-collection templates and eight executed Jupyter notebooks.

Evaluation material included

- E1 SBOM generator pilot (real tool output; 3 fixtures). A manifest-only Python SBOM recalled 4 of 12 installed packages, and a vendored C library went undetected.

- E4/E7 seeded-fault evaluation (synthetic bundles; 69 faults). These include 24 faults contributed by an independent adversarial review. The v1.2 engine produced 0/69 false PASS decisions; the earlier v1.1 gate produced 63/69. This verifies the engine logic against anticipated faults and does not estimate real-world prevalence.

- E9 retrospective release replay, pre-registered. The sample is 20 open-source IoT and network products with 144 real releases (2024Q4–2026Q3), frozen from git history, plus lockfile inventories for 94 releases (47,363 component-versions). Two results already come from real data. First, consecutive quarterly releases share a median Jaccard of 0.51 of their runtime components, and 91% of transitions change more than 10% of components. Second, 17 C/firmware releases have no package manifest. The vulnerability replay and the comparison with OpenCRA are not yet run; they will be added in a later version. The open-source projects are used as proxies; no claim is made that they themselves fall under the CRA.

Data status. Real data: the E1 pilot outputs, the E9 release sample, inventories and drift analysis. Everything else (examples, the demo release bundle, the mutation suite, and the vulnerability sections of notebook 08) is synthetic and labelled as such.

Limits. These are research instruments only: not legal advice, not an official CRA assessment and not a conformity assessment. Risk scores are not CRA criteria.

Licensing. Code is licensed under Apache-2.0. Documentation, templates, the obligation catalogue, workbooks and notebook text are licensed under CC BY 4.0 (see LICENSES/ and NOTICE).

AI assistance. Parts of the code, documentation and protocols were developed with the assistance of an AI system (Claude, Anthropic). The author reviewed the outputs and is responsible for the content.

Source repository: https://github.com/oltoHalmstad/cra-sme-toolkit

## 4. Description: HTML (paste into the editor's source/HTML view)
```html
<p><strong>CRA-SME</strong> is an open research toolkit for implementing and evaluating the EU Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) in small and medium-sized enterprises. It connects product risks, software supply-chain evidence, vulnerability data and CRA obligations in a traceable chain: <em>obligation → risk → control → test → evidence → reviewer decision</em>. Each link is bound to a specific product build.</p>
<p><strong>Main components</strong></p>
<ul>
<li><strong>CRA obligation catalogue</strong> (46 rows, CSV). Each row gives the article/annex reference, application date, gate, evidence type and legal-review status. Every row is currently <em>unverified</em>, pending review by a qualified legal reviewer.</li>
<li><strong>Release-decision engine</strong> (<code>crasme-gate</code>). It returns PASS / FAIL / REVIEW_REQUIRED with 65 reason codes and fails safe on missing, failed, stale or tampered evidence. PASS means only "eligible for human conformity review": the tool never determines legal conformity, and risk scores are not an input.</li>
<li><strong>Tested Python package</strong> <code>crasme</code>. It provides fail-safe scanner status records; build-bound evidence manifests; ordinal and Monte Carlo risk models with anchored ratings; inter-rater agreement statistics; SBOM and scanner accuracy metrics; Article 14 reporting clocks and tabletop scoring; and lockfile parsers with vulnerability "time-travel" (OSV and CISA KEV as of a given date).</li>
<li><strong>SHA-pinned GitHub Actions workflows</strong>: a product evidence workflow, CI, and the E9 replay workflow.</li>
<li><strong>Risk and evidence workbook</strong> (xlsx), templates for the CRA lifecycle and Article 14, and governance documentation.</li>
<li><strong>Nine experiment protocols (E1–E9)</strong>, a pre-registration template, data-collection templates and eight executed Jupyter notebooks.</li>
</ul>
<p><strong>Evaluation material included</strong></p>
<ul>
<li><strong>E1 SBOM generator pilot</strong> (real tool output; 3 fixtures). A manifest-only Python SBOM recalled 4 of 12 installed packages, and a vendored C library went undetected.</li>
<li><strong>E4/E7 seeded-fault evaluation</strong> (synthetic bundles; 69 faults). These include 24 faults contributed by an independent adversarial review. The v1.2 engine produced 0/69 false PASS decisions; the earlier v1.1 gate produced 63/69. This verifies the engine logic against anticipated faults and does not estimate real-world prevalence.</li>
<li><strong>E9 retrospective release replay</strong>, pre-registered. The sample is 20 open-source IoT and network products with 144 real releases (2024Q4–2026Q3), frozen from git history, plus lockfile inventories for 94 releases (47,363 component-versions). Two results already come from real data. First, consecutive quarterly releases share a median Jaccard of 0.51 of their runtime components, and 91% of transitions change more than 10% of components. Second, 17 C/firmware releases have no package manifest. The vulnerability replay and the comparison with OpenCRA are <strong>not yet run</strong>; they will be added in a later version. The open-source projects are used as proxies; no claim is made that they themselves fall under the CRA.</li>
</ul>
<p><strong>Data status.</strong> Real data: the E1 pilot outputs, the E9 release sample, inventories and drift analysis. Everything else (examples, the demo release bundle, the mutation suite, and the vulnerability sections of notebook 08) is <strong>synthetic and labelled as such</strong>.</p>
<p><strong>Limits.</strong> These are research instruments only: not legal advice, not an official CRA assessment and not a conformity assessment. Risk scores are not CRA criteria.</p>
<p><strong>Licensing.</strong> Code is licensed under Apache-2.0. Documentation, templates, the obligation catalogue, workbooks and notebook text are licensed under CC BY 4.0 (see <code>LICENSES/</code> and <code>NOTICE</code>).</p>
<p><strong>AI assistance.</strong> Parts of the code, documentation and protocols were developed with the assistance of an AI system (Claude, Anthropic). The author reviewed the outputs and is responsible for the content.</p>
<p>Source repository: <a href="https://github.com/oltoHalmstad/cra-sme-toolkit">https://github.com/oltoHalmstad/cra-sme-toolkit</a></p>
```

## 5. After publishing
1. Note the **concept DOI** shown under *Versions* ("Cite all versions"). If it differs from 23437353, run
   `python tools/set_doi.py --concept 10.5281/zenodo.<concept> --version 10.5281/zenodo.23437353`, then commit and push.
2. **Pre-registration.** The E9 pre-registration (`experiments/e9_release_replay/PREREGISTRATION.md`) is now timestamped by this record, before any vulnerability data was fetched. Mention the DOI in the paper's methods section. Registering it additionally on OSF is optional.
3. **Version 1.3.0.** After the `e9-replay` workflow has run, add the results and create **New version** on this record (`docs/ZENODO.md` §4b).
