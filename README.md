# CRA-SME Toolkit

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23437353.svg)](https://doi.org/10.5281/zenodo.23437353)
![licence: Apache-2.0 (code) / CC BY 4.0 (docs, data)](https://img.shields.io/badge/licence-Apache--2.0%20%7C%20CC%20BY%204.0-blue)

**A risk-driven, evidence-based research toolkit for implementing the EU Cyber Resilience Act (Regulation (EU) 2024/2847) in SMEs.** Version 1.3.0rc1 (release candidate for 1.3.0), research edition, 17 October 2026.

> **Not legal advice. Not an official CRA assessment. Not a certification.** The risk scores are research instruments and are not EU thresholds. Nothing here establishes CRA applicability or conformity.

## Install and run
```bash
# download and unzip the release archive from https://doi.org/10.5281/zenodo.23437353, then:
cd cra-sme-toolkit-<version>
python -m pip install -e ".[test,notebooks]"     # Python ≥ 3.12
pytest                                            # ~100 tests; workbook parity needs LibreOffice
python tools/run_notebooks.py                     # re-execute the six notebooks
```

## How to cite
Cite the Zenodo DOI of the version you used. GitHub's "Cite this repository" button reads `CITATION.cff`.

> Torstensson, O. (2026). *CRA-SME Toolkit: a risk-driven, evidence-based research toolkit for EU Cyber Resilience Act implementation in SMEs* (Version 1.3.0rc1) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.23437353

## Licensing
| Part | Licence |
|---|---|
| Code: `crasme/`, `tools/`, `tests/`, `automation/`, `schemas/`, shell scripts, notebook code cells | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| Documentation, templates, `comparison/`, experiment protocols and data templates, `data/` catalogue, workbooks, notebook text and figures | [CC BY 4.0](LICENSES/CC-BY-4.0.txt) |

See `NOTICE` for details and third-party material.

## Automated evidence ≠ legal conformity
The release-decision engine (`crasme-gate`) returns one of three verdicts:
- **PASS:** every required scan completed; there is no blocking finding; every in-force mandatory obligation has reviewed evidence bound to *this* build; legal mappings are verified; approvals are valid. PASS means only that the build is **eligible for human conformity review**.
- **FAIL:** a known blocker was found, for example a KEV-listed component confirmed as affected, tampered evidence, or an obligation recorded as failed.
- **REVIEW_REQUIRED:** something is missing, failed, stale, unverified or needs a human decision.

The engine never determines legal conformity: `legal_conformity` is always `NOT_DETERMINED_BY_TOOL`. Risk scores are not an input. The shipped obligation catalogue is **legally unverified**, so out of the box the best possible verdict is REVIEW_REQUIRED (see `examples/demo-release/`).

```bash
crasme-gate --bundle examples/demo-release --policy examples/demo-policy.yaml --as-of 2027-12-20T12:00:00Z --out /tmp/decision.json   # → REVIEW_REQUIRED
python tools/mutation_suite.py        # 69 seeded faults: false-green 0/69 (legacy v1.1: 63/69)
```

## New in 1.3.0rc1: E9, a real-world release replay
The toolkit is replayed on **20 open-source IoT and network products and 144 real releases**. The question is what each gate would have decided at each release date. See `experiments/e9_release_replay/` and notebook 08.

The sample, inventories and drift results are real. The vulnerability replay runs in the `e9-replay` GitHub Actions workflow, because it needs OSV and KEV access.

## What is new in v1.2
| Path | What it is |
|---|---|
| `crasme/gate.py`, `tools/ci_gate.py`, `policy.example.yaml`, `schemas/release_decision.schema.json` | Single release-decision engine |
| `crasme/scanstatus.py`, `tools/run_scan.py`, `automation/security-scan.v1.2.yml` | Fail-safe scanner status records and workflow |
| `tools/catalogue_review.py`, `data/cra_requirements_catalogue.csv` (v1.2.0) | Legal-review metadata and workflow |
| `templates/` (7 new) | Applicability, support period, security updates, substantial-modification log, Art. 14 record, EU DoC checklist, release approval |
| `docs/risk-scoring-guide.md`, `docs/evidence-data-governance.md` | Scoring anchors; evidence and privacy policy |
| `crasme/mutation.py`, `experiments/e4_e7_gate_mutation/`, notebook 07 | Seeded-fault evaluation |
| `crasme/e3.py`, `experiments/e3_rater_study/` | E3 allocation and pre-registered analysis |
| `docs/v1.2-implementation-status.md` | Status of every recommendation, including what still needs humans |

## Added in v1.1
| Path | What it is |
|---|---|
| `REVIEW-v1.0-findings.md` | 16 review findings on v1.0 (incl. wrong Annex I letters, unpinned CI actions) with status |
| `CRA-SME-Risk-and-Evidence-Calculator-v1.2.xlsx` | Corrected 46-row Evidence Matrix with legal status, uncertainty + exploitation + gate columns, Scoring anchors, Provenance sheet |
| `data/cra_requirements_catalogue.csv` | Machine-readable obligation catalogue (source of the matrix) |
| `crasme/` | Tested Python core used by notebooks, CI and experiments |
| `schemas/trace_unit.schema.json` | Traceability-unit JSON Schema (concept note §5) |
| `automation/security-scan.v1.2.yml` | SHA-pinned evidence workflow (v1.2: fail-safe, single decision) |
| `experiments/` | Protocols E1–E8, pre-registration, interview guide, data templates, E1 pilot results |
| `notebooks/` | Seven executed Jupyter notebooks (risk sensitivity, inter-rater, SBOM/scanner, traceability, Art. 14 tabletop, pilot analysis, gate mutation) |
| `tests/` | pytest suite (`pip install -r requirements.txt && pytest`) |
| `comparison/` | Existing-solutions landscape and verified related-work list |

Synthetic data is always labelled as such; only `experiments/e1_sbom_benchmark/pilot-results/` contains real tool output.

## Contents (v1.0 practitioner kit, retained)
- `docs/CRA-SME-Implementation-Playbook-v1.0.docx` — 12-week practical playbook
- `CRA-SME-Risk-and-Evidence-Calculator.xlsx` — v1.0 workbook (kept unchanged for comparison; use v1.1)
- `templates/` — templates for classification, threat model, risk acceptance, CVD policy, Annex II/VII and incident reporting
- `automation/security-scan.yml` — v1.0 starter job (superseded: uses mutable action tags, see F-07)
- `automation/scripts/generate_sbom.sh` — reproducible example command
- `examples/` — fictitious sample inputs, NOT an assurance claim

## First steps
1. Copy directory to a restricted project repository; assign the responsible product owner.
2. Open workbook START HERE; replace/delete **DEMO-** rows.
3. Fill Products scope and classification memo; check Annex III/IV, exemptions and conformity route.
4. Complete threat model and Risk Register; justify scores and financial assumptions.
5. Map Annex I/II/VII obligations to controls and evidence; mark inapplicable only with recorded rationale.
6. Adapt scanning workflow to your build, repository permissions, licensing and data handling; verify tool outputs manually.
7. Set up CVD intake, reportability triage and reporting escalation with on-call coverage.
8. Review technical file and conformity path before product release.

**Important dates:** Article 14 notifications apply since 11 September 2026; the CRA main application is 11 December 2027. In-scope products already available on the EU market may have reporting duties even before the main application date. See official sources below.

**Official sources:**
- https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng
- https://digital-strategy.ec.europa.eu/en/policies/cra-summary
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- https://digital-strategy.ec.europa.eu/en/factpages/cyber-resilience-act-implementation
- https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation

**Scope and limitation:** Illustrative threat scoring and financial estimates are not prescribed by the CRA. A compliance matrix is an aid to evaluation, not a replacement for reviewing full Annex I and legal obligations. Scanning requires permissions; run only on assets you own or are authorized to test.

## Repository map (additions for publication)
`CITATION.cff`, `.zenodo.json` and `codemeta.json` hold the citation and archive metadata. `LICENSES/` and `NOTICE` hold the licences. `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `SECURITY.md` cover governance. `.github/` has CI (SHA-pinned), Dependabot and issue/PR templates. `docs/background/` holds the research concept note and the CRA state-of-play summary. `docs/RELEASING.md` explains how to publish a release on GitHub and Zenodo.
