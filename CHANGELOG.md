# Changelog
## 1.1.0 — 17 Oct 2026 (research edition)
The changes below respond to the review findings in `REVIEW-v1.0-findings.md`.
- **Added** the `crasme/` Python package, a tested research core:
  - risk models (workbook parity, Monte Carlo, ranking stability)
  - inter-rater statistics
  - SBOM and scanner parsers and metrics
  - Art. 14 deadline engine and tabletop scoring
  - traceability schema, coverage, freshness, hash verification and the score-independent release gate
  - provenance manifest CLI
  - pilot statistics
- **Added** `data/cra_requirements_catalogue.csv`, a catalogue of 46 obligations with references, application dates, gates and evidence types. It fixes the Annex I Part I(2) letter errors (F-01) and adds the missing obligations (F-02).
- **Added** `CRA-SME-Risk-and-Evidence-Calculator-v1.1.xlsx`:
  - a rebuilt Evidence Matrix
  - risk-register columns for uncertainty, exploitation evidence and the gate (W–AI)
  - a Provenance sheet
  - maturity anchors

  The v1.0 workbook is kept unchanged for comparison.
- **Added** `automation/security-scan.v1.1.yml`:
  - every action is SHA-pinned
  - pinned tool versions
  - OSV, Semgrep, and Trivy secret and misconfiguration scanning
  - an evidence manifest
  - a KEV gate
  - a build attestation

  Also added `tools/ci_gate.py`.
- **Added** `experiments/`:
  - protocols E1–E8, a pre-registration template, an interview guide and data templates
  - the E1 runner with fixtures and **real pilot results**
  - the E2 synthetic analysis fixtures
  - the E5 inject set using SRP field names
- **Added** six executed Jupyter notebooks in `notebooks/`.
- **Added** a pytest suite of 100+ tests in `tests/`. It includes:
  - LibreOffice recalculation parity with the workbooks
  - published reference values for ICC and Krippendorff's α
  - SHA-pinning checks on the workflow
- **Added** `comparison/`, a verified landscape of existing solutions and a related-work bibliography.
- **Publication packaging:**
  - licences: Apache-2.0 for code, CC BY 4.0 for docs and data, plus a `NOTICE`
  - citation and archive metadata: `CITATION.cff`, `.zenodo.json`, `codemeta.json`, and `pyproject.toml` (installable `crasme` package with bundled schema and catalogue)
  - CI: SHA-pinned, Python 3.12 and 3.13, LibreOffice parity tests, weekly notebook run
  - Dependabot, issue and PR templates
  - `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
  - release tools: `tools/check_release.py`, `tools/prepare_release.py`, and `docs/RELEASING.md`
  - one absolute sandbox path redacted from the E1 pilot output
- **Unchanged:** the v1.0 playbook (docx), templates, v1.0 workflow and v1.0 workbook. Their remaining issues are listed as open (📋) in the review.
