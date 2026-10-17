# Changelog
## 1.3.0rc1 — 17 Oct 2026: E9 real-world release replay (pre-registered; vulnerability replay pending)
- **Added E9** (`experiments/e9_release_replay/`): a frozen sample of 20 open-source IoT and network products and 144 real releases (2024Q4–2026Q3), selected from git history with a pre-registered rule. It also includes lockfile inventories for 94 releases (47,363 component-versions), coverage classification for all 144, and `PREREGISTRATION.md` (H9a–H9f).
- **Added `crasme.replay`:**
  - lockfile parsers (npm, pnpm, yarn, go.sum, Cargo.lock, requirements, rebar.lock)
  - ecosystem-aware version ordering, including Maven padding rules
  - OSV affected-range evaluation and as-of-date "time-travel"
  - KEV `dateAdded` filtering
  - a CVSS v3.1 base-score calculator checked against reference vectors
  - baseline gates, and bundles that run the real engine on replayed data
- **Added `crasme.gate` `scope="security"`** for research replay. It checks only scans and findings, reports `SCOPE_SECURITY_ONLY`, and is never eligible for conformity review; the schema is updated to match.
- **Added `tools/replay/`:** release selection, inventory extraction, time-travelled CI resolution (uv `--exclude-newer`, npm `--before`, Maven, Syft), data fetching with fail-safe KEV handling, the offline replay runner, Syft-vs-lockfile comparison, and the OpenCRA 0.1.6 head-to-head and fail-safe probes.
- **Added `.github/workflows/e9-replay.yml`:** a SHA-pinned matrix workflow (resolve → sbom → replay).
- **Added notebook 08.** Coverage and drift use real data. The vulnerability sections use a labelled **synthetic** cache until the CI run.
- **Changed:** an OSV report with `results: []` is now a valid clean result. OSV-Scanner omits clean sources, and an empty inventory is caught by the SBOM check and the input binding instead.
- **Packaging:** the synthetic E9 test cache (939 files) is now one `tests/fixtures/e9_synthetic_cache.tar.gz`; `run_replay.py --cache` accepts a `.tar.gz`. This keeps the archive under Zenodo's preview limit.
- **Release metadata:**
  - Zenodo DOI 10.5281/zenodo.23437353
  - public GitHub repository https://github.com/oltoHalmstad/cra-sme-toolkit
  - SECURITY.md uses GitHub private vulnerability reporting, with email as a fallback
  - schema `$id`s are DOI-based identifiers
  - `tools/set_doi.py` added
  - `tools/check_release.py` accepts PEP 440 pre-release versions
- **Real results so far:**
  - Median Jaccard between consecutive quarterly releases is 0.51, and 91% of transitions change more than 10% of components.
  - 17 C/firmware releases have no package manifest at all.

## 1.2.0 — 17 Oct 2026
This release implements `docs/reviews/v1.1-to-v1.2-improvement-recommendations.md`. Status per item: `docs/v1.2-implementation-status.md`.
- **P0-01 Fail-safe scans.**
  - `crasme.scanstatus` and `tools/run_scan.py` write explicit execution-status records with output validation: empty or truncated KEV feed, malformed JSON, empty SBOM, documented exit codes, timeouts.
  - `automation/security-scan.v1.2.yml` replaces the v1.1 workflow. It has no `|| true`, no `continue-on-error` and no empty-KEV fallback.
- **P0-02 Single release decision.**
  - `crasme.gate` (CLI `crasme-gate`, `tools/ci_gate.py`) decides PASS / FAIL / REVIEW_REQUIRED, with 64 reason codes, bundle and policy digests, and a JSON Schema.
  - PASS means only that the build is eligible for human conformity review.
  - Policy floors cannot be lowered, the catalogue is pinned by digest, and `--expect-build`/`--expect-product` bind the decision to the CI run.
  - Hardened after an independent adversarial review, which found 30 false-PASS inputs in the first draft; all were fixed and kept as `tests/test_adversarial.py`.
  - `policy.example.yaml` added.
- **P0-03 Catalogue legal QA.**
  - Catalogue v1.2.0 adds legal-status, source, reviewer, rationale, requirement-kind and operator-role metadata. All rows are `unverified`.
  - `tools/catalogue_review.py` records reviews in an append-only log.
  - Unverified in-force mandatory rows force REVIEW_REQUIRED.
- **P0-04 Build-bound evidence.**
  - Evidence manifest v2 records product, version, build SHA, artifact digest and input digests.
  - The gate checks binding, integrity, input changes and configurable (non-legal) age rules.
  - `schemas/product.schema.json` added.
- **P1.**
  - Anchored risk scoring with low/central/high ranges (`docs/risk-scoring-guide.md`, `crasme.risk.RatingRange`, workbook *Scoring anchors* sheet).
  - Seven lifecycle and Art. 14 templates, plus an updated incident checklist.
  - `docs/evidence-data-governance.md`, secret redaction and `tools/redact_check.py`.
  - `constraints-ci.txt`, `tools/verify_package.py`, and CI `package` and mutation jobs.
- **P2.**
  - E1 `benchmark-manifest.yaml`.
  - E3 Latin-square allocation and pre-registered analysis (`crasme.e3`, `experiments/e3_rater_study/`).
  - Seeded-fault suite `crasme.mutation` / `tools/mutation_suite.py`, with results in `experiments/e4_e7_gate_mutation/` and notebook 07. The v1.2 false-green rate is 0/69; the legacy v1.1 gate's is 63/69.
  - Pilot protocol and consent document.
- **Workbook:** `CRA-SME-Risk-and-Evidence-Calculator-v1.2.xlsx` replaces v1.1. It adds legal-status columns and the anchors sheet. The v1.0 workbook is kept for comparison.
- **Legacy:** the v1.1 gate has moved to `tools/legacy/` and is kept only as the comparison baseline.
- **Demo:** `examples/demo-release/` is a synthetic bundle whose decision is REVIEW_REQUIRED (legal mapping pending).

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
