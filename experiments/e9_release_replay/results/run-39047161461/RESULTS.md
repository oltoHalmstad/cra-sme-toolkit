# E9 results: run 39047161461 (17 Oct 2026)

**Pre-registration:** 10.5281/zenodo.23438234 (v1.1, freeze commit `91ccf8a`). Deviations D1 and D2 are in `../../REGISTRATION.md`; neither changes the analysis plan.
**Run:** GitHub Actions run 39047161461, source commit `e399bc1`. Data fetched 2026-10-17T16:18Z.
**Data completeness:**
- 5,899 runtime packages and 4,958 OSV records
- **0 unfetched**
- KEV catalogue 2026.10.16 (1,748 entries), fetched directly from cisa.gov. `kev_dates.csv` holds the CVE IDs and dates the analysis uses; the full JSON is on branch `e9-results-run-39047161461`, with its SHA-256 in `kev_catalog.json`.
- The OSV cache (artifact `e9-osv-cache`, kept 90 days) should be archived as a Zenodo dataset for exact reproduction.

**Sample:** 144 releases of 20 products. Numbers are from `ANALYSIS.json` (`tools/replay/analyze_e9.py`). Proportions carry 95% Wilson CIs, plus a product-level cluster bootstrap (5,000 resamples, seed 2026) where shown.

## Gate decisions (n = 144)
| Gate | PASS | REVIEW | FAIL |
|---|---|---|---|
| none | 144 | – | 0 |
| naive_kev (missing = clean) | 144 | – | 0 |
| cvss7 (missing = clean) | 74 | – | 70 |
| **CRA-SME v1.2** (`scope=security`) | 55 | 89 | 0 |

Every release that `cvss7` failed, CRA-SME sent to REVIEW (70/70). CRA-SME also sent 19 releases that `cvss7` passed to REVIEW. Every release CRA-SME passed was also passed by `cvss7`.

## Registered hypotheses
| ID | Result | Verdict |
|---|---|---|
| **H9a** silent PASS on unassessable releases | **Baselines:** all three PASS every release with an empty or invalid inventory (5/5; Wilson 0.57–1.00). They also PASS ≥ 24/25 releases whose inventory class the registration declared unassessable or expected-incomplete. **CRA-SME v1.2:** PASSes 0/5 of the empty or invalid ones (0–0.43), but **19/25 of the declared-incomplete ones** (0.76; 0.57–0.89). These are tasmota ×7 and pihole-ftl ×6 (Syft found 1–2 components in C/firmware without a package manifest) and emqx ×6 (rebar3 unresolvable; Syft found only Python test tooling). | **Partly refuted.** The baseline half is supported. The claim "CRA-SME PASSes none" holds only for *empty or invalid* evidence. The engine has no test for *non-empty but incomplete* inventories, so it fails open there. |
| **H9b** ≥ 5% shipped an already KEV-listed vulnerability | 0/119 assessable releases (Wilson 0–3.1%). There is one *possibly affected* case: frigate v0.18.0, starlette CVE-2026-48710, KEV-listed 4 days before release. The version pin is a wildcard, so this is undecidable, and the engine raised `KEV_TRIAGE_PENDING` and `ARTICLE14_ASSESSMENT_REQUIRED`. Only 3 OSV records (2 CVEs) in all the inventories were *ever* KEV-listed. | **Not supported.** KEV-based gating gives almost no signal for open-source dependency stacks. Meanwhile 58% of assessable releases (49–66%) shipped a known HIGH/CRITICAL vulnerability, and 56% shipped one with a fix already published. |
| **H9c** > 10% component change in most transitions | Lockfile products: median Jaccard **0.53**, **91%** (82–95%) of 85 transitions below 0.9. All inventories: 0.58; 78% of 121. | **Supported.** A previous release's SBOM or scan is stale evidence. |
| **H9d** median exposure > 30 days | 2,633 (product, vulnerability, package) units disclosed after a release. 1,904 were fixed in a later sampled release: median **50 days** (IQR 23–78; upper bound because of quarterly sampling). **69%** (67–72%) took over 30 days. 729 units were not fixed within the window (right-censored, so the true median is higher). | **Supported.** |
| **H9e** CRA-SME reviews more than baselines; cost reported | REVIEW on **62%** (54–69%; product bootstrap 46–78%), versus a FAIL rate of 49% for `cvss7` and 0% for `naive_kev`. Reasons, counted per release: `FINDING_UNTRIAGED` 78, `KEV_STATUS_UNKNOWN` (no CVE alias) 35, `SCAN_OUTPUT_INVALID` 5, `KEV_TRIAGE_PENDING` 1, `ARTICLE14_ASSESSMENT_REQUIRED` 1. | **Supported.** The review burden is substantial: about 13 points more releases than `cvss7` blocks. |
| **H9f** OpenCRA 0.1.6 fail-safe probes | **Clean exit (0)** on an **empty** SBOM and on a **truncated/malformed** SBOM ("0 critical vulnerabilities found"). It fails (exit 2) on a non-CycloneDX file, on a missing file and when offline with no cache. | **Supported.** 2 of the 5 broken-input probes give a clean result. |

## Registered sensitivity analysis
Excluding releases with undecidable matches removes frigate (7 releases; its requirements pin `x.y.*` wildcards). With n = 137, CRA-SME REVIEW is 60% and `cvss7` FAIL is 46%. The conclusions are unchanged.

## Manual validation (registered; in progress)
The pre-registered sample has **0 `known_kev` units** (none exist) and **30 `known_high` units** (from 255 available). Because only one stratum exists, the stratum is not hidden from raters in practice. Rater sheets are in `../../validation/` and the coordinator key is in `coordinator/`. Status: awaiting two raters (VALIDATION.md).

## Exploratory (not registered; label as such in any paper)
- **OpenCRA with today's knowledge** flags KEV hits on 18/144 release SBOMs:
  - 15 involve vite or starlette with known versions
  - 5 thingsboard releases also carry **Spring4Shell (CVE-2022-22965) and CVE-2018-1273**, matched to Spring Boot starters that Syft listed **without a version** (POM properties unresolved). The resolved runtime inventory shows spring-beans 6.1.15, which is not affected, so these are false positives from matching versionless components.
  - See `opencra/opencra_kev_matches.csv`.
- **E1 at scale (Syft vs lockfile, median recall):**

  | Ecosystem | Median recall | Minimum |
  |---|---|---|
  | npm | 1.00 | – |
  | crates.io | 0.99 | – |
  | Go | 0.98 | 0.79 |
  | PyPI | **0.85** | 0.76 |

  For C/firmware there is no lockfile ground truth. Syft finds 0–2 components there.
- **Alias duplication:** 8% of raw known findings are the same vulnerability under two IDs (for example GHSA and PYSEC). Release-level metrics are unaffected; the validation sample contains no alias duplicates.

## What this means for the paper
1. The strongest, quotable results are H9c (stale evidence), H9d (50-day exposure windows), and the KEV result (H9b refuted: KEV-only gates such as `naive_kev`, or OpenCRA `--fail-on kev`, see almost nothing in open-source dependency stacks, while over half of releases ship known HIGH findings).
2. The honest limitation is H9a. Fail-safety on *missing or invalid* evidence works. *Silently incomplete* evidence (C/firmware, unresolvable ecosystems) passes every gate, including CRA-SME v1.2. This is a concrete design requirement, an inventory-completeness assertion, and a natural v1.3 engine change. Its effect must be reported as a **post-hoc** analysis.
