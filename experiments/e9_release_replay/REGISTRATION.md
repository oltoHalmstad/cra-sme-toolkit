# E9 registration record

| | |
|---|---|
| Pre-registration DOI | **10.5281/zenodo.23438234**, https://doi.org/10.5281/zenodo.23438234 |
| Registered version | PREREGISTRATION.md v1.1 + VALIDATION.md |
| Freeze commit | `91ccf8a8ad34d1c2aac978b3fde11700d0a242cf` (2026-10-17T14:31:51Z) |
| Published | Confirmed published by the author on Zenodo before 2026-10-17T15:25Z (see the record's publication date) |
| Integrity | SHA-256 of every registered file is listed in FREEZE.txt inside the Zenodo record; the files in this folder must match it |
| Registered | 17 Oct 2026. No OSV, KEV or registry vulnerability data had been fetched before registration (see the note on the aborted run) |

Any deviation from the registered plan is listed below and reported in the paper.

## Aborted run before registration (disclosed)
Run 39042942480 of `e9-replay` was started by mistake on 17 Oct 2026 at 14:57 UTC, before the registration record was published, and cancelled within minutes. Only the `resolve` and `sbom` jobs had started: git checkouts, dependency resolution against package registries, and Syft. All were cancelled before completion. The `replay` job, the only one that fetches OSV, KEV and vulnerability data, never started, and no outputs were kept or inspected. The run's log: https://github.com/oltoHalmstad/cra-sme-toolkit/actions/runs/39042942480

## Deviations
| # | Date | What changed | Why | Effect on analysis |
|---|---|---|---|---|
| D1 | 17 Oct 2026 | `e9-replay.yml`: replay job logs every step and always pushes logs + results to branch `e9-results-run-<id>` (job permission `contents: write`). `fetch_data.py`: a failed request raises an error that names the URL and HTTP status. New SHA-256: e9-replay.yml `7dff8b0537a919e85a98235d62a2c776d1468eb513ce42a9ad6f561d17e33fc7`, fetch_data.py `87c9d07b8284303f73bf8a51b2cc363e71a7cef2594fb858445f52b9c5a483dc` | Run 39044972246 (first registered run) failed in the data-fetch step. Its log and artifacts could not be retrieved from the analysis environment, so the error was not visible | None. Sampling, inventories, matching rules, gates, statistics and the validation procedure are unchanged. Run 39044972246 produced no results |
| D2 | 17 Oct 2026 | `fetch_data.py`: up to 7 retries with backoff; failed OSV records are retried in two more passes with less parallelism; failures are recorded in MANIFEST.json (`osv_unfetched_records`, `osv_index_unfetched_packages`) and no longer abort the run; an OSV 404 is stored as a tombstone. `run_replay.py`: a package with **any** indexed but unfetched OSV record now counts as unassessed (before, the missing record was silently skipped). New SHA-256: fetch_data.py `c69870bc42ee08d8a743a96526c569a1825f11844365af2842b9762590c41800`, run_replay.py `9ad4f5d3df0de31e5b07c8e332b027405b0c2c4882037f5cf9f7f9f041a72ed8` | Run 39046134739 failed on a transient `Network is unreachable` error while fetching single OSV records (the KEV and OSV index steps had succeeded). The silent skip was found while diagnosing it, and would have broken the registered rule that missing data never counts as clean (§6) | Restores the registered fail-safe rule; strictly more conservative. No results existed before this change |

## Protocol notes (not deviations)
| # | Date | Note |
|---|---|---|
| N1 | 17 Oct 2026 | **Rater calibration.** Before the real sample, raters complete 3 practice items (`validation/practice/`). The items are drawn from unsampled `known_high` findings that share no package or vulnerability with the 30 sampled units. They are excluded from all analyses. The coding guide (VALIDATION.md) is unchanged. |
| N2 | 17 Oct 2026 | **Sampling error found after the run.** Mosquitto's latest stable release before the freeze is 2026-02-09, so it did not meet the registered activity criterion ("a stable release in the 6 months before the freeze"). It is retained as registered. Excluding it reduces the H9a empty-or-invalid group from 5 to 1 release; no other result changes. |
| N3 | 17 Oct 2026 | **Partial Maven resolution not flagged.** ThingsBoard v3.9, v3.9.1, v4.0.1 and v4.2 resolved to only 50–52 runtime components, against 515–522 later, but were counted as assessable. All four gates passed them. This is reported as further evidence for the H9a finding: silently incomplete inventories pass. |

## Registered run
Run **39047161461** (source `e399bc1`, 17 Oct 2026, data fetched 16:18Z, 0 unfetched OSV records) is the registered E9 run. Results: `results/run-39047161461/` (RESULTS.md, ANALYSIS.json). Runs 39044972246 and 39046134739 failed in the data-fetch step and produced no results.
