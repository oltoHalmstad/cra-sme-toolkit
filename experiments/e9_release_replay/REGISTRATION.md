# E9 registration record

| | |
|---|---|
| Pre-registration DOI | **10.5281/zenodo.23438234**, https://doi.org/10.5281/zenodo.23438234 |
| Registered version | PREREGISTRATION.md v1.1 + VALIDATION.md |
| Freeze commit | `91ccf8a8ad34d1c2aac978b3fde11700d0a242cf` (2026-10-17T14:31:51Z) |
| Integrity | SHA-256 of every registered file is listed in FREEZE.txt inside the Zenodo record; the files in this folder must match it |
| Registered | 17 Oct 2026. No OSV, KEV or registry vulnerability data had been fetched before registration (see the note on the aborted run) |

Any deviation from the registered plan is listed below and reported in the paper.

## Aborted run before registration (disclosed)
Run 39042942480 of `e9-replay` was started by mistake on 17 Oct 2026 at 14:57 UTC, before the registration record was published, and cancelled within minutes. Only the `resolve` and `sbom` jobs had started: git checkouts, dependency resolution against package registries, and Syft. All were cancelled before completion. The `replay` job, the only one that fetches OSV, KEV and vulnerability data, never started, and no outputs were kept or inspected. The run's log: https://github.com/oltoHalmstad/cra-sme-toolkit/actions/runs/39042942480

## Deviations
None so far.
