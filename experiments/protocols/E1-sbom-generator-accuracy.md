# E1 — SBOM generator accuracy against installed ground truth
**RQ4 · Annex I Part II(1) · metric "SBOM completeness"** · Runner `../e1_sbom_benchmark/run_e1.sh` · Analysis: notebook 03

## Hypotheses
- **H1a:** SBOMs generated from manifests alone have lower version-level recall than SBOMs generated from the built artefact or installed environment.
- **H1b:** For C/C++ and firmware fixtures, recall stays below 0.8 for every source-based generator. Only binary analysis closes the gap.
- **H1c:** Fewer than half of the generator outputs conform to BSI TR-03183-2 v2.1.0 without post-processing. The relevant requirements are format ≥ CycloneDX 1.6 or SPDX 3.0.1, hashes, licence identifiers and recursive dependency depth.

## Fixtures (target: 24, stratified)
| Stratum | n | Examples | Ground-truth method |
|---|---|---|---|
| Python app | 4 | Flask/Django apps with pinned and unpinned dependencies | `pip freeze --all` inside a clean venv after install. Record whether pip/setuptools count as components (see validity) |
| Node app | 4 | lockfile v3, workspaces, a native addon | `npm ls --all --json` |
| Java | 4 | Maven multi-module, Gradle, shaded jar | `mvn dependency:list` on the resolved build. Reuse chains-project/sbom-2023 ground truth (Balliu et al. 2023) |
| Go | 3 | modules, vendored, CGO | `go list -m all` |
| Container | 4 | distroless, alpine, debian-slim, multi-stage | Package DB + language manifests in the final image |
| C/C++/embedded | 5 | vendored libs, Conan, Yocto image, CMake FetchContent, a firmware blob | Curated by hand from build logs, with two independent curators and adjudication |

Pilot (17 Oct 2026): py-app, node-app and c-vendored. Results are in `../e1_sbom_benchmark/pilot-results/` and notebook 03.

## Generators (pin versions in `runs.csv`)
Syft, Trivy, cdxgen, the ecosystem-native CycloneDX plugins (cyclonedx-py, cyclonedx-npm, cyclonedx-maven/gradle), and the GitHub dependency-graph export. Add at least one binary or firmware analyser if licensed (e.g. ONEKEY, or open-source binwalk + cve-bin-tool). Run each generator in every mode it supports: source, lockfile, installed environment, image.

## Procedure
1. Build each fixture reproducibly and record the commit and image digest. Run `setup_fixtures.sh` to regenerate the ground truth and **freeze it with a date**, because resolvers drift.
2. Run `run_e1.sh fixtures results` three times to check determinism (identical component sets).
3. Score each output with `crasme.sbom.accuracy` at version and name level. Save the diff lists.
4. Validate format conformance: the CycloneDX JSON schema, then a TR-03183-2 field checklist covering hashes, licences, supplier, dependency relationships and depth.
5. Feed every SBOM to the same scanner (Trivy) to measure how SBOM differences change vulnerability counts (as in O'Donoghue et al. 2024).

## Measures
Precision, recall and F1 (version level and name level); TR-03183 conformance per field; run-to-run Jaccard; wall time; the vulnerability-count delta caused by the SBOM.

## Validity threats and mitigations
- **Ground-truth definition.** Decide beforehand whether build-only tools, dev dependencies and OS packages count as components. Report results under both definitions. In the pilot, `pip` itself counted as a false positive.
- **Fixture representativeness.** Use stratified fixtures and include at least 2 anonymised SME-like repositories from the pilots, with consent.
- **Tool drift.** Pin versions, keep raw outputs, and record DB timestamps for scanners.

## Pilot result (illustrative; n = 3)
The manifest-only Python SBOM had recall 0.33, while the environment mode had recall 1.0. The vendored zlib in C was missed (recall 0.5). The Node lockfile tools were exact. See notebook 03.
