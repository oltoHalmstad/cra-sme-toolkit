# E9 Pre-registration: Retrospective release replay on open-source IoT and network products

**Version:** 1.1, frozen 17 Oct 2026, before any vulnerability data was fetched (amendment log in §11).
**Toolkit commit:** record the commit that adds this file. Register it on OSF, or archive it on Zenodo, *before* running `.github/workflows/e9-replay.yml`.

## 1. Research questions and hypotheses
**RQ4 (false assurance) and head-to-head comparison.** Had each real release been gated at its release date, using only what was knowable then, what would each gate have decided?

| ID | Hypothesis (direction) | Primary measure |
|---|---|---|
| H9a | Gates that treat missing data as clean (`naive_kev`, `cvss7`) PASS ≥ 1 release whose inventory could not be assessed. CRA-SME v1.2 PASSes none. | Silent-pass rate on unassessable releases |
| H9b | ≥ 5% of releases with an assessable inventory shipped a component affected by a vulnerability that was **already KEV-listed on the release date**. | Share of releases with `known_kev > 0` |
| H9c | Consecutive quarterly releases change > 10% of their runtime components in most transitions. If so, a previous release's SBOM or scan is stale evidence. | Median Jaccard between consecutive inventories; share < 0.9 |
| H9d | For vulnerabilities disclosed after a release, the median time until a sampled later release no longer contains an affected version exceeds 30 days. | Days from publication to the first sampled release without it (upper bound) |
| H9e | CRA-SME v1.2 raises REVIEW on more releases than the baselines (the cost of fail-safety). This review burden is reported, not hidden. | Share of releases at REVIEW_REQUIRED, with reason-code distribution |
| H9f | Fail-safe comparison with OpenCRA 0.1.6. On empty, malformed or missing SBOMs and on unavailable feeds, each tool either fails or gives a clean exit. | Exit code per probe |

Status on 17 Oct 2026: H9c was computable from the frozen inventories and has been evaluated (§8). H9a, H9b, H9d, H9e and H9f require the CI run.

## 2. Product selection (done; frozen in `products.yaml`)
Inclusion criteria:
- open-source software for connected devices, gateways, edge or network appliances
- tagged releases
- a stable release in the 6 months before the freeze
- a public GitHub repository

The sample spans ecosystems: npm (4), PyPI (4), Go (5), Maven (2), C/firmware (3), Rust (1), Erlang/Hex (1). Three screened-out candidates are listed with reasons. **The projects are proxies.** We make no claim that they are themselves subject to the CRA; free and open-source software outside commercial activity is treated differently under the Act.

## 3. Release selection (done; frozen in `releases.csv`, 144 releases)
- **Stable tags only:** tags matching `^v?\d+(\.\d+){1,3}$`, or a product-specific pattern recorded in `products.yaml`.
- **Release date:** the committer date of the tagged commit, in UTC. Commit SHAs are recorded.
- **Window:** 2024-10-01 to 2026-09-30, split into 8 quarters.
- **One release per quarter:** the latest-dated stable tag in each quarter, giving at most 8 per product.

## 4. Inventories (done for lockfiles; CI for the rest)
- **Lockfiles at the release commit** (`inventories/`; `crasme.replay` parsers): npm package-lock/pnpm/yarn, go.sum, Cargo.lock, pinned requirements. Runtime dependencies are the primary analysis; dev dependencies feed a sensitivity analysis (`include_dev`).
- **No committed lock:** time-travelled resolution in CI. For pip this is `uv pip compile --exclude-newer <release date>`. For npm it is `npm install --package-lock-only --before=<release date>`. Maven uses `dependency:list`, because its versions are pinned in the POMs. Erlang/rebar3 is not resolvable and is reported as unassessable.
- **C/firmware:** a Syft directory scan. It is expected to be incomplete, and is reported as such rather than repaired by hand.

## 5. Vulnerability time-travel
- **OSV:** all OSV records per package, fetched in CI and cached with a fetch timestamp.
- **"Known at release":** OSV `published` ≤ release date, and not withdrawn by then.
- **Affectedness:** decided from OSV `affected` (explicit versions, then SEMVER/ECOSYSTEM ranges). If it cannot be decided (for example a GIT range only), the case is reported and treated as "possibly affected".
- **"KEV-listed at release":** any CVE alias has KEV `dateAdded` ≤ release date.
- **"Fix available at release":** a fixed version had been published to the registry by the release date.

## 6. Gates compared
| Gate | Rule |
|---|---|
| `none` | always PASS (status quo without a gate) |
| `naive_kev` | FAIL if a known finding is KEV-listed; missing data counts as clean (the v1.1 / typical CI pattern) |
| `cvss7` | FAIL if a known finding has CVSS ≥ 7.0; missing data counts as clean (common practice) |
| `crasme_v1_2` | the real `crasme.gate` engine at `scope=security`, as of the release date. Fail-safe; no VEX or triage is available retrospectively |
| OpenCRA 0.1.6 | the real tool on Syft SBOMs, **current knowledge only** (it has no time-travel), plus the fail-safe probes |

## 7. Analysis plan
- **Primary analysis:** descriptive proportions per gate, with 95% Wilson CIs. Releases are clustered within products, so report a product-level bootstrap as well (resample products).
- **No significance tests between gates.** The decisions are deterministic functions of the same data; we report differences and the cases that drive them.
- **Manual validation:** a stratified random sample of 30 `known_kev` and 30 `known_high` findings (seed 2026). Two raters check whether the affected code is plausibly reachable in the product, and Cohen's κ is reported. Precision = share judged plausibly reachable. The unit, strata, blinding, labels and statistics are fixed in **VALIDATION.md** and implemented in `crasme/validation.py` (tested).
- **Sensitivity analyses:**
  - include dev dependencies
  - exclude releases with undecidable matches
  - KEV-only versus KEV plus EPSS > 0.1 (if EPSS history is obtainable)

## 8. Results already available (frozen inventories, 17 Oct 2026)
- **Coverage:** 94 of 144 releases have a committed lockfile inventory. 29 need resolution. 17 (C/firmware) have no package manifest. 4 Node-RED releases have no committed lockfile.
- **H9c:** the median Jaccard between consecutive quarterly releases is **0.51**, and **91%** of transitions change more than 10% of components (notebook 08 §2). H9c is supported for the lockfile-inventory products.

## 9. Threats to validity
- **Construct:** a lockfile is not the shipped artefact. A KEV listing does not mean the product was exploitable. OSV ranges carry hindsight. A gate decision here is not a conformity statement.
- **Internal:** OSV `published` can lag the original disclosure. The registry publish time is used as the fix-availability date. Quarterly sampling makes exposure windows upper bounds.
- **External:** these are open-source, mostly community-maintained projects. SME commercial products may differ. The sample is purposive.
- **Reliability:** all inputs are frozen or cached with timestamps, tool versions are pinned, and the workflow is published.

## 10. Ethics
Only public data are used. Any previously unknown, exploitable issue found during manual validation is reported privately to the maintainers under their security policy, and never in the paper before a fix.

## 11. Amendment log
| Version | Date | Change | Data seen? |
|---|---|---|---|
| 1.0 | 17 Oct 2026 | Initial registration | No |
| 1.1 | 17 Oct 2026 | Manual validation operationalised in VALIDATION.md: (product, vulnerability, package) units deduplicated across releases; stratum blinding; three labels; κ before adjudication; Wilson CIs. KEV is fetched from CISA's GitHub mirror (cisagov/kev-data) if cisa.gov refuses the CI runner; the source is recorded in MANIFEST.json. | No. No OSV or KEV data had been fetched. |
