# E9 manual validation: protocol and rater coding guide

Part of the E9 pre-registration (PREREGISTRATION.md §7). Frozen 17 Oct 2026, before any vulnerability data was fetched.

## Purpose
A replay finding means "the lockfile pinned a version that OSV lists as affected". Validation estimates how often such a finding is a **plausible real exposure of the shipped product**: the precision of the version match. It does not test exploitability.

## Sample (automated, `tools/replay/validation.py sample`)
- **Unit:** a unique (product, vulnerability, package) triple whose vulnerability was *known at release*. The same triple in several releases is one unit, validated at its earliest sampled release.
- **Strata:**
  - `known_kev`: KEV-listed by the release date.
  - `known_high`: CVSS ≥ 7.0 and not KEV-listed. A unit that qualifies for both is assigned to `known_kev`.
- **Size:** 30 units per stratum, drawn with `random.Random(2026)`. If a stratum has fewer than 30 units, all of them are taken, and the shortfall is reported.
- **Blinding:**
  - Items are presented in one seeded random order that mixes both strata.
  - Rater sheets do not show the stratum, the CVSS score or the KEV date.
  - `sample_key.csv` holds the stratum and is kept by the coordinator. Raters must not see it.
  - Each rater works independently and does not discuss items until both sheets are submitted.

## What each rater does per item (target 10–15 minutes; record `minutes_spent`)
1. Open `osv_url` and identify the affected function or module and any conditions, such as a configuration option, platform or feature.
2. Open `source_url` (the product's source at the release commit) and determine how the package is used:
   - Is it a runtime dependency of the shipped product, or only build, test or dev tooling that the lockfile mislabels?
   - Is the affected functionality imported or used, directly or through a direct dependency? Use repository code search or grep.
   - Is the affected platform or feature part of what the project ships?
3. Assign **one label**:

| Label | Use when |
|---|---|
| `PLAUSIBLE` | The package ships at runtime **and** nothing found rules out the affected code path. The default when it is used and the affected feature is not clearly absent. |
| `NOT_PLAUSIBLE` | There is positive evidence that the affected code cannot be reached in the shipped product. Examples: only a build, test or dev tool; affected API never imported; affected platform not built; version actually overridden or patched in the source. |
| `UNDETERMINED` | You cannot decide within about 20 minutes. For example, the advisory gives no detail, or usage is too indirect to trace. |

4. Write one or two sentences in `evidence`: file paths, the import found or not found, the advisory's precondition.

**Do not** run exploits or test against live systems. Use only public data. If you believe you have found a previously unknown, exploitable issue, stop and tell the coordinator. It will be reported privately to the maintainers under their security policy (PREREGISTRATION §10).

## Agreement and adjudication
- **Cohen's κ** (unweighted, 3 labels) on the independent labels, **before adjudication**, with a 95% bootstrap CI (2,000 resamples, seed 2026). Observed agreement is reported too.
- **Adjudication:** both raters discuss each disagreement and record a consensus label in `adjudicated.csv` (same columns). If they cannot agree, the label is `UNDETERMINED`.
- **Precision** per stratum = PLAUSIBLE / (PLAUSIBLE + NOT_PLAUSIBLE) on adjudicated labels, with a 95% Wilson CI. `UNDETERMINED` items are reported separately.
- **Sensitivity:** precision with `UNDETERMINED` counted as `NOT_PLAUSIBLE`.

## Commands
```bash
python tools/replay/validation.py sample --results e9-results --e9 experiments/e9_release_replay \
    --out experiments/e9_release_replay/validation
# send rater_A.csv / rater_B.csv to the raters; collect them back into the same folder
python tools/replay/validation.py score --dir experiments/e9_release_replay/validation            # κ
python tools/replay/validation.py score --dir experiments/e9_release_replay/validation --adjudicated  # + precision
```
