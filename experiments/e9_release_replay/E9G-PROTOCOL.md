# E9-G: completeness-aware gating (POST-HOC, EXPLORATORY)

**Status:** post-hoc. Written 18 Oct 2026, **after** the registered E9 results were known; committed before the E9-G code was written or run. It is **not** part of pre-registration 10.5281/zenodo.23438234 and must be reported separately from H9a–H9f.

## Question
Can an inventory-completeness check reduce silent PASS on incomplete inventories without making review impractical?

## Gates
| Gate | Definition |
|---|---|
| G1 | CVSS ≥ 7 gate, as registered (missing data treated as clean) |
| G2 | CRA-SME v1.2 engine, as registered (fail-safe on missing, invalid, stale or tampered evidence; no representativeness test) |
| G3 | G2 plus the completeness rules C1–C3 below. Any C-rule that fires turns a G2 PASS into REVIEW_REQUIRED; FAIL is unchanged |

## Completeness rules (fixed before running)
Inputs available at release time: the gate's inventory, the method that produced it, the product's declared build ecosystem, and an **independent** SBOM of the same checkout (Syft directory scan).
- **C1 `INVENTORY_METHOD_INCOMPLETE`:** the inventory comes only from a source-directory scan of a product with no package manifest, or from an ecosystem whose dependencies could not be resolved (rebar3 without a lock).
- **C2 `INVENTORY_ECOSYSTEM_MISSING`:** the product's declared build ecosystem (npm, PyPI, Go, Maven, crates.io, Hex) contributes zero components to the inventory.
- **C3 `INVENTORY_CROSSCHECK_LOW`:** coverage of the independent SBOM is below **0.50**. Coverage is the share of the independent SBOM's component names in the declared ecosystem that also appear in the inventory, development dependencies included, compared by name and not by version. It is evaluated only when the independent SBOM has ≥ 10 such components.

## Evaluation A: natural historical releases (all 144)
- **Known-incomplete set (24):**
  - the 20 releases with a present but declared-incomplete inventory
  - the 4 ThingsBoard releases with partial Maven resolution, identified after the run (registration note N3)
- **Complete controls:** releases whose inventory is a committed lockfile (`inventory_status = lockfile`).
- **Endpoints:**
  1. PASS rate on the known-incomplete set, for G1, G2 and G3
  2. extra REVIEW caused by C-rules on complete controls that G2 passed (unnecessary REVIEW)
  3. G3 review rate overall

## Evaluation B: seeded faults
- **Controls:** complete-control releases that G2 passes.
- **Faults:** each fault is applied to each control's inventory, with the random seed 2026. The independent SBOM is left unchanged; it simulates a second, independent pipeline.

  | Fault | Change to the inventory |
  |---|---|
  | F1 | remove a random 50% of runtime components |
  | F2 | remove a random 90% of runtime components |
  | F3 | keep only development or test components, relabelled as runtime (skipped if the control has none) |
  | F4 | remove every component of the declared ecosystem; if nothing remains, the inventory is empty |
  | F5 | keep two random components ("source-only firmware scan") |
  | F6 | strip all versions |

- **Re-evaluation:** G1, G2 and G3 are re-evaluated on each faulty inventory with the same cached OSV, KEV and registry data.
- **Endpoints:**
  1. false PASS = a faulty inventory receives PASS, per gate and per fault, with Wilson 95% CIs and product-cluster bootstrap
  2. detection recall of G3's C-rules
- **Overhead:** wall-clock time of the C-rules per release.

## Limits stated in advance
- **Controls are not human-verified.** A committed lockfile is treated as a complete inventory of the resolved dependency graph, not of the shipped artefact.
- **C3 depends on an independent SBOM.** If both inventories are wrong in the same way, C3 cannot detect it.
- **No acceptance threshold was set with SMEs.** The results are descriptive.
