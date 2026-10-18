# E9-G results (POST-HOC, EXPLORATORY)

Protocol: `../../E9G-PROTOCOL.md`, committed in `39cc882` before implementation. Code: `crasme/completeness.py` and `tools/replay/e9g_completeness.py`. Inputs: the cached OSV, KEV and registry data of the registered run; the inventories as run; and an independent Syft SBOM per release, taken from the archived OpenCRA outputs. Figures below come from `E9G.json`, `e9g_natural.csv` and `e9g_seeded.csv`.

## A. Natural historical releases (n = 144)
- **PASS on 24 known-incomplete releases:**
  - G1 (CVSS gate): 23/24
  - G2 (CRA-SME v1.2): 23/24
  - **G3 (with completeness rules): 0/24**
- **How each was caught:**

  | Releases | Caught by |
  |---|---|
  | 4 ThingsBoard partial resolutions | C3 independent cross-check (coverage 0.10) |
  | 7 EMQX releases | C2 (the Hex ecosystem is absent) |
  | 13 C/firmware releases | only C1, the method rule. This is by construction: both inventories are source scans, so a source-level cross-check cannot verify firmware. That needs a build-time or binary SBOM |

- **Complete controls (committed lockfile, n = 94):**
  - Decision-level unnecessary REVIEW: 0/26 (the 26 controls that G2 passed)
  - Flag-level: C3 fired on 13/94 releases, all of which G2 had already reviewed
    - Home Assistant ×8, coverage 0.07: the pinned core requirements omit the ~1000 integration dependencies installed on demand. The flag is arguably a true signal.
    - Frigate ×5, small independent counts and wildcard pins
- **Overall:** review rate rises from 62% (G2) to 78% (G3). Every additional review is a known-incomplete release.
- **Overhead:** about 0.1 ms per release for the C-rules (median), excluding the cost of producing the independent SBOM.

## B. Seeded faults (26 complete controls from 8 products; 130 faulty inventories)
- **Consistency:** on the unmodified controls, the re-evaluation reproduces the registered G1 and G2 decisions 26/26.
- **False PASS, all faults:** G1 130/130 · G2 80/130 · **G3 12/130**

| Fault | G1 | G2 | G3 | C-rule detection |
|---|---|---|---|---|
| F1 remove 50% | 26/26 | 26/26 | 12/26 | 14/26 |
| F2 remove 90% | 26/26 | 26/26 | 0/26 | 26/26 |
| F3 dev-only as runtime | n/a | n/a | n/a | not applicable: the frozen inventories retain no development dependencies (registration deviation D3) |
| F4 drop declared ecosystem | 26/26 | 2/26 | 0/26 | 26/26 |
| F5 two components | 26/26 | 26/26 | 0/26 | 26/26 |
| F6 strip versions | 26/26 | 0/26 | 0/26 | 0/26 (G2 already reviews: undecidable matches) |

**Limits:**
- F1 sits at the 0.50 coverage threshold, so about half pass. A stricter threshold trades this against more flags on controls.
- Controls are not human-verified.
- C3 requires a second, independent inventory pipeline.
- F3 could not be tested, because the inventories retain no development dependencies (deviation D3).
