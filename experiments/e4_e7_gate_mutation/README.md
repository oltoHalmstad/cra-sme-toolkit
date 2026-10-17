# E4/E7 lab result: seeded-fault evaluation of the release decision (17 Oct 2026)

**What it measures.** We planted 69 faults, one per bundle, into an otherwise valid **synthetic** release bundle (`crasme/demo.py`) for DEMO-001. The faults cover six areas:
- scanner and feed failures
- vulnerability findings
- evidence lineage and freshness
- obligations and legal mappings
- approvals
- policy and catalogue integrity
- engine errors

Each faulty bundle was evaluated by the v1.2 decision engine (`crasme.gate`) and by the legacy v1.1 CI gate (`tools/legacy/ci_gate_v1_1.py`).

| Metric (definition: v1.2 recommendations §5) | v1.2 engine | legacy v1.1 gate |
|---|---|---|
| Baseline (fault-free bundle) decision | PASS | PASS |
| **False-green rate**: PASS on a bundle containing a planted blocker | **0 / 69 (0%)** | **63 / 69 (91%)** |
| Expected decision (FAIL vs REVIEW_REQUIRED) | 69 / 69 | n/a |
| Expected reason code reported | 69 / 69 | n/a |
| **Freshness recall**: stale or mislinked evidence detected | **5 / 5** | 0 / 5 |

Reproduce with `python tools/mutation_suite.py`. Per-mutation rows are in `results.csv`. CI also enforces the result through `tests/test_gate.py`.

**How the fault set grew (reported so the numbers can be read honestly).**
- **M01–M37** were written by the toolkit authors together with the first v1.2 engine.
- **M38–M45** came from the authors' own follow-up review. The first v1.2 draft passed **all 8** of them.
- **M46–M69** came from an **independent adversarial review**, which found 30 further false-PASS inputs in that draft. These covered re-pointed or emptied scan outputs with recomputed digests, empty reports, VEX and approval gaps, policy and catalogue weakening, timezone handling, and overwriting via the workflow. All were fixed, and they are encoded here and in `tests/adversarial_review_attacks.py`.

One reviewer case is kept as intended behaviour: a revocation of an approval for a *different* build does not block the current build.

**How to read this.** This result is a **verification of the engine's logic against faults its authors anticipated**. It is not an estimate of how often such faults occur in real SMEs, and it says nothing about faults outside the catalogue. The v1.1 comparison shows *why* v1.2 was needed: v1.1 only checked KEV hits, and it treated missing or empty inputs as "nothing found".

The planned next step (E4 in the pilots) is to apply the same mutation operators to pilot repositories and to measure reviewer time per evidence package.
