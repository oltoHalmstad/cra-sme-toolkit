# E4/E7 lab result: seeded-fault evaluation of the release decision (17 Oct 2026)

**What it measures.** We planted 37 faults, one per bundle, into an otherwise valid **synthetic** release bundle (`crasme/demo.py`) for DEMO-001. The faults cover six areas:
- scanner and feed failures
- vulnerability findings
- evidence lineage and freshness
- obligations and legal mappings
- approvals
- engine errors

Each faulty bundle was evaluated by the v1.2 decision engine (`crasme.gate`) and by the legacy v1.1 CI gate (`tools/legacy/ci_gate_v1_1.py`).

| Metric (definition: v1.2 recommendations §5) | v1.2 engine | legacy v1.1 gate |
|---|---|---|
| Baseline (fault-free bundle) decision | PASS | PASS |
| **False-green rate**: PASS on a bundle containing a planted blocker | **0 / 37 (0%)** | **33 / 37 (89%)** |
| Expected decision (FAIL vs REVIEW_REQUIRED) | 37 / 37 | n/a |
| Expected reason code reported | 37 / 37 | n/a |
| **Freshness recall**: stale or mislinked evidence detected | **5 / 5** | 0 / 5 |

Reproduce with `python tools/mutation_suite.py`. Per-mutation rows are in `results.csv`. CI also enforces the result through `tests/test_gate.py`.

**How to read this.** This result is a **verification of the engine's logic against faults its authors anticipated**. It is not an estimate of how often such faults occur in real SMEs, and it says nothing about faults outside the catalogue. The v1.1 comparison shows *why* v1.2 was needed: v1.1 only checked KEV hits, and it treated missing or empty inputs as "nothing found".

The planned next step (E4 in the pilots) is to apply the same mutation operators to pilot repositories and to measure reviewer time per evidence package.
