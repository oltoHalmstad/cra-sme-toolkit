# Demo release bundle (SYNTHETIC)

All identifiers, findings and the KEV entry are invented. Regenerate with `python tools/make_demo_bundle.py`; evaluate with
`python -m crasme.gate --bundle examples/demo-release --as-of 2027-12-20T12:00:00Z --out /tmp/decision.json`.

Expected decision: **REVIEW_REQUIRED** because the shipped obligation catalogue has not been legally reviewed (all rows `unverified`). With a verified catalogue the same bundle is PASS (see `tests/test_gate.py`).
