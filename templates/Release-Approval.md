# Release approval record — template
| Field | Entry |
|---|---|
| Product ID / version / build SHA / artifact digest | |
| Release-decision file (`decision.json`) bundle digest and decision | PASS / FAIL / REVIEW_REQUIRED |
| Open REVIEW items and how each was resolved (reason code → resolution) | |
| Unresolved findings accepted with rationale (cannot include known exploitable vulnerabilities — Annex I Part I(2)(a)) | |
| Legal decisions relied on (applicability, classification, conformity route) and their reviewers | |
| Security lead approval (name, date, expiry) | |
| Product owner approval (name, date, expiry) | |
| Final outcome: release / hold / release to limited channel | |
Record approvals in `approvals.json` for the decision engine: `{"role", "reviewer", "build_sha", "approved_at", "expires_at", "revoked"}`.
PASS from the engine is a precondition for human review, not a conformity declaration.
