# Evidence and research-data governance (v1.2, recommendation P1-05)

Evidence bundles and research data can contain secrets, personal data, unreleased vulnerability details and confidential product designs. This policy sets out what may be stored, who may see it, and what may be published.

## 1. What evidence may contain
| Class | Examples | Allowed in CI artifact | Allowed in shared/published bundle |
|---|---|---|---|
| Public component data | SBOM, package versions, public CVE IDs | Yes | Yes |
| Scan results on own code | SCA/SAST findings, misconfigurations | Yes (restricted repository) | Only aggregated or anonymised |
| **Secret-scan matches** | API keys, passwords found in code | **Redacted values only** (`run_scan.py --redact-secrets`) | **Never** |
| Unfixed vulnerability details | Exploit paths, PoCs, affected endpoints | Restricted, need-to-know | **Never** before a fix and coordinated disclosure |
| Incident data (Art. 14) | Logs, IOCs, customer impact | Not in CI; store in an incident record with access control | **Never** |
| Personal data | Names, emails of users or reporters, IPs | Avoid; pseudonymise | **Never** (research data: pseudonymised under the consent terms) |
| Approvals / sign-offs | Reviewer name and role | Yes | Role only, unless the person consents |

## 2. Controls
- **Redaction at source.** Trivy secret output is masked before it is written as evidence. Run `tools/redact_check.py <bundle>` before sharing any bundle; it fails on likely secrets or email addresses. A clean result is heuristic only, and a human still reviews the bundle.
- **Access.** CI evidence artifacts inherit repository permissions: keep product repositories private, and restrict Actions artifact access. Long-term evidence lives in a restricted archive, not in the CI artifact store, whose retention here is 90 days.
- **Retention.** The technical documentation and EU declaration of conformity must be kept for the period set by the CRA: at least 10 years or the support period, whichever is longer (see catalogue row TD-02; verify against the current text). Evidence relied on in the technical file follows the same retention. Research data follows the consent and data-management plan.
- **Integrity.** Each evidence file is hashed in `evidence-manifest.json`. The decision engine recomputes the hashes, and the attestation job signs the bundle on `main`.
- **Secure sharing** with notified bodies, authorities or researchers:
  - share an export, never repository access
  - send it over an encrypted channel
  - log what was shared, with whom and when
  - include `decision.json` and the manifest so the recipient can verify integrity
- **Logs.** CI logs must not print secrets or evidence contents. `run_scan.py` prints status lines only.

## 3. Published samples in this repository
Everything under `examples/`, `experiments/` and `notebooks/` is synthetic or public open-source package data. The one exception is the E1 pilot output, which contains public package metadata, with one sandbox path redacted. The `redact-check` CI job scans these folders on every push.

## 4. Research data (SME pilots)
- **Consent and agreements.** Use written consent and a data-processing or collaboration agreement per SME (see `experiments/protocols/pilot-protocol-and-consent.md`).
- **Pseudonymisation.** Pseudonymise people and products before data leaves the SME. Keep the key file separately, with access limited to the PI.
- **Real vulnerabilities.** Any real vulnerability found during a pilot is reported to the SME under its CVD policy. It is never published in research outputs, and only aggregate counts are reported.
- **Deletion.** Delete or archive data on the schedule set in the data-management plan.
