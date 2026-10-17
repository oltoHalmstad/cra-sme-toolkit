# E7 — Seeded-vulnerability false-assurance study
**RQ4 "false assurance"** · Lab only

This experiment asks how often the automated CRA-SME pass reports *no blocking issue* while an applicable Annex I Part I requirement is violated.

## Targets (deliberately vulnerable, run in an isolated lab)
- **Web:** OWASP Juice Shop, WebGoat
- **IoT/firmware:** OWASP IoTGoat; a Damn Vulnerable Router Firmware image; a custom ESP32-class demo firmware
- **Custom:** the DEMO-001 gateway with **seeded defects**, one for each Annex I Part I(2) letter. Examples:

| Seed | Annex I | Defect |
|---|---|---|
| S-b | (2)(b) | Default admin password, no reset to secure state |
| S-c | (2)(c) | Update channel without signature verification |
| S-d | (2)(d) | Unauthenticated management endpoint |
| S-e | (2)(e) | TLS 1.0 and plaintext credential storage |
| S-g | (2)(g) | Telemetry collects device location without need |
| S-j | (2)(j) | Debug port/service enabled in release build |
| S-l | (2)(l) | No security event logging |
| S-m | (2)(m) | Factory reset leaves user credentials on flash |

## Procedure
1. Run the full v1.1 pipeline: SBOM, SCA, OSV, Semgrep, Trivy secret and misconfiguration scanning, and the gate.
2. Two blinded experts review the pipeline output and the technical-file draft, then rate each requirement *met / not met / cannot tell*.
3. Compare the results with the seed key.

## Measures
- Detection rate per seed: automated only, versus automated plus expert review.
- **False-assurance rate:** seeds where the automated output gave no signal and the requirement was marked met.

The expected result is that design-level requirements ((g), (l), (m)) are invisible to scanners. This supports the claim that human review is necessary (RQ4).

Seed list template: `../data-templates/e7_seeds.csv`.
