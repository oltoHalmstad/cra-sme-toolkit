# Security policy

## Reporting a vulnerability in this toolkit
**Report privately to the author by email** (see the creator contact on the Zenodo record, https://doi.org/10.5281/zenodo.23437353). The development repository is private, so there is no public issue tracker. Please put "CRA-SME security" in the subject line.

Please include the affected file or version, reproduction steps, and the impact. We aim to acknowledge reports within 5 working days.

## Scope
In scope:
- code in `crasme/` and `tools/`
- the CI workflows in `.github/workflows/` and `automation/`
- supply-chain issues such as an unpinned or compromised action

Out of scope:
- vulnerabilities in the third-party tools the workflows invoke (report those upstream)
- findings about products evaluated in the research pilots (these go through the coordinated disclosure process agreed with each SME, never through this repository)

## Supported versions
Only the latest release receives fixes.
