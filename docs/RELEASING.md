# Releasing to GitHub and Zenodo

## One-time setup
1. **Create an empty GitHub repository** named `cra-sme-toolkit`, without a README or licence, because both are already here.
2. **Fill in the placeholders:**
   ```bash
   python tools/prepare_release.py --owner <github-user-or-org> \
       --orcid <0000-0000-0000-0000> --affiliation "<institution>" --security-email <address>
   python tools/check_release.py --strict      # must print no PLACEHOLDER lines
   git commit -am "Fill release metadata"
   ```
3. **Push:**
   ```bash
   git remote add origin https://github.com/<owner>/cra-sme-toolkit.git
   git push -u origin main --tags
   ```
   The repository is shipped as a git bundle, so clone it first with `git clone cra-sme-toolkit-v1.1.0.bundle cra-sme-toolkit`.
4. **On GitHub,** turn on Settings → Code security → *Private vulnerability reporting*, plus Dependabot alerts.
5. **On Zenodo,** log in with GitHub, open Account → GitHub, and switch the repository **on**. Only releases created *after* the switch is on are archived.

## Each release
1. Bump the version and date in `pyproject.toml`, `CITATION.cff`, `.zenodo.json`, `codemeta.json` and `crasme/__init__.py`, and add a `CHANGELOG.md` entry.
2. Run `python tools/check_release.py --strict && pytest && python tools/run_notebooks.py`, then commit the executed notebooks.
3. Tag and push with `git tag -a vX.Y.Z -m "vX.Y.Z" && git push --tags`.
4. **Create the GitHub release** from the tag (Releases → Draft a new release). Zenodo then archives the release and mints two DOIs: a *version DOI* and a *concept DOI* that always resolves to the latest version.
5. **Add the DOI to the repository:** run `python tools/set_doi.py --concept <concept DOI> --version <version DOI>` and commit to `main`; there is no need to re-release. The Zenodo-specific steps are in `docs/ZENODO.md`.

## Uploading by hand instead of through the GitHub integration
Upload `cra-sme-toolkit-v1.1.0.zip` on zenodo.org → New upload. Copy the fields from `.zenodo.json`: resource type *Software*, licence Apache-2.0, plus the creators, description and keywords. Mention the CC BY 4.0 part in the description, because a Zenodo record holds only one licence.

## Before the first public release
- **Legal review:** have a legal specialist review the catalogue rows marked "verify" and the E5 answer key (`REVIEW-v1.0-findings.md`, items marked 📋).
- **Third-party material:** confirm you have the right to publish `docs/background/` and the v1.0 playbook.
- **Confidential data:** confirm that no real SME data is included. Everything except `experiments/e1_sbom_benchmark/pilot-results/` is synthetic.
