# Zenodo instructions for the CRA-SME Toolkit

**Existing record:** DOI **10.5281/zenodo.23437353**, https://doi.org/10.5281/zenodo.23437353
Prepared 17 Oct 2026. The record could not be inspected from the build environment, so **step 0 is to confirm what it contains.**

---

## 0. Confirm what the existing DOI is (5 minutes)
Open https://zenodo.org/records/23437353 and note the following.

| Check | Where on the record page | Write down |
|---|---|---|
| Is it published or still a **draft with a reserved DOI**? | A draft shows "Save draft / Publish" and is visible only to you | published / draft |
| **Version** | "Version" field (right-hand side) | e.g. 1.2.0 |
| **Version DOI vs concept DOI** | The page shows the version DOI at the top. Under *Versions*, "Cite all versions? You can cite all versions by using the DOI …" shows the **concept DOI** | concept DOI = 10.5281/zenodo.______ |
| **Files** | *Files* box | e.g. `cra-sme-toolkit-v1.2.0.zip` |
| **Creators, licence, keywords** | Metadata section | check against §3 below |

What each DOI is for:
- **Version DOI** (23437353, if this is a version): cite it in a paper's *replication package* for the exact files used.
- **Concept DOI**: put it in the README badge and in "how to cite". It always resolves to the latest version.

---

## 1. If the record is still a **draft** (DOI reserved, not yet published)
1. Make sure the uploaded file is the **v1.2.0 release archive** (`cra-sme-toolkit-v1.2.0.zip`), not the 1.3.0-dev E9 snapshot. The E9 vulnerability results are not in yet, and they belong in a later version.
2. Fill in the metadata from §3. **Before you click Publish, check:**
   - the creator name and ORCID are yours
   - the affiliation is filled in
   - **both licences** are listed: Apache-2.0 for code and CC-BY-4.0 for docs and data. Current Zenodo allows several licences; if your form allows only one, choose Apache-2.0 and keep the licensing sentence in the description.
   - the related identifiers are entered (§3)
3. **Publish.** Files can no longer be changed after this, but metadata can still be edited with *Edit → Publish*, without creating a new DOI.

## 2. If the record is **published**
- **Metadata corrections** (typos, ORCID, affiliation, related links): use *Edit* on the record and then *Publish*. The DOI stays the same.
- **New files**, for example the E9 results: create a *New version* (§4). Never delete the old version and re-upload; a new version is how changes are recorded.

---

## 3. Metadata to paste (v1.2.0)
| Field | Value |
|---|---|
| Resource type | Software |
| Title | CRA-SME Toolkit: a risk-driven, evidence-based research toolkit for EU Cyber Resilience Act implementation in SMEs |
| Creators | Torstensson, Olga (add ORCID + affiliation) |
| Version | 1.2.0 |
| Publication date | 2026-10-17 |
| Licences | Apache-2.0 (code); CC-BY-4.0 (documentation, templates, catalogue, workbooks, notebook text) |
| Keywords | Cyber Resilience Act; Regulation (EU) 2024/2847; SME; SBOM; compliance as code; cybersecurity risk assessment; evidence traceability; vulnerability disclosure; Article 14 reporting; design science research |
| Language | English |
| Related identifier: *References* | https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng (Publication) |
| Description | Use the text in `.zenodo.json` → `description`. It already states the data status, the limits and the licensing split |

**Notes / Additional description** (paste as-is):
> Research instruments only: not legal advice, not an official CRA assessment and not a conformity assessment. The obligation catalogue is legally UNVERIFIED (every row is marked `unverified`); see docs/v1.2-implementation-status.md. Synthetic data is labelled; only experiments/e1_sbom_benchmark/pilot-results/ contains real tool output. Software development was assisted by an AI system (Claude, Anthropic); the author reviewed the outputs and is responsible for the content.

The AI-assistance sentence matches what most publishers now require. Keep it consistent with what you write in papers.

---

## 4. Next versions (planned)
### 4a. E9 pre-registration: a **separate** record, to be published **before** running the e9-replay workflow
A pre-registration must carry a timestamp that predates the data, so make it its own small record. Do not make it a version of the software record.

| Field | Value |
|---|---|
| Resource type | Publication → *Preprint*, or *Other* with "Pre-registration" in the title |
| Title | Pre-registration: Retrospective release replay of 20 open-source IoT and network products (E9, CRA-SME) |
| Files | `PREREGISTRATION.md` (export to PDF), `products.yaml`, `releases.csv`, `inventories/summary.csv` |
| Related identifier | *Is supplement to* 10.5281/zenodo.23437353 (or the concept DOI) |
| Licence | CC-BY-4.0 |
| Description | "Hypotheses H9a–H9f, sampling rule, gates compared and analysis plan, registered before any vulnerability data were fetched. The release sample (144 releases) and lockfile inventories are frozen from git history as of 2026-10-17." |

Alternatively, register on **OSF Registries** (osf.io/registries), which is the standard place for pre-registrations, and link the OSF DOI here.

### 4b. Software version 1.3.0 (after the e9-replay run)
1. In the repository, set version 1.3.0 in all metadata files (`python tools/check_release.py` checks them). Add the E9 results (`e9-results/`, plus `e9-cache/MANIFEST.json` and `kev.json`) under `experiments/e9_release_replay/results/`. Commit and tag `v1.3.0`.
2. On the existing record, click **New version**. Zenodo copies the metadata, and you replace the files with `cra-sme-toolkit-v1.3.0.zip`.
3. Update the version, date and description. Add one sentence: "1.3.0 adds E9, a retrospective release replay on 20 open-source IoT and network products (144 releases), with real vulnerability time-travel results."
4. Add the related identifier: *Is supplement to* → the pre-registration DOI (§4a).
5. **Large data.** If the OSV cache (`e9-osv-cache`) is large, archive it as a separate **Dataset** record linked with *Is derived from* / *Is supplement to*, rather than inflating the software archive.

### 4c. When a paper is accepted
Add a related identifier to the record (Edit → Publish): *Is supplement to* → the paper's DOI.

---

## 5. Repository changes made for this DOI (already done)
- `README.md`: the DOI badge and the citation now use 10.5281/zenodo.23437353.
- `CITATION.cff`: `doi: 10.5281/zenodo.23437353` added, so GitHub's "Cite this repository" shows it.
- `.zenodo.json` and `codemeta.json`: the DOI is recorded as an identifier.

**After step 0:** if 23437353 turns out to be a *version* DOI and you have the concept DOI, run
`python tools/set_doi.py --concept 10.5281/zenodo.<concept> --version 10.5281/zenodo.23437353`
and commit. The README then cites the concept DOI, and `CITATION.cff` keeps the version DOI as an extra identifier.

## 6. Final checks before publishing anything
- [ ] `python tools/check_release.py --strict` passes: no OWNER, example.invalid or placeholder values.
- [ ] `pytest` passes, and `python tools/verify_package.py` reports OK.
- [ ] `python tools/redact_check.py examples experiments notebooks docs` reports 0 items.
- [ ] You have the right to publish `docs/background/` (your concept note and summary) and the v1.0 playbook.
- [ ] The archive does not contain the Git bundle or local caches. `git archive` of the tag guarantees this.
