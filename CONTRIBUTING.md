# Contributing

Contributions are welcome, especially from SME practitioners, compliance specialists and other researchers.

## Ways to contribute
- **Obligation catalogue corrections** (`data/cra_requirements_catalogue.csv`). Open an issue using the *Obligation mapping correction* template. Cite the exact article or annex point on EUR-Lex, or the Commission guidance (C(2026) 5252) section. Changes to legal mappings need a second reviewer before merge.
- **E1/E2 fixtures and results.** Add a fixture with a `ground_truth.csv`, and record how the ground truth was produced. Include raw tool output and the tool version.
- **Code** (`crasme/`, `tools/`). Every change must ship with tests, and `pytest` must pass locally.
- **Notebooks.** Edit `tools/build_notebooks.py` if present, otherwise edit the notebook itself, then run `python tools/run_notebooks.py`. Commit executed notebooks so readers can see outputs without running them.

## Rules
- **No real vulnerability details, credentials, customer data or identifiable SME information** belong in issues, PRs or commits. Report security issues as described in `SECURITY.md`.
- **Label synthetic data in file names or headers.** Never mix synthetic and real data.
- **Pin versions.** GitHub Actions must be pinned to full commit SHAs, with the tag in a trailing comment.
- **Keep the disclaimers.** Nothing in this repository may claim to establish CRA conformity.

## Development
```bash
python -m pip install -e ".[test,notebooks]"
pytest                      # ~10 s; workbook parity tests need LibreOffice (skipped otherwise)
RUN_NOTEBOOKS=1 pytest tests/test_notebooks.py
```

Contributions of code are licensed under Apache-2.0. Contributions of documentation, templates and data are licensed under CC BY 4.0 (see `NOTICE`).
