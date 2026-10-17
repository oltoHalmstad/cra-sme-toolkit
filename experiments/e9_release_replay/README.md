# E9: Retrospective release replay on real open-source IoT and network products

**Pre-registration:** https://doi.org/10.5281/zenodo.23438234 (see REGISTRATION.md).

**Sample:** 20 products and 144 real releases (2024Q4–2026Q3), frozen from git history on 17 Oct 2026.

| File | Content | Real? |
|---|---|---|
| `products.yaml` | Product sample, roles, lockfile sources, screened-out candidates | Real |
| `releases.csv` | 144 releases: tag, commit SHA, release date (UTC) | Real (git) |
| `inventories/` | Runtime and dev components per release from lockfiles (47,363 component-versions); `summary.csv` gives the coverage status | Real |
| `PREREGISTRATION.md` | Hypotheses H9a–H9f, gates, analysis plan, threats | Register before the CI run |

## How to run (needs network access: OSV, CISA KEV, package registries)
1. Register `PREREGISTRATION.md` (OSF or Zenodo) and note the toolkit commit.
2. Trigger the **`e9-replay`** workflow (Actions → e9-replay → Run workflow), or run locally:
   ```bash
   python tools/replay/resolve_ci.py --e9 experiments/e9_release_replay --product octoprint   # repeat per product needing resolution
   python tools/replay/fetch_data.py --inventories experiments/e9_release_replay/inventories --cache e9-cache
   python tools/replay/run_replay.py --e9 experiments/e9_release_replay --cache e9-cache --out e9-results
   tools/replay/opencra_compare.sh <dir-with-syft-sboms> e9-results/opencra
   E9_RESULTS=$PWD/e9-results python tools/run_notebooks.py notebooks/08_release_replay_E9.ipynb
   ```
3. Archive `e9-results/` and `e9-cache/` (fetch timestamps live in `MANIFEST.json`) with the paper's replication package.

## Regenerating the frozen sample (only if you deliberately re-freeze; record it as a protocol deviation)
```bash
for r in $(python -c "import yaml;print(' '.join(p['repo'] for p in yaml.safe_load(open('experiments/e9_release_replay/products.yaml'))['products']))"); do
  git clone --bare --filter=tree:0 https://github.com/$r mirrors/$(echo $r | tr / _).git; done
python tools/replay/select_releases.py --mirrors mirrors --products experiments/e9_release_replay/products.yaml --out experiments/e9_release_replay/releases.csv
python tools/replay/extract_inventory.py --mirrors mirrors --products experiments/e9_release_replay/products.yaml \
    --releases experiments/e9_release_replay/releases.csv --out experiments/e9_release_replay/inventories
```

## Results already available (no network needed)
- **Coverage:** 94/144 releases have lockfile inventories, 29 need resolution, 17 are C/firmware with no package manifest, and 4 have no committed lock.
- **Drift:** the median Jaccard between consecutive quarterly releases is **0.51**, and 91% of transitions change more than 10% of components. A previous release's SBOM is therefore rarely valid evidence for the next one.

Everything else in notebook 08 runs on a **SYNTHETIC** vulnerability cache (`tests/fixtures/e9_synthetic_cache.tar.gz`) until the CI run provides real data.
