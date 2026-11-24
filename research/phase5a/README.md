# Phase 5A research tools

All commands below expect private inputs outside the Git worktree. The tools
refuse paths under a repository and write files with restrictive permissions.

```powershell
$P = 'C:\Users\kj\threat-detection-experiments\phase-5a-v1'
node research/phase5a/fixtures.mjs "$P\fixture-rerun"
node research/phase5a/run.mjs "$P\fixture-rerun\manifest.json" "$P\fixture-rerun\ledger.jsonl" "$P\validated-fixture-rerun"

# Existing pinned development projections (aggregate comparison only)
node research/phase5a/compare.mjs `
  "$P\phiusiil-v1\dataset\development" `
  "$P\phase-3d-v1\phresh" `
  "$P\comparison\report.json"

# Official-control inventory; no endpoint polling
node research/phase5a/control-inventory.mjs `
  "$P\controls\report.json" `
  "$P\phiusiil-v1\dataset" `
  "$P\phase-3c-v1\phresh" `
  "$P\phase-3d-v1\phresh" `
  "$P\phase-3e-v1\official-cohort\numeric.jsonl" `
  "$P\phase-3f-v1\cohort\numeric.jsonl"
```

`run.mjs` accepts a five-file historical projection suffix when an authorized
real ledger is available. It creates natural numeric JSONL, balanced ID views,
partition profiles and a freeze receipt. The final test files are intentionally
separate from development outputs.

The schema is the existing `url-lexical-v1` 14-column extractor. Features are
computed from normalized URL structure only; query strings, fragments,
credentials and page content are never exported.
