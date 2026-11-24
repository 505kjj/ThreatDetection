# Phase 5F offline runner

Use the pinned Phase 5B CPython environment, Phase 3C PyArrow packages, Phase 5E private numeric projection receipts, and saved Phase 5C–5E model artifacts. The full run verifies the Phase 5E thresholds and metrics before fitting the structurally grouped experiment. `--replay-only` skips new model fitting.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$env:PYTHONPATH = "$p/phase-3c-v1/packages"
$guard = 'research/phase3d/resource_guard.py'
npm ci --prefix research/phase5e --ignore-scripts
npm ci --prefix evaluation --ignore-scripts
New-Item -ItemType Directory "$p/phase-5f-rerun"
& $py $guard --metrics "$p/phase-5f-rerun/resources.json" -- $py research/phase5f/run.py $p "$p/phase-5f-rerun/experiment"
& $py $guard --metrics "$p/phase-5f-rerun/tests.json" -- $py -m unittest discover -s research/phase5f -p 'test*.py'
```

The output directory is exclusive and outside Git. Only `results.json` and the resource receipt are aggregate artifacts. Keep model binaries and private Phase 5E projections outside the repository. The experiment opens no independent URL archive or publisher test labels. See the [report](../../docs/experiments/phase5f/README.md) for current evidence, frozen evaluation constraints and custody requirements.
