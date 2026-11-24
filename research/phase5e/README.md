# Phase 5E offline research runner

Use the private CPython 3.11 Phase 5B environment and its pinned Phase 3C
PyArrow dependency. Install the Node dependencies from the experiment lock.
The optional Chromium check uses the same isolated Playwright installation
described in the repository's extension regression instructions.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$old = "$p/phase-5c-v1"
$d = "$p/phase-5e-rerun"
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$g = 'research/phase3d/resource_guard.py'
$env:PYTHONPATH = "$p/phase-3c-v1/packages"
npm ci --prefix evaluation --ignore-scripts
npm ci --prefix research/phase5e --ignore-scripts
New-Item -ItemType Directory $d

& $py $g --metrics "$d/freeze-resources.json" -- $py research/phase5e/freeze_url.py $p "$d/frozen-url.json"
& $py $g --metrics "$d/projection-pilot-resources.json" -- $py research/phase5e/acquire.py $old "$d/html-pilot" --shards train-000 train-055 train-018 --budget-bytes 680000000
& $py $g --metrics "$d/model-pilot-resources.json" -- $py research/phase5e/compare.py "$old/cohort" "$d/model-pilot" 1000 --projections "$d/html-pilot"
& $py $g --metrics "$d/browser-resources.json" -- node research/phase5e/browser.mjs "$d/browser.json"
& $py $g --metrics "$d/controls-resources.json" -- $py research/phase5e/controls.py "$d/model-pilot" "$d/controls.json"
```

After verifying the preflight, pass its projection directory to the
scale worker. This skips previously projected shards and stops as soon
as the requested balanced training capacity has been reached.

```powershell
& $py $g --metrics "$d/projection-20k-resources.json" -- $py research/phase5e/acquire.py $old "$d/html-20k" --target-train 20000 --reuse "$d/html-pilot" --budget-bytes 14000000000
& $py $g --metrics "$d/model-20k-resources.json" -- $py research/phase5e/compare.py "$old/cohort" "$d/model-20k" 20000 --projections "$d/html-pilot" "$d/html-20k"
```

Use the resulting per-shard receipts, domain support, transfer rate
and resource measurements to decide whether a 50,000-row follow-up is
feasible. The scaler accepts both previous projection directories with
`--reuse` and stops when capacity or its transfer ceiling is reached.
Derived features and checkpoints remain private. The parser consumes an
in-memory stream of bounded documents and writes numeric records only.

For independent validation, the freeze receipt provides hashes for the
five saved models, the fusion coefficients and each model's original
operating points. A custody handoff needs a licensed and timestamped
cohort, independently supported labels, domain and family exclusion
receipts, and a documented access history before its one-time scoring.

## Tests

```powershell
node --test research/phase5e/dom.test.mjs
& $py $g --metrics "$d/python-tests-resources.json" -- $py -m unittest discover -s research/phase5e -p 'test*.py'
npm audit --prefix research/phase5e --omit=dev
```
