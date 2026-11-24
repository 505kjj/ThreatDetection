# Phase 5D offline research runner

Use the existing CPython 3.11.9 Phase 5B environment, CPU PyTorch 2.6.0,
NumPy 2.4.6, scikit-learn 1.9.1, XGBoost 3.2.0, SciPy 1.17.1,
joblib 1.6.0, Node.js 24 and the verified Phase 5C private experiment directory.
These commands run from the Phase 5D worktree.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$old = "$p/phase-5c-v1"
$d = "$p/phase-5d-rerun"
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$guard = 'research/phase3d/resource_guard.py'
New-Item -ItemType Directory $d

& $py $guard --metrics "$d/transformer-1000-resources.json" -- $py research/phase5d/fit_transformer.py "$old/cohort" "$d/transformer-1000" 1000
if ($LASTEXITCODE) { throw 'Transformer preflight failed' }

foreach ($size in @(20000, 50000, 70570)) {
  & $py $guard --metrics "$d/transformer-$size-resources.json" -- $py research/phase5d/fit_transformer.py "$old/cohort" "$d/transformer-$size" $size --preset "$d/transformer-1000/fit.json"
  if ($LASTEXITCODE) { throw 'Matched Transformer fit failed' }
}

& $py $guard --metrics "$d/prepare-resources.json" -- node --max-old-space-size=3072 research/phase5d/prepare.mjs $old "$d/prepared"
if ($LASTEXITCODE) { throw 'Data validation or cohort preparation failed' }

$temporal = "$d/prepared/temporal"
& $py $guard --metrics "$d/temporal-transformer-resources.json" -- $py research/phase5d/fit_transformer.py $temporal "$d/temporal-transformer" 20000 --preset "$d/transformer-1000/fit.json"
if ($LASTEXITCODE) { throw 'Temporal Transformer fit failed' }

foreach ($model in @('ngram', 'cnn', 'xgboost')) {
  & $py $guard --metrics "$d/temporal-$model-resources.json" -- $py research/phase5d/fit_baselines.py $model $temporal "$d/temporal-$model"
  if ($LASTEXITCODE) { throw 'Temporal baseline fit failed' }
}

& $py $guard --metrics "$d/mixed-resources.json" -- $py research/phase5d/fit_baselines.py mixed "$old/cohort" "$d/mixed" --auxiliary "$d/prepared/auxiliary"
if ($LASTEXITCODE) { throw 'Source-balanced fit failed' }

& $py $guard --metrics "$d/evaluation-resources.json" -- $py research/phase5d/evaluate.py $old $d
```

The data prep worker validates the canonical hashes, public shard pins,
private development projections, eligible membership and recorded
test exclusions. It writes checksummed temporal and auxiliary views.
The temporal training workers open training and tuning data. The
scoring worker records its frozen thresholds and checkpoint hashes
before opening the two chronological evaluation windows.

Every checkpoint and row-level artifact is private. `results.json`
contains aggregate metrics and cohort digests. The
[experiment report](../../docs/experiments/phase5d/README.md) describes the
protocol and interpretation.

## Tests

```powershell
node --test --test-concurrency=1 research/phase5d/prepare.test.mjs
& $py -m unittest discover -s research/phase5d -p 'test*.py'
```
