# Phase 5C offline URL experiments

The runner compares numerical logistic regression, random forest and XGBoost,
character TF-IDF logistic regression and a character CNN. Each worker loads
the same checksummed canonical partitions and uses stable record IDs to verify
matched model comparisons.

## Environment

Use CPython 3.11 with the existing Phase 5B numerical dependencies, CPU
PyTorch 2.6.0 and the Phase 3C PyArrow 21.0.0 projection dependencies.
Node.js 24 uses the existing evaluation dependency lock. Run
`npm ci --prefix evaluation` if `csv-parse` is missing.

The commands use PowerShell from the Phase 5C checkout. Supply the existing
private Phase 3C–5B exports and choose a new directory under the private
experiment root.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$d = "$p/phase-5c-v1"
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$env:PYTHONPATH = "$p/phase-3c-v1/packages"
$guard = 'research/phase3d/resource_guard.py'
New-Item -ItemType Directory $d
Invoke-WebRequest -Uri 'https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip' -OutFile "$d/uci.zip"
& $py $guard --metrics "$d/acquire-train.json" -- $py research/phase5c/acquire.py train "$d/phresh-development"
& $py $guard --metrics "$d/acquire-custody.json" -- $py research/phase5c/acquire.py test "$d/phresh-custody"
& $py $guard --metrics "$d/uci.json" -- $py research/phase5c/uci.py "$d/uci.zip" "$p/phiusiil-v1/dataset/development" "$d/uci-development.jsonl"
& $py $guard --metrics "$d/history.json" -- node research/phase5c/custody.mjs history "$d/history.jsonl" "$p/phiusiil-v1/dataset" "$p/phase-3c-v1/phresh" "$p/phase-3d-v1/phresh" "$p/phase-3e-v1/official-cohort/numeric.jsonl" "$p/phase-3f-v1/cohort/numeric.jsonl"
& $py $guard --metrics "$d/replay-custody.json" -- node research/phase5c/custody.mjs replay "$d/replay-exclusions.jsonl" "$p/phiusiil-v1/dataset" "$p/phase-3c-v1/phresh" "$p/phase-3d-v1/phresh"
$replayPin = (Get-FileHash "$d/replay-exclusions.jsonl").Hash.ToLower()
& $py $guard --metrics "$d/replay.json" -- node --max-old-space-size=3072 research/phase5c/recover.mjs "$d/phresh-development" "$d/replay-exclusions.jsonl" $replayPin "$p/phase-5b-v1/run-1/manifest.json" "$d/recovered"
& $py $guard --metrics "$d/membership-resources.json" -- $py research/phase5c/membership.py "$d/uci-development.jsonl" "$p/phiusiil-v1/dataset/development" "$d/recovered" "$p/phase-3d-v1/phresh" "$p/phase-5b-v1/run-1/manifest.json" "$d/phresh-custody" "$d/membership.json"
& $py $guard --metrics "$d/financial-resources.json" -- node research/phase5c/financial.mjs "$d/phresh-development"
```

Keep the source archives and custody workspace private. The PhreshPhish
custody process projects only publisher IDs and URLs and exports hashes.
The UCI publisher distributes a single CSV archive. The separated UCI
worker checks the archive and CSV hashes, assigns the legacy
domain partition and skips holdout rows before examining their labels.
Use the checksum-verified development output as the input to the modeling
stage. The historical reader verifies the earlier numeric exports and
collects only domain and lexical-family keys from them.

## Preparation and training

```powershell
$historyPin = (Get-FileHash "$d/history.jsonl").Hash.ToLower()
$uciPin = (Get-FileHash "$d/uci-development.jsonl").Hash.ToLower()
& $py $guard --metrics "$d/prepare.json" -- node --max-old-space-size=3072 research/phase5c/cohort.mjs "$d/phresh-development" "$d/phresh-custody" "$d/history.jsonl" $historyPin "$d/uci-development.jsonl" $uciPin "$d/cohort"
& $py research/phase5c/run.py "$d/cohort" 1000 "$d/preflight"
& $py research/phase5c/run.py "$d/cohort" 20000 "$d/scale-20000"
& $py research/phase5c/run.py "$d/cohort" 50000 "$d/scale-50000"
```

Complete the preflight before advancing to 20,000 rows. Use the smaller
training class to calculate balanced capacity before attempting a larger
scale. Each model runs in a separate Windows Job Object with two logical
CPUs. The per-model resource file reports whole-worker-tree peak committed
bytes and wall time. The fit timer measures model fitting with inputs
already prepared. The CNN timer includes tuning predictions for early
stopping. The runner verifies checkpoint scoring after reload.

The canonical row contains a stable source-derived ID, original and
normalized URLs, source and revision, label, domain and alias digests,
nullable campaign, collection date, target and language, partition and
the existing numerical vector. `sequence.represent` provides separate
numerical, n-gram, CNN and future Transformer inputs with the same record
ID and partition. Model text omits credentials, query strings and
fragments. Raw URLs, checkpoints and row-level receipts stay outside Git.

The CNN uses 95 printable ASCII characters, an unknown token and a
padding token. It keeps the first 160 characters, right-pads shorter
inputs, embeds tokens into 16 dimensions and uses parallel width-3, -5
and -7 convolutions with 16 filters each. It masks padding windows before
global max pooling and applies 0.2 dropout before the binary head.
Tuning average precision drives early stopping with patience two and at
most eight epochs. The validation partition is separate from both tuning
and low-FPR calibration.

## Tests

```powershell
node --test research/phase5c/cohort.test.mjs
& $py -m unittest discover -s research/phase5c -p 'test*.py'
```

Run receipts and aggregate results are described in the
[Phase 5C experiment report](../../docs/experiments/phase5c/README.md).
