# Phase 3B phishing URL research

The [PhiUSIIL experiment report](../docs/experiments/phiusiil/README.md) records four models trained and scored on the frozen retrospective holdout. The preflight below still runs independently of training. The experiment leaves the product and production training gate unchanged.

The [Phase 3C cross-dataset report](../docs/experiments/phase3c/README.md) covers frozen model transfer, matched-budget experiments, feature expansion, fusion and browser measurements.

The [Phase 3D laptop-bounded report](../docs/experiments/phase3d/README.md) records a new chronological holdout, training through 100,000 URLs, feature ablation, fusion, and measured resource limits.

The [Phase 3E financial validation report](../docs/experiments/phase3e/README.md) records the frozen-model comparison, eligible Indian financial controls, and the remaining evidence required to evaluate phishing recall.

The [Phase 3F acquisition and validation report](../docs/experiments/phase3f/README.md) records a licensed historical transfer test, new independent Indian financial controls, and the evidence still required for financial phishing validation.

The [Phase 3G failure analysis](../docs/experiments/phase3g/README.md) checks frozen model decisions and score transfer. Use the [financial data validator](../docs/experiments/phase3g/validator.md) to review new authorized inputs offline.

This environment prepares unfitted Logistic Regression, Random Forest, CPU XGBoost, and a small MLP. Logistic Regression and MLP package scaling inside their estimator pipelines. All candidates use a fixed seed, and both tree ensembles use one worker. The preflight verifies constructor and input compatibility. It performs no fit, evaluation, model serialization, or deployment.

## Reproduce the environment

Run from the repository root on Windows x86-64 with CPython 3.11. The lock includes hashes for all resolved CPU wheels. XGBoost on Windows requires the Microsoft Visual C++ runtime. [XGBoost installation guide](https://xgboost.readthedocs.io/en/stable/install.html)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --index-url https://pypi.org/simple --only-binary=:all: --require-hashes -r research/requirements-win-x64-py311.lock
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -s research
.\.venv\Scripts\python.exe research/preflight.py
```

## Verify the Phase 3A feature contract

Use the Phase 3A exporter with its pinned manifest. It assigns the chronological, registrable-domain-disjoint splits before writing a vector. The preflight validates the 14-element `url-lexical-v1` vector, counts labels within their assigned splits, and does not create a new split or retain raw destinations. Bare feature rows contain no domain identity and cannot prove their own domain-disjoint provenance. Keep the corresponding inputs, manifest, and aggregate report together in private storage.

```powershell
npm ci --prefix evaluation --ignore-scripts
$researchTemp = Join-Path ([IO.Path]::GetTempPath()) ('threat-research-' + [guid]::NewGuid())
New-Item -ItemType Directory $researchTemp | Out-Null
$features = Join-Path $researchTemp 'synthetic-features.jsonl'
$report = Join-Path $researchTemp 'synthetic-report.json'
node evaluation/run.mjs --manifest evaluation/manifests/synthetic.json --input-dir evaluation/fixtures --features $features --report $report
.\.venv\Scripts\python.exe research/preflight.py --features $features
```

## Production training gate

The Phase 3A **NO-GO for production training** still applies. The authorized PhiUSIIL experiment is a retrospective, single-corpus benchmark. Obtain dated, independently adjudicated Indian financial positives and hard negatives with training rights, plus frozen independent reputation snapshots. Reserve future test partitions for final evaluation. [Phase 3A evaluation and gate](../docs/dataset-evaluation.md)
