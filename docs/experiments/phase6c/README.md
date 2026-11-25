# Phase 6C browser inference research

Status is an initial prototype. Production ML warnings, blocking and shadow testing remain NO-GO. Independent validation remains incomplete. The prototype is an isolated extension fixture and is not connected to product navigation or telemetry.

## Frozen character TF-IDF and logistic regression

The exporter checks the Phase 5C 20,000-row checkpoint against the Phase 5E receipt before loading it. It writes the existing vocabulary, IDF values, coefficients, intercept and operating thresholds to a private JSON file. It performs no fitting. The browser scorer implements character n-grams of lengths 2–5, sublinear term frequency and L2 normalization. The private converted file is 4,554,994 bytes, compared with the 1,611,706-byte compressed source artifact. It can contain derived training information and must remain outside Git.

The tolerance was specified as an absolute score difference of `1e-10` before running the browser comparison. On ten synthetic, already-normalized strings, including a punycode hostname, escaped path, repeated characters and a port, the maximum difference from the frozen Python pipeline was `1.67e-16`. Decisions agreed at each non-null frozen operating point. This checks the classifier on those strings, not browser URL extraction or real-world accuracy. Input normalization and broader parity remain open.

Chromium 159.0.8154.6 loaded a locally bundled model in a Manifest V3 service worker using the default extension CSP and no permissions. Three concurrent requests processed 3,000 synthetic strings. The observed median was below the browser timer resolution and p95 was 0.2 ms per model call. Initial model fetch, parse and scorer construction took 66.7 ms. A stopped service worker restarted and reproduced the same outputs. The Windows resource guard reported two logical CPUs, 1.92 seconds wall time, 2.88 CPU seconds and 507,633,664 bytes peak job commit for the complete Chromium test. This peak covers Chromium processes and the harness. It is not model-only memory. The run does not establish stable memory use over prolonged operation, cold-start distribution or end-to-end latency.

A second guarded run measured 95.8 ms initialization and 0.2 ms p95. Invalid input returned an error and a subsequent valid request succeeded. The test blocked HTTP(S) page requests and observed none. Service-worker network activity has not yet been independently instrumented. The worker source fetches its model from the local extension package.

The research URL extractor reuses the product canonicalizer and public-suffix parser. Eleven synthetic and malformed inputs matched the frozen numerical feature extractor in Node, and six of those cases also matched in Chromium. The fixtures include Unicode, punycode, escaped paths, credentials, query and fragment removal, ports and unsupported schemes. These are preliminary fixtures, and end-to-end processing time has not been benchmarked.

## Frozen XGBoost tree scoring

The numerical URL checkpoint and Phase 5F weighted DOM checkpoint were checksum-verified and converted to JSON trees in private storage. The converted files measured 90,950 and 178,192 bytes respectively. On 12 synthetic numerical vectors per model, the maximum browser-to-Python score differences were `3.88e-8` and `7.08e-8`, within the `2e-6` tolerance set before testing. All published non-null URL operating-point decisions agreed. The DOM checkpoint has no independent operating points in this receipt, so its threshold decisions were not tested. These vectors test scoring and do not establish DOM extraction parity. The guarded Chromium run peaked at 523,620,352 bytes of job commit across the entire test, with 2 logical CPUs and 3.20 CPU seconds. It did not benchmark tree latency or prolonged memory use.

## Reproduction

From the repository root, use the established private Python environment, Playwright installation and a fresh output directory outside Git. The export and browser runner create new files and do not overwrite their outputs.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$env:PYTHONPATH = "$p/phase-3c-v1/packages"
$out = "$p/phase-6c-rerun"
New-Item -ItemType Directory $out
& $py research/phase3d/resource_guard.py --metrics "$out/export-resources.json" -- $py research/phase6c/export_ngram.py $p "$out/ngram"
& $py research/phase3d/resource_guard.py --metrics "$out/xgboost-export-resources.json" -- $py research/phase6c/export_xgboost.py $p "$out/xgboost"
& $py research/phase3d/resource_guard.py --metrics "$out/browser-resources.json" -- node research/phase6c/browser.cjs $out
node --test research/phase6c/ngram.test.mjs
```

Set `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` to the existing local Playwright and Chromium installation as described in the extension regression instructions. The experiment directory holds the converted checkpoint, synthetic references, browser profile and measurement receipts. It should be access-controlled and kept outside the repository.

## Remaining work

- Expand numerical XGBoost and weighted DOM scorer parity. Implement and compare the Phase 5D ensemble, Phase 5F fixed fusion, CNN and Transformer against their frozen Python outputs.
- Expand URL feature parity coverage and validate the frozen DOM feature definitions in the browser. Cover delayed DOM changes, cross-origin frames and unavailable evidence without collecting field values.
- Evaluate implementation and licensing options, including WebAssembly and ONNX Runtime Web, when required by a candidate. Measure end-to-end latency, initialization distributions, CPU, model-only memory and repeated-run memory growth under the resource guard.
- Add reviewed aggregate results to the existing research dashboard only after the measurements and scope are complete. Run the requested full regression and frozen-integrity checks on the final branch.
- Identify preferred candidates only after their comparable parity, performance and independent-validation limitations are documented.
