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

## Fusion and sequence models

The Phase 5D URL ensemble and Phase 5F fixed 75:25 fusion apply their frozen clipped-logit calibration and weights. Ten synthetic score pairs matched the Python calculations with maximum absolute differences of `1.14e-8` and `3.99e-8` respectively, within the predeclared `2e-6` tolerance. Decisions agreed at all published non-null operating points for these fixtures. The DOM vectors in this comparison are synthetic numerical inputs. The grouped Phase 5F n-gram model is a separate checkpoint and its converted file is 4,564,030 bytes.

The CNN and Transformer were exported from checksum-verified checkpoints to fixed batch-size-one ONNX files. The Transformer exporter required disabling PyTorch's fused attention fast path, which ONNX export did not support. The reference scores use the original Python fast path. Chromium with locally bundled ONNX Runtime Web 1.23.2 and WebAssembly matched ten synthetic inputs per model within a predeclared `1e-5` tolerance. Token IDs matched Python and all published non-null threshold decisions agreed for these fixtures. The ONNX Runtime Web package declares an MIT license. Its three runtime files total 11,975,718 bytes, separate from model sizes. The extension fixture permits local WebAssembly through `wasm-unsafe-eval` and uses no extension permissions. No remote runtime is loaded. Neural inference was tested on an extension page, and service-worker execution remains unverified.

| Candidate | Private converted model bytes | Synthetic browser model-call p95 | Maximum score error | Scope |
| --- | ---: | ---: | ---: | --- |
| Phase 5C character TF-IDF | 4,554,994 | 0.1 ms | 1.67e-16 | 10 strings |
| Phase 5C numerical XGBoost | 90,950 | 0.1 ms | 3.88e-8 | 12 vectors |
| Phase 5D URL ensemble | 4,645,944 | 0.1 ms | 1.14e-8 | 10 pairs |
| Phase 5F weighted DOM XGBoost | 178,192 | 0.1 ms | 7.08e-8 | 12 vectors |
| Phase 5F fixed fusion | 4,742,222 | 0.2 ms | 3.99e-8 | 10 pairs |
| Phase 5C CNN | 30,042 | 0.3 ms | 7.22e-8 | 10 strings; runtime separate |
| Phase 5D Transformer | 94,586 | 2.3 ms | 3.43e-8 | 10 strings; runtime separate |

Tree and fusion timings use 1,000 model calls per candidate in the guarded Chromium run. Neural timings use 100 calls after warm-up. The browser timer reports 0 ms medians for the JavaScript candidates. The neural run measured 432.7 ms CNN initialization and 87.1 ms Transformer initialization after the runtime was already loaded. Its whole-job peak was 721,575,936 bytes with 2 logical CPUs and 3.94 CPU seconds. These timings exclude URL and DOM collection, messaging and extension startup. They do not establish a p95 for complete URL+DOM processing or sustained memory stability.

The Phase 5E browser fixture rechecked seven inert synthetic documents against the frozen DOM parser and included a delayed form. Cross-origin frames and capture failures still need focused testing. The extractor reads structural attributes and title text for local features. It does not read field values, passwords, OTPs, cookies or screenshots.

For continued research the Phase 5C character TF-IDF model is the leading URL candidate on the combination of this preliminary browser parity and the earlier Phase 5D retrospective PhreshPhish validation. At the separate 1% domain-FPR calibration target, that validation reported recall 0.823 and observed domain FPR 0.00749 at score 0.74445. The lighter numerical XGBoost reported recall 0.576 and observed domain FPR 0.00585 at score 0.92664 on the same validation cohort. These are retrospective results with different observed operating points. Phase 5F fixed fusion is the multimodal candidate for further technical work. Neither is independently validated or approved for production.

## Reproduction

From the repository root, use the established private Python environment, Playwright installation and a fresh output directory outside Git. The export and browser runner create new files and do not overwrite their outputs.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$env:PYTHONPATH = "$p/phase-3c-v1/packages"
$out = "$p/phase-6c-rerun"
New-Item -ItemType Directory $out
& $py research/phase3d/resource_guard.py --metrics "$out/export-resources.json" -- $py research/phase6c/export_ngram.py $p "$out/ngram"
& $py research/phase3d/resource_guard.py --metrics "$out/grouped-export-resources.json" -- $py research/phase6c/export_ngram.py $p "$out/ngram-f" --candidate phase5f
& $py research/phase3d/resource_guard.py --metrics "$out/xgboost-export-resources.json" -- $py research/phase6c/export_xgboost.py $p "$out/xgboost"
& $py research/phase3d/resource_guard.py --metrics "$out/fusion-resources.json" -- $py research/phase6c/export_fusion.py $out
& $py research/phase3d/resource_guard.py --metrics "$out/browser-resources.json" -- node research/phase6c/browser.cjs $out
$env:PYTHONPATH = "$p/phase-3c-v1/packages;$p/phase-6a-v1/browser-python"
& $py research/phase3d/resource_guard.py --metrics "$out/neural-export-resources.json" -- $py research/phase6c/export_neural.py $p "$out/neural"
$runtime = "$p/phase-6a-v1/browser-packages/node_modules/onnxruntime-web/dist"
& $py research/phase3d/resource_guard.py --metrics "$out/neural-resources.json" -- node research/phase6c/neural-browser.cjs $out $runtime
node --test research/phase6c/*.test.mjs
```

Set `NODE_PATH` and `PLAYWRIGHT_BROWSERS_PATH` to the existing local Playwright and Chromium installation as described in the extension regression instructions. The neural export uses the existing private ONNX Python installation in `phase-6a-v1/browser-python`. The experiment directory holds the converted checkpoints, synthetic references, browser profiles and measurement receipts. It should be access-controlled and kept outside the repository.

The dashboard aggregate is generated from `browser-summary.json` by `node scripts/project-monitor-research.mjs`. It contains only the synthetic measurements and limitations above. Maven verification passed 62 tests, the extension unit suite passed 29 tests, the Phase 6C Node suite passed four tests, and the direct Chromium smoke with responsive matrix passed after the dashboard change. Python exporters compiled and ran under the guard. The Phase 6B receipt checker passed 54 checks, with grouped membership digests outside that check. The secure Windows smoke passed on the Phase 6B base and needs a repeat on the final Phase 6C head.

## Remaining work

- Expand model and fusion parity beyond the small synthetic sample, including near-threshold cases and complete browser feature pipelines.
- Expand URL feature parity coverage and validate the frozen DOM feature definitions in the browser. Cover delayed DOM changes, cross-origin frames and unavailable evidence without collecting field values.
- Evaluate native JavaScript, typed-array and WebAssembly tradeoffs further. Measure end-to-end latency, initialization distributions, CPU, model-only memory and repeated-run memory growth under the resource guard.
- Add reviewed aggregate results to the existing research dashboard only after the measurements and scope are complete. Run the requested full regression and frozen-integrity checks on the final branch.
- Identify preferred candidates only after their comparable parity, performance and independent-validation limitations are documented.
