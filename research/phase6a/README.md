# Phase 6A offline visual lab

From this worktree, make the pinned Phase 4C commit available locally. Keep the existing Phase 5G candidate and feature files intact. The domain reader checks the Git blob hash before loading the registry. Use the pinned Phase 5B CPython 3.11 / Torch 2.6.0 CPU environment. Install the Phase 6A packages in private storage outside all Git worktrees.

```powershell
$experiments = 'C:/Users/kj/threat-detection-experiments'
$p = "$experiments/phase-6a-v1"
$py = "$experiments/phase-5b-v1/venv/Scripts/python.exe"
$guard = 'research/phase3d/resource_guard.py'
git fetch origin feature/phase-4c-financial-login-protection
& $py -m pip install --no-deps --target "$p/packages" -r research/phase6a/requirements-win.txt
$env:PYTHONPATH = "$p/packages"
$env:HF_HUB_OFFLINE = '1'
$env:HF_HUB_DISABLE_TELEMETRY = '1'
```

Place the checksum-pinned PNG renditions from [assets.json](assets.json) and `mobilenetv3-small.safetensors` in the private source directory. Use the [revision-pinned model file](https://huggingface.co/timm/mobilenetv3_small_100.lamb_in1k/blob/76b303ec28c466e9df37f4745dfb7aef20ab87ae/model.safetensors). The loader enforces the SHA-256 in [vision.py](vision.py), checks reference bytes before decoding and loads no remote assets. Output paths must be new and outside Git.

```powershell
& $py $guard --metrics "$p/visual-rerun-resources.json" -- $py research/phase6a/run.py $p "$p/visual-rerun"
& $py $guard --metrics "$p/tests-rerun-resources.json" -- $py -m unittest discover -s research/phase6a -p 'test*.py'
```

For the optional browser test, add the isolated ONNX Python and JavaScript runtimes. Set the Playwright environment paths to a private package install containing Playwright 1.65.1 and its matching Chromium. `--export-browser` exports the classifier-free graph, invented raster fixtures and vectors into private storage. The browser loader copies only those fictional fixtures, the graph, and local WASM assets into its disposable extension.

```powershell
& $py -m pip install --no-deps --target "$p/browser-python" onnx==1.19.1 protobuf==6.33.5 ml-dtypes==0.5.4
npm install --prefix "$p/browser-packages" --no-save --ignore-scripts onnxruntime-web@1.23.2
$env:PYTHONPATH = "$p/packages;$p/browser-python"
& $py $guard --metrics "$p/export-rerun-resources.json" -- $py research/phase6a/run.py $p "$p/export-rerun" --export-browser
& $py $guard --metrics "$p/browser-rerun-resources.json" -- node research/phase6a/browser.mjs "$p/export-rerun" "$p/browser-packages/node_modules/onnxruntime-web/dist" "$p/browser-rerun.json"
```

Publish only reviewed result and resource receipts. Raw images, reference embeddings, model weights, ONNX, browser assets and synthetic input files stay private. [Phase 6A report](../../docs/experiments/phase6a/README.md)
