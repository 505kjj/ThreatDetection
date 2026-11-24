# Phase 5B runner

Run with the pinned CPython 3.11 environment and private inputs:

```powershell
$py = 'C:\Users\kj\threat-detection-experiments\phase-5b-v1\venv\Scripts\python.exe'
& $py -m unittest discover -s research/phase5b -p 'test*.py'
& $py research/phase5b/train.py `
  --uci 'C:\Users\kj\threat-detection-experiments\phiusiil-v1\dataset' `
  --phresh 'C:\Users\kj\threat-detection-experiments\phase-3d-v1\phresh' `
  --output 'C:\Users\kj\threat-detection-experiments\phase-5b-v1\rerun'
```

The output directory must not already exist and must remain outside the Git
checkout. Training uses the common `url-lexical-v1` feature schema and Phase 3D
model configurations. The Phase 3D Job Object resource monitor is not invoked by
this script; this run limits numerical threads but does not measure or cap peak
memory. Do not increase sample sizes until the runner is wrapped by that guard.
