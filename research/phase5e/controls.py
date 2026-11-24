"""Replay fabricated controls through the guarded parser and local DOM checkpoint."""

import argparse
import json
import os
import subprocess
from time import perf_counter

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from acquire import HtmlWorker, ROOT, digest, private
from compare import FEATURES, model_input


def run(model_directory, destination):
    metrics = json.loads((model_directory / "results.json").read_bytes())["models"]["dom-xgboost"]
    checkpoint = model_directory / "dom-xgboost" / "model.joblib"
    if digest(checkpoint) != metrics["fit"]["modelSha256"]:
        raise ValueError("DOM checkpoint checksum differs")
    fixtures = json.loads(subprocess.check_output([
        "node", "--input-type=module", "-e",
        "import {FIXTURES,ORIGIN} from './research/phase5e/fixtures.mjs'; "
        "console.log(JSON.stringify({fixtures:FIXTURES,origin:ORIGIN}))"
    ], cwd=ROOT, encoding="utf-8"))
    model = joblib.load(checkpoint)
    cases = list(fixtures["fixtures"].items())
    cases.append(("dynamic-login-materialized", fixtures["fixtures"]["dynamic-login"].replace(
        "</main>", '<form><input type="password"></form></main>')))
    results = {}
    milliseconds = []
    with HtmlWorker() as worker, threadpool_limits(limits=2):
        for i in range(320):
            name, html = cases[i % len(cases)]
            start = perf_counter()
            report = worker.analyze(name, html, fixtures["origin"] + "/" + name)
            if report["status"] != "usable":
                raise ValueError("Fabricated control failed HTML preprocessing")
            value = float(model.predict_proba(model_input([{"dom": report["features"]}], FEATURES))[0, 1])
            elapsed = (perf_counter() - start) * 1000
            if i >= 20:
                milliseconds.append(elapsed)
            results[name] = {"score": value, "atHalf": value >= 0.5, "atConstraints": {
                key: None if entry["threshold"] is None else value >= entry["threshold"]
                for key, entry in metrics["thresholds"].items()
            }}
    output = {"modelSha256": digest(checkpoint), "fabricatedControls": results, "examples": len(milliseconds),
              "endToEndMedianMs": float(np.median(milliseconds)),
              "endToEndP95Ms": float(np.percentile(milliseconds, 95))}
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2, allow_nan=False)
    print(f"Replayed {len(cases)} synthetic control cases through {len(milliseconds)} timed analyses")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_directory", type=private)
    parser.add_argument("destination", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
