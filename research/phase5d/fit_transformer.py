"""Fit a single guarded Transformer with fixed inputs and a private checkpoint."""

import argparse
from hashlib import sha256
import json
import os
from time import perf_counter

import numpy as np
import torch

from shared import PHASE5C, balanced, ids_sha256, labels, load_partition, private, protocol_bytes
from transformer import BATCH, DEPTH, HEADS, LENGTH, WIDTH, fit, inputs, predict, restore


def run(cohort, output, size, preset):
    manifest_bytes = (cohort / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    version = manifest["version"]
    if version not in {"phase5c-development-v1", "phase5d-temporal-v1"}:
        raise ValueError("Unknown experiment manifest")
    if version == "phase5d-temporal-v1" and manifest["protocolSha256"] != sha256(protocol_bytes()).hexdigest():
        raise ValueError("Temporal protocol changed after freeze")
    phase5c = json.loads(PHASE5C.read_bytes())
    manifest_hash = sha256(manifest_bytes).hexdigest()
    if version.startswith("phase5c") and manifest_hash != phase5c["20000"][0]["cohortSha256"]:
        raise ValueError("Phase 5C manifest changed")
    pool = load_partition(cohort, manifest, "train")
    capacity = 2 * min(sum(row["label"] == label for row in pool) for label in (0, 1))
    if size == 70570 and capacity != size:
        raise ValueError("Exact balanced capacity changed")
    train_rows = balanced(pool, size)
    fingerprint = ids_sha256(train_rows)
    if version.startswith("phase5c") and str(size) in phase5c:
        if fingerprint != phase5c[str(size)][0]["trainIdsSha256"]:
            raise ValueError("Phase 5C sample membership changed")
    tuning = load_partition(cohort, manifest, "tuning")[:1000 if size == 1000 else 4096]
    if len(set(labels(tuning))) != 2:
        raise ValueError("Early stopping requires both development labels")
    output.mkdir(mode=0o700)
    torch.set_num_threads(2)
    torch.set_num_interop_threads(1)
    train_x, train_y = inputs(train_rows), labels(train_rows)
    tune_x, tune_y = inputs(tuning), labels(tuning)
    if size == 1000 and preset is None:
        rates, epochs = (0.001, 0.003), 2
    else:
        if preset is None:
            raise ValueError("Complete the preflight before scaling")
        preflight = json.loads(preset.read_bytes())
        if preflight["trainRows"] != 1000 or preflight["version"] != "phase5c-development-v1":
            raise ValueError("Preflight receipt differs")
        rates, epochs = (preflight["learningRate"],), 5
    trials = []
    winner = None
    best_score = -1.0
    fit_start = perf_counter()
    for rate in rates:
        start = perf_counter()
        model, trial = fit(train_x, train_y, tune_x, tune_y, rate, epochs)
        trials.append(trial | {"fitSeconds": perf_counter() - start})
        if trial["selectionScore"] > best_score:
            winner, best_score = model, trial["selectionScore"]
            best_trial = trial
    elapsed = perf_counter() - fit_start
    checkpoint = output / "model.pt"
    torch.save(winner.state_dict(), checkpoint)
    loaded = restore(checkpoint)
    np.testing.assert_array_equal(predict(winner, train_x[:8]), predict(loaded, train_x[:8]))
    report = {"version": version, "cohortSha256": manifest_hash, "trainRows": size,
              "trainIdsSha256": fingerprint, "tuningRows": len(tuning), "tuningIdsSha256": ids_sha256(tuning),
              "capacity": capacity, "trials": trials, "fitSeconds": elapsed, **best_trial,
              "modelSha256": sha256(checkpoint.read_bytes()).hexdigest(), "modelBytes": checkpoint.stat().st_size,
              "parameters": sum(param.numel() for param in winner.parameters()),
              "sequenceLength": LENGTH, "heads": HEADS, "layers": DEPTH, "width": WIDTH, "batchSize": BATCH}
    (output / "fit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("trainRows", "learningRate", "fitSeconds", "bestEpoch", "parameters")}),
          flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=private)
    parser.add_argument("output", type=private)
    parser.add_argument("size", type=int, choices=(1000, 20000, 50000, 70570))
    parser.add_argument("--preset", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
