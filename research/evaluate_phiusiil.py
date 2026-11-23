"""Open the preserved holdout once, after all models and cutoffs have been frozen."""

import argparse
from datetime import datetime, timezone
from time import perf_counter_ns

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from experiment_data import REPO, identity, load_partition, private_path, read_json, read_manifest, sha256, write_json
from experiment_metrics import classify, ranking


MODELS = {"logistic_regression", "random_forest", "xgboost", "mlp"}


def claim_holdout(output, freeze_hash):
    write_json(output / "holdout-opened.json", {
        "frozenSha256": freeze_hash, "openedAt": datetime.now(timezone.utc).isoformat(),
    })


def measure_latency(estimator, features):
    if "n_jobs" in estimator.get_params():
        estimator.set_params(n_jobs=1)
    for _ in range(12):
        estimator.predict_proba(features[:1])
    calls = []
    for index in range(256):
        started = perf_counter_ns()
        estimator.predict_proba(features[index:index + 1])
        calls.append((perf_counter_ns() - started) / 1000)
    samples = []
    for _ in range(16):
        started = perf_counter_ns()
        estimator.predict_proba(features)
        samples.append((perf_counter_ns() - started) / (1000 * len(features)))
    return {"singleP50Microseconds": float(np.median(calls)), "singleP95Microseconds": float(np.percentile(calls, 95)),
            "batchSize": len(features), "batchP50MicrosecondsPerRow": float(np.median(samples)), "inferenceThreads": 1}


def evaluate(development, holdout, output):
    development, holdout, output = map(private_path, (development, holdout, output))
    if (output / "holdout-opened.json").exists():
        raise FileExistsError("This frozen run has already opened the holdout.")
    frozen_path = output / "frozen.json"
    frozen = read_json(frozen_path)
    freeze_hash = sha256(frozen_path)
    report_file = output / "development-report.json"
    group_file = output / "development-groups.txt"
    if (sha256(report_file) != frozen["developmentReportSha256"]
            or sha256(group_file) != frozen["developmentGroupsSha256"]
            or sha256(REPO / "research/phiusiil-experiment.json") != frozen["configSha256"]
            or set(frozen["models"]) != MODELS):
        raise ValueError("Frozen experiment artifacts have changed.")
    dev_report = read_json(report_file)
    dev_manifest = read_manifest(development)
    if identity(dev_manifest) != frozen["dataset"] or dev_manifest["validation"] != dev_report["calibrationPartition"]:
        raise ValueError("Development data does not match the frozen run.")
    calibration = load_partition(development, dev_manifest, "validation")
    columns = dev_manifest["featureColumns"]
    indices = [columns.index(name) for name in frozen["usedFeatures"]]
    latency_features = calibration.features[:1024, indices]
    estimators, latencies = {}, {}
    with threadpool_limits(limits=1):
        for name, model in frozen["models"].items():
            if model["file"] != f"{name}.joblib":
                raise ValueError("Unexpected frozen model filename.")
            path = output / model["file"]
            if sha256(path) != model["sha256"] or path.stat().st_size != model["bytes"]:
                raise ValueError("Frozen model checksum differs.")
            # Only load this experiment's locally generated, checksum-verified objects.
            estimator = joblib.load(path)
            estimators[name] = estimator
            latencies[name] = measure_latency(estimator, latency_features)

        claim_holdout(output, freeze_hash)
        manifest = read_manifest(holdout)
        if identity(manifest) != frozen["dataset"]:
            raise ValueError("Holdout does not match the frozen data identity.")
        test = load_partition(holdout, manifest, "test")
        development_groups = set(group_file.read_text(encoding="ascii").splitlines())
        if development_groups.intersection(test.groups):
            raise ValueError("The holdout contains development domains.")
        results = {}
        for name, estimator in estimators.items():
            # One predictive pass per model. All thresholds reuse this score array.
            scores = estimator.predict_proba(test.features[:, indices])[:, 1]
            strict = []
            for policy in frozen["models"][name]["thresholds"]:
                cutoff = policy["threshold"]
                strict.append({"calibration": policy, "holdout": None if cutoff is None else
                               classify(test.labels, scores, test.groups, cutoff)})
            results[name] = {
                **ranking(test.labels, scores),
                "default": classify(test.labels, scores, test.groups, 0.5),
                "strict": strict, "modelOnlyLatency": latencies[name],
            }
            print(f"Scored {name} once on the frozen holdout.", flush=True)
    baseline = read_json(REPO / "evaluation/reports/phiusiil-uci-967.json")["retrospectiveDomainDisjoint"]["test"]
    write_json(output / "holdout-report.json", {
        "dataset": frozen["dataset"], "holdout": manifest["test"], "frozenSha256": freeze_hash,
        "preselectedChampion": frozen["preselectedChampion"], "artifacts": frozen["models"], "metrics": results,
        "baseline": {name: baseline[name] for name in ("reputation", "impersonation", "combined")},
    })


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--development-dir", required=True)
    cli.add_argument("--holdout-dir", required=True)
    cli.add_argument("--model-dir", required=True)
    args = cli.parse_args()
    evaluate(args.development_dir, args.holdout_dir, args.model_dir)
