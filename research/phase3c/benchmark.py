"""Compare frozen and bounded CPU experiments on the independent dated projection."""

import argparse
from hashlib import sha256
import io
from itertools import combinations
import platform
from statistics import median
import sys
from pathlib import Path
import time
import tracemalloc

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiment_data import load_partition, private_path, read_json, read_manifest, sha256 as file_hash, write_json
from experiment_metrics import classify, negative_domain_scores, ranking, threshold_at_target


SEED = 137
HOST = [2, 3, 4, 5, 6, 7, 8, 9]
PATH = HOST + [10, 11, 12, 13]
NAMES = ("logistic", "forest", "xgboost", "mlp")


def read_external(path, manifest, name):
    spec = manifest["partitions"][name]
    source = path / f"{name}.tsv"
    if file_hash(source) != spec["sha256"]:
        raise ValueError("External partition checksum differs")
    items = [line.split("\t") for line in source.read_text(encoding="ascii").splitlines()]
    labels = np.asarray([int(row[0]) for row in items], dtype=np.int8)
    groups = np.asarray([row[1] for row in items], dtype="U64")
    brands = np.asarray([int(row[2]) for row in items], dtype=np.int8)
    vectors = np.asarray([row[3:] for row in items], dtype=np.float32)
    if ((len(labels), int(labels.sum()), len(np.unique(groups))) != (spec["rows"], spec["phishing"], spec["groups"])
            or not np.isin(labels, [0, 1]).all() or not np.isin(brands, [0, 1]).all()
            or vectors.shape != (len(labels), 14) or not np.isfinite(vectors).all()):
        raise ValueError("External partition shape or counts differ")
    return vectors, labels, groups, brands


def scores(model, values):
    return np.asarray(model.predict_proba(values)[:, 1], dtype=np.float64)


def metrics(test, values, threshold=0.5):
    _, labels, groups, _ = test
    return {**ranking(labels, values), "thresholdMetrics": classify(labels, values, groups, threshold)}


def calibrated_metrics(test, values, calibration, cal_values, threshold=0.5):
    _, cy, cg, _ = calibration
    negatives = negative_domain_scores(cy, cal_values, cg)
    result = metrics(test, values, threshold)
    result["domainTargetMetrics"] = []
    for target in (0.01, 0.001):
        policy = threshold_at_target(negatives, target, 0.05)
        cutoff = policy["threshold"]
        result["domainTargetMetrics"].append({
            "calibration": policy,
            "external": None if cutoff is None else classify(test[1], values, test[2], cutoff),
        })
    return result


def frozen_scores(folder, external):
    frozen = read_json(folder / "frozen.json")
    findings = {}
    for name, item in frozen["models"].items():
        if item["file"] != name + ".joblib" or file_hash(folder / item["file"]) != item["sha256"]:
            raise ValueError("Phase 3B artifact checksum differs")
        estimator = joblib.load(folder / item["file"])
        if "n_jobs" in estimator.get_params():
            estimator.set_params(n_jobs=1)
        value = scores(estimator, external[0][:, HOST])
        findings[name] = {
            **metrics(external, value), "frozenArtifactSha256": item["sha256"],
            "phase3bCutoffs": [
                {"target": policy["targetNegativeDomainFpr"], "results":
                 classify(external[1], value, external[2], policy["threshold"])}
                for policy in item["thresholds"] if policy["threshold"] is not None
            ],
        }
    return {"frozenManifestSha256": file_hash(folder / "frozen.json"), "models": findings}


def model_for(name):
    if name == "logistic":
        return make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=300, random_state=SEED))
    if name == "forest":
        return RandomForestClassifier(n_estimators=24, max_depth=7, min_samples_leaf=5, n_jobs=1, random_state=SEED)
    if name == "xgboost":
        return XGBClassifier(n_estimators=50, max_depth=3, learning_rate=0.12, n_jobs=1,
                             random_state=SEED, tree_method="hist", device="cpu", eval_metric="logloss")
    if name == "mlp":
        return make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(16,), max_iter=35,
                                                            random_state=SEED, batch_size=128))
    raise ValueError("Unknown experimental model")


def subsample(partition, per_class):
    x, y, groups = partition[:3]
    selected = []
    for label in (0, 1):
        indices = np.flatnonzero(y == label)
        first = {}
        for index in indices:
            first.setdefault(groups[index], index)
        order = sorted(first, key=lambda group: sha256(f"{SEED}:{group}".encode()).digest())
        if len(order) < per_class:
            raise ValueError("Insufficient independent groups for matched budget")
        selected.extend(first[group] for group in order[:per_class])
    return x[selected], y[selected], groups[selected]


def join(first, second):
    return tuple(np.concatenate((a, b)) for a, b in zip(first, second, strict=True))


def fit_comparison(train, test, calibration, columns):
    start = time.perf_counter()
    model = model_for("forest").fit(train[0][:, columns], train[1])
    held = scores(model, test[0][:, columns])
    cal = scores(model, calibration[0][:, columns])
    return {"trainingRows": len(train[1]), "features": len(columns), "fitAndEvaluationSeconds": time.perf_counter() - start,
            **calibrated_metrics(test, held, calibration, cal)}


def fusion(train, external, calibration):
    x, y, groups = train
    x = x[:, HOST]
    oof = np.empty((len(y), len(NAMES)))
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
    for fit, validation in splitter.split(x, y, groups):
        if np.intersect1d(groups[fit], groups[validation]).size:
            raise ValueError("OOF domains overlap")
        for index, name in enumerate(NAMES):
            oof[validation, index] = scores(model_for(name).fit(x[fit], y[fit]), x[validation])
    ap = np.array([average_precision_score(y, oof[:, i]) for i in range(len(NAMES))])
    selected = np.argsort(-ap)[:2]
    calibrators = [LogisticRegression().fit(oof[:, i:i + 1], y) for i in range(len(NAMES))]
    stack = LogisticRegression().fit(oof, y)
    weights = np.maximum(ap - np.mean(y), 0.001)
    weights /= weights.sum()
    models = [model_for(name).fit(x, y) for name in NAMES]

    def raw(samples):
        return np.column_stack([scores(model, samples[:, HOST]) for model in models])

    def mix(value):
        calibrated = np.column_stack([scores(cal, value[:, i:i + 1]) for i, cal in enumerate(calibrators)])
        return {
            "bestIndividual": value[:, selected[0]],
            "twoWeighted": calibrated[:, selected] @ (weights[selected] / weights[selected].sum()),
            "majority": np.mean(value >= 0.5, axis=1),
            "fourWeighted": calibrated @ weights,
            "stacked": scores(stack, value),
        }

    hold = raw(external[0])
    dev = raw(calibration[0])
    held_scores, cal_scores = mix(hold), mix(dev)
    findings = {name: calibrated_metrics(external, values, calibration, cal_scores[name],
                                         0.75 if name == "majority" else 0.5) for name, values in held_scores.items()}
    agreements = []
    binary = hold >= 0.5
    err = binary != external[1][:, None]
    for first, second in combinations(range(len(NAMES)), 2):
        corr = np.corrcoef(err[:, first], err[:, second])[0, 1]
        agreements.append({"models": [NAMES[first], NAMES[second]], "disagreeRows": int(
            np.count_nonzero(binary[:, first] != binary[:, second])), "bothWrongRows": int(
            np.count_nonzero(err[:, first] & err[:, second])), "errorCorrelation": float(corr) if np.isfinite(corr) else None})
    architecture = {
        "A_brand_only": metrics(external, external[3]),
        "E_selective_page_analysis": None,
    }
    for candidate, policy in [("B_single", "bestIndividual"), ("C_two", "twoWeighted"), ("D_four", "fourWeighted")]:
        architecture[candidate] = calibrated_metrics(external, np.maximum(held_scores[policy], external[3]),
                                                      calibration, np.maximum(cal_scores[policy], calibration[3]))
    perf = {
        "B_single": inference_cost([models[selected[0]]], [], None, calibration[0][:, HOST]),
        "C_two": inference_cost([models[i] for i in selected], [calibrators[i] for i in selected],
                                weights[selected] / weights[selected].sum(), calibration[0][:, HOST]),
        "D_four": inference_cost(models, calibrators, weights, calibration[0][:, HOST]),
    }
    return {
        "oofFolds": 3, "oofAveragePrecision": dict(zip(NAMES, map(float, ap), strict=True)),
        "selectedModels": [NAMES[i] for i in selected], "weights": dict(zip(NAMES, map(float, weights), strict=True)),
        "results": findings, "agreements": agreements, "architecture": architecture, "offlinePerformance": perf,
    }


def inference_cost(models, calibration, weights, samples):
    bundle = (models, calibration, weights)
    raw, packed = io.BytesIO(), io.BytesIO()
    joblib.dump(bundle, raw, compress=0)
    joblib.dump(bundle, packed, compress=3)
    data = packed.getvalue()
    loads = []
    for _ in range(5):
        before = time.perf_counter_ns()
        joblib.load(io.BytesIO(data))
        loads.append((time.perf_counter_ns() - before) / 1e6)

    def predict(x):
        value = np.column_stack([scores(model, x) for model in models])
        if calibration:
            value = np.column_stack([scores(cal, value[:, i:i + 1]) for i, cal in enumerate(calibration)])
            return value @ weights
        return value[:, 0]

    predict(samples[:1])
    durations = []
    cpu = time.process_time_ns()
    for i in range(100):
        start = time.perf_counter_ns()
        predict(samples[i:i + 1])
        durations.append((time.perf_counter_ns() - start) / 1000)
    cpu = (time.process_time_ns() - cpu) / 100000
    tracemalloc.start()
    predict(samples[:256])
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"uncompressedBytes": len(raw.getvalue()), "compressedBytes": len(data), "loadMedianMs": median(loads),
            "singleMedianUs": median(durations), "singleP95Us": float(np.percentile(durations, 95)),
            "processCpuMeanUs": cpu, "pythonTracedPeakBytesFor256": peak, "runtime": "Python CPU, not Chrome"}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    for name in ("external", "uci-development", "phase3b-models", "output"):
        cli.add_argument("--" + name, type=Path, required=True)
    args = cli.parse_args()
    external_path = private_path(args.external)
    manifest = read_json(external_path / "manifest.json")
    external = read_external(external_path, manifest, "test")
    with threadpool_limits(limits=1):
        frozen = frozen_scores(private_path(args.phase3b_models), external)
        output = private_path(args.output)
        output.mkdir()
        write_json(output / "frozen-transfer.json", frozen)
        print("Frozen Phase 3B transfer completed before fitting Phase 3C models.", flush=True)
        ext_train = read_external(external_path, manifest, "train")
        calibration = read_external(external_path, manifest, "calibration")
        for a, b in combinations((ext_train, calibration, external), 2):
            if np.intersect1d(a[2], b[2]).size:
                raise ValueError("External partitions share a domain")
        uci_path = private_path(args.uci_development)
        uci = load_partition(uci_path, read_manifest(uci_path), "train")
        uci = (uci.features, uci.labels, uci.groups)
        if np.intersect1d(uci[2], np.concatenate((ext_train[2], calibration[2], external[2]))).size:
            raise ValueError("UCI overlaps external data")
        counts = [len(np.unique(ext_train[2][ext_train[1] == label])) for label in (0, 1)]
        cap = 2 * (min(2500, *counts) // 2)
        if cap < 200:
            raise ValueError("Insufficient independent training groups")
        single_uci, single_ext = subsample(uci, cap), subsample(ext_train, cap)
        mixed = join(subsample(uci, cap // 2), subsample(ext_train, cap // 2))
        regimes = {name: fit_comparison(data, external, calibration, HOST) for name, data in
                   (("uci_only", single_uci), ("phresh_only", single_ext), ("equal_mixture", mixed))}
        expanded = fit_comparison(single_ext, external, calibration, PATH)
        results = fusion(mixed, external, calibration)
    write_json(output / "research.json", {
        "source": manifest, "seed": SEED, "rowsPerClassPerRegime": cap, "platform": platform.platform(),
        "regimes": regimes, "phreshOnlyPathAblation": expanded, **results,
    })
    print("Matched-budget experiments, fusion and Python runtime benchmarks completed.", flush=True)


if __name__ == "__main__":
    main()
