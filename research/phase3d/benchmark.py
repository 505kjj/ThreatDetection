"""Prepare, fit, and score bounded Phase 3D URL-only research candidates."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
from statistics import median
import subprocess
import sys
from time import perf_counter, process_time
import warnings

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiment_data import DIGEST, load_partition, private_path, read_json, read_manifest, sha256, write_json
from experiment_metrics import classify, negative_domain_scores, ranking, threshold_at_target


SEED = 143
MODELS = ("logistic", "forest", "xgboost", "mlp")
HOST = tuple(range(2, 10))
PATH = HOST + tuple(range(10, 14))
FEATURES = {"host": HOST, "path": PATH, "brand": PATH + (14,)}


@dataclass(frozen=True)
class Rows:
    x: np.ndarray
    y: np.ndarray
    groups: np.ndarray
    families: np.ndarray

    def select(self, index):
        return Rows(self.x[index], self.y[index], self.groups[index], self.families[index])


def combine(*sources):
    return Rows(*(np.concatenate([getattr(data, key) for data in sources]) for key in ("x", "y", "groups", "families")))


def store(file, data):
    with file.open("xb") as stream:
        np.savez(stream, x=data.x, y=data.y, groups=data.groups, families=data.families)


def load(file):
    with np.load(file, allow_pickle=False) as source:
        return Rows(source["x"], source["y"], source["groups"], source["families"])


def external(folder, name, spec):
    path = folder / (name + ".tsv")
    if sha256(path) != spec["sha256"]:
        raise ValueError("PhreshPhish partition checksum mismatch")
    features, labels, groups, families = [], [], [], []
    with path.open(encoding="ascii") as stream:
        for line in stream:
            label, group, family, brand, *raw = line.rstrip("\n").split("\t")
            if (label not in ("0", "1") or brand not in ("0", "1") or not DIGEST.fullmatch(group)
                    or (family and not DIGEST.fullmatch(family)) or len(raw) != 14):
                raise ValueError("Bad PhreshPhish numeric row")
            values = [int(value) for value in raw]
            if any(value < 0 or value > 8192 for value in values):
                raise ValueError("PhreshPhish numeric feature outside bounds")
            features.append(values + [int(brand)])
            labels.append(int(label))
            groups.append(group)
            families.append(family)
    if (len(labels), sum(labels), len(set(groups))) != (spec["rows"], spec["phishing"], spec["groups"]):
        raise ValueError("PhreshPhish cohort counts mismatch")
    return Rows(np.array(features, dtype=np.float32), np.array(labels, dtype=np.int8),
                np.array(groups, dtype="U64"), np.array(families, dtype="U64"))


def disjoint(left, right):
    if np.intersect1d(left.groups, right.groups).size:
        raise ValueError("Shared domain across cohorts")
    if np.intersect1d(left.families[left.families != ""], right.families[right.families != ""]).size:
        raise ValueError("Shared lexical family across PhreshPhish cohorts")


def unique_training(data):
    shuffled = data.select(np.random.default_rng(SEED).permutation(len(data.y)))
    _, first, inverse = np.unique(shuffled.groups, return_index=True, return_inverse=True)
    flags = np.zeros(len(first), dtype=np.int8)
    np.bitwise_or.at(flags, inverse, 1 << shuffled.y)
    return shuffled.select(np.sort(first[flags != 3]))


def balance(data, rows):
    if rows % 2:
        raise ValueError("Balanced training requires an even row count")
    indices = [np.flatnonzero(data.y == label)[:rows // 2] for label in (0, 1)]
    if any(len(index) != rows // 2 for index in indices):
        raise ValueError("Insufficient independent examples")
    return data.select(np.sort(np.concatenate(indices)))


def prepare(run, uci, phresh):
    development = uci / "development"
    manifest = read_manifest(development)
    original = load_partition(development, manifest, "train")
    uci_rows = Rows(np.pad(original.features, ((0, 0), (0, 1))), original.labels, original.groups,
                    np.full(len(original.labels), "", dtype="U1"))
    sources = read_json(phresh / "manifest.json")
    if sources["featureColumns"] != manifest["featureColumns"]:
        raise ValueError("Mismatched reusable URL schema")
    parts = sources["partitions"]
    if not (parts["train"]["lastDay"] < parts["validation"]["firstDay"]
            <= parts["validation"]["lastDay"] < parts["test"]["firstDay"]):
        raise ValueError("Nonchronological PhreshPhish cohorts")
    train = external(phresh, "train", parts["train"])
    validation = external(phresh, "validation", parts["validation"])
    disjoint(train, validation)
    disjoint(uci_rows, train)
    disjoint(uci_rows, validation)
    prepared = run / "prepared"
    prepared.mkdir()
    capacities = {}
    for name, rows in (("uci", uci_rows), ("phresh", train)):
        distinct = unique_training(rows)
        store(prepared / f"{name}.npz", distinct)
        capacities[name] = {label: int(np.count_nonzero(distinct.y == class_id))
                            for class_id, label in ((0, "legitimate"), (1, "phishing"))}
    store(prepared / "validation.npz", validation)
    write_json(prepared / "capacity.json", capacities)
    print(json.dumps(capacities), flush=True)


def train_data(run, cohort, count):
    prepared = run / "prepared"
    if cohort in ("uci", "phresh"):
        return balance(load(prepared / f"{cohort}.npz"), count)
    if cohort == "mixed":
        return combine(*(balance(load(prepared / f"{name}.npz"), count // 2) for name in ("uci", "phresh")))
    raise ValueError("Unknown training cohort")


def model_for(name):
    if name == "logistic":
        return make_pipeline(StandardScaler(), LogisticRegression(C=1, max_iter=150, random_state=SEED))
    if name == "forest":
        return RandomForestClassifier(n_estimators=48, max_depth=8, min_samples_leaf=5, n_jobs=2, random_state=SEED)
    if name == "xgboost":
        return XGBClassifier(n_estimators=96, max_depth=3, learning_rate=0.10, tree_method="hist",
                             device="cpu", n_jobs=2, eval_metric="logloss", random_state=SEED)
    if name == "mlp":
        return make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(16,), batch_size=256,
                                                            max_iter=30, random_state=SEED))
    raise ValueError("Unknown model")


def probability(model, features):
    return model.predict_proba(features)[:, 1].astype(np.float64)


def restrict_inference(model):
    if "n_jobs" in model.get_params():
        model.set_params(n_jobs=1)
    return model


def predict(bundle, features):
    values = features[:, bundle["columns"]]
    if bundle["mode"] == "single":
        return probability(bundle["models"][0], values)
    base = np.column_stack([probability(model, values) for model in bundle["models"]])
    if bundle["mode"] == "stack":
        return probability(bundle["stack"], base)
    calibrated = np.column_stack([probability(cal, base[:, i:i+1]) for i, cal in enumerate(bundle["calibrators"])])
    return calibrated @ bundle["weights"]


def save_candidate(run, name, bundle, training, validation, fit_seconds, notes):
    folder = run / "candidates" / name
    folder.mkdir()
    artifact = folder / "model.joblib"
    joblib.dump(bundle, artifact, compress=3)
    validation_scores = predict(bundle, validation.x)
    negatives = negative_domain_scores(validation.y, validation_scores, validation.groups)
    thresholds = [threshold_at_target(negatives, target, 0.05) for target in (0.01, 0.001)]
    calibrated = [None if policy["threshold"] is None else
                  classify(validation.y, validation_scores, validation.groups, policy["threshold"])
                  for policy in thresholds]
    report = {
        "candidate": name, "sampleRows": len(training.y), "fitSeconds": fit_seconds,
        "modelBytes": artifact.stat().st_size, "artifactSha256": sha256(artifact),
        "trainingAP": ranking(training.y, predict(bundle, training.x))["prAucAveragePrecision"],
        "validation": ranking(validation.y, validation_scores),
        "validationAtHalf": classify(validation.y, validation_scores, validation.groups, 0.5),
        "validationAtCutoffs": calibrated, "cutoffs": thresholds, "notes": notes,
    }
    write_json(folder / "validation.json", report)
    print(f"{name}: {len(training.y)} rows, validation AP {report['validation']['prAucAveragePrecision']:.4f}", flush=True)


def fit(run, cohort, count, name, feature_set):
    train = train_data(run, cohort, count)
    validation = load(run / "prepared/validation.npz")
    columns = FEATURES[feature_set]
    if feature_set == "brand" and cohort != "phresh":
        raise ValueError("Only PhreshPhish supplies the local brand feature")
    with warnings.catch_warnings(record=True) as messages:
        warnings.simplefilter("always", ConvergenceWarning)
        start = perf_counter()
        model = restrict_inference(model_for(name).fit(train.x[:, columns], train.y))
        fit_seconds = perf_counter() - start
    notes = {"iterationCapWarning": any(issubclass(w.category, ConvergenceWarning) for w in messages)}
    identifier = f"{cohort}-{count}-{feature_set}-{name}"
    save_candidate(run, identifier, {"mode": "single", "columns": columns, "models": [model]},
                   train, validation, fit_seconds, notes)


def fit_fusion(run, cohort, count):
    train = train_data(run, cohort, count)
    validation = load(run / "prepared/validation.npz")
    started = perf_counter()
    features = train.x[:, HOST]
    families = np.where(train.families != "", train.families, train.groups)
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
    oof = np.zeros((len(train.y), len(MODELS)))
    with warnings.catch_warnings(record=True) as messages:
        warnings.simplefilter("always", ConvergenceWarning)
        for learn, hold in splitter.split(features, train.y, families):
            for index, name in enumerate(MODELS):
                estimator = model_for(name).fit(features[learn], train.y[learn])
                oof[hold, index] = probability(estimator, features[hold])
        bases = [restrict_inference(model_for(name).fit(features, train.y)) for name in MODELS]
    ap = np.array([ranking(train.y, values)["prAucAveragePrecision"] for values in oof.T])
    top_two = np.argsort(-ap)[:2]
    weights = np.maximum(ap - np.mean(train.y), 0.001)
    calibrators = [LogisticRegression().fit(values[:, None], train.y) for values in oof.T]
    stack = LogisticRegression().fit(oof, train.y)
    seconds = perf_counter() - started
    notes = {"trainingCohort": cohort, "baseFitSecondsShared": seconds, "oofFolds": 3,
             "oofAP": dict(zip(MODELS, map(float, ap))), "topTwo": [MODELS[i] for i in top_two],
             "iterationCapWarnings": sum(issubclass(w.category, ConvergenceWarning) for w in messages)}
    for label, indexes in (("two", top_two), ("four", np.arange(len(MODELS)))):
        chosen = weights[indexes]
        bundle = {"mode": "blend", "columns": HOST, "weights": chosen / chosen.sum(),
                  "models": [bases[i] for i in indexes], "calibrators": [calibrators[i] for i in indexes]}
        save_candidate(run, f"fusion-{cohort}-{count}-{label}", bundle, train, validation, seconds, notes)
    save_candidate(run, f"fusion-{cohort}-{count}-stack",
                   {"mode": "stack", "columns": HOST, "models": bases, "stack": stack},
                   train, validation, seconds, notes)


def measure(bundle, sample):
    predict(bundle, sample[:1])
    start_cpu = process_time()
    latency = []
    for index in range(min(64, len(sample))):
        started = perf_counter()
        predict(bundle, sample[index:index+1])
        latency.append((perf_counter() - started) * 1000)
    return {"predictionMedianMs": median(latency), "predictionP95Ms": float(np.percentile(latency, 95)),
            "processCpuMsPerPrediction": (process_time() - start_cpu) * 1000 / len(latency)}


def final_score(run, phresh, plan):
    frozen = read_json(plan)
    output = run / "final"
    output.mkdir(exist_ok=True)
    write_json(output / "opened.json", {"planSha256": sha256(plan), "testSha256": frozen["testSha256"]})
    spec = read_json(phresh / "manifest.json")["partitions"]["test"]
    if spec["sha256"] != frozen["testSha256"]:
        raise ValueError("Reserved external test cohort differs from the frozen plan")
    test = external(phresh, "test", spec)
    for file in ("uci.npz", "phresh.npz", "validation.npz"):
        disjoint(load(run / "prepared" / file), test)
    controls = json.loads(subprocess.check_output(["node", str(Path(__file__).with_name("controls.mjs"))], text=True))
    for name, digest in frozen["candidates"].items():
        folder = run / "candidates" / name
        model_file = folder / "model.joblib"
        candidate_file = folder / "validation.json"
        if sha256(candidate_file) != digest:
            raise ValueError("Frozen calibration report mismatch")
        candidate = read_json(candidate_file)
        if sha256(model_file) != candidate["artifactSha256"]:
            raise ValueError("Frozen local artifact mismatch")
        start = perf_counter()
        model = joblib.load(model_file)
        load_ms = (perf_counter() - start) * 1000
        scores = predict(model, test.x)
        comparisons = [
            None if policy["threshold"] is None else classify(test.y, scores, test.groups, policy["threshold"])
            for policy in candidate["cutoffs"]
        ]
        hard = (test.y == 0) & (test.x[:, 14] != 0)
        hard_sample = {
            "definition": "Benign PhreshPhish examples with a local financial-brand advisory signal",
            "rows": int(hard.sum()), "urlsFlaggedAtHalf": int(np.count_nonzero(scores[hard] >= 0.5)),
        }
        financial = {}
        for cohort, vectors in controls.items():
            fixture_scores = predict(model, np.asarray(vectors, dtype=np.float32))
            financial[cohort] = {
                "rows": len(fixture_scores),
                "atHalf": int(np.count_nonzero(fixture_scores >= 0.5)),
                "atCalibratedCutoffs": [
                    None if p["threshold"] is None else int(np.count_nonzero(fixture_scores >= p["threshold"]))
                    for p in candidate["cutoffs"]
                ],
            }
        result = {"candidate": name, "test": ranking(test.y, scores),
                  "testAtHalf": classify(test.y, scores, test.groups, 0.5),
                  "testAtCutoffs": comparisons, "brandAdvisoryHardNegatives": hard_sample,
                  "financialControls": financial,
                  "loadMs": load_ms, **measure(model, test.x)}
        write_json(output / f"{name}.json", result)
        print(f"{name}: external AP {result['test']['prAucAveragePrecision']:.4f}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "fit", "fusion", "final"))
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--uci", type=Path)
    parser.add_argument("--phresh", type=Path)
    parser.add_argument("--cohort", choices=("uci", "phresh", "mixed"))
    parser.add_argument("--count", type=int)
    parser.add_argument("--model", choices=MODELS)
    parser.add_argument("--features", choices=FEATURES, default="host")
    parser.add_argument("--plan", type=Path)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Run the worker using the Windows resource guard")
    run = private_path(args.run)
    with threadpool_limits(limits=1):
        if args.mode == "prepare":
            prepare(run, private_path(args.uci), private_path(args.phresh))
        elif args.mode == "fit":
            fit(run, args.cohort, args.count, args.model, args.features)
        elif args.mode == "fusion":
            fit_fusion(run, args.cohort, args.count)
        else:
            final_score(run, private_path(args.phresh), private_path(args.plan))


if __name__ == "__main__":
    main()
