"""Train matched offline URL and DOM models on checksummed numeric projections."""

import argparse
from collections import Counter
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sys
from time import perf_counter

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "phase5d"))

from shared import balanced, build_input, ids_sha256, labels, load_partition, private
from evaluate import read, thresholds, hash_file
from fusion import blend, platt, probability
from metrics import evaluate, paired_recall, disagreement
from benchmark import model_for
from train import fit_model

VIEWS = ("train", "tuning", "calibration", "validation")
SCHEMA = read(HERE / "feature-schema.json")
GROUPS = SCHEMA["groups"]
FEATURES = tuple(name for group in GROUPS.values() for name in group)
METHODS = ("dom-logistic", "dom-forest", "dom-xgboost", "url-dom-xgboost")


def load_matched(cohort, projections):
    manifest = read(cohort / "manifest.json")
    if manifest["version"] != "phase5c-development-v1":
        raise ValueError("Expected the Phase 5C canonical view")
    pin = hash_file(cohort / "manifest.json")
    projected = {}
    shards = []
    filenames = set()
    statuses = Counter()
    for directory in projections:
        receipt = read(directory / "manifest.json")
        if receipt["cohortSha256"] != pin or receipt["revision"] != manifest["sourceRevision"]:
            raise ValueError("HTML projection belongs to a different source or canonical view")
        for spec in receipt["completedShards"]:
            if spec["name"] in filenames or spec["file"] != spec["name"] + ".jsonl":
                raise ValueError("Duplicate or unexpected HTML shard")
            filenames.add(spec["name"])
            path = directory / spec["file"]
            if hash_file(path) != spec["derivedSha256"]:
                raise ValueError("Derived content checksum changed")
            size = 0
            with path.open(encoding="utf-8") as stream:
                for text in stream:
                    row = json.loads(text)
                    if row["id"] in projected or row["partition"] not in VIEWS or row["label"] not in (0, 1):
                        raise ValueError("Unexpected content row identity")
                    if row["status"] == "usable":
                        feature = row["features"]
                        if set(feature) != set(FEATURES) or any(type(value) not in (int, float)
                                                              or not math.isfinite(value) or value < 0
                                                              for value in feature.values()):
                            raise ValueError("Untrusted content features differ from schema")
                    projected[row["id"]] = row
                    statuses[row["status"]] += 1
                    if row.get("malformed"):
                        statuses["usableWithParseErrors"] += 1
                    size += 1
            if size != spec["matched"]:
                raise ValueError("Content shard row count mismatch")
            shards.append(spec["name"])

    pools = {}
    matched_counts = {}
    covered = set()
    owners = {}
    for part in VIEWS:
        canonical = load_partition(cohort, manifest, part)
        pools[part] = []
        counts = Counter()
        for row in canonical:
            extra = projected.get(row["id"])
            if extra is None:
                continue
            if (row["partition"], row["label"]) != (extra["partition"], extra["label"]):
                raise ValueError("Content record disagrees with canonical membership")
            covered.add(row["id"])
            counts[f'{extra["status"]}/{row["label"]}'] += 1
            if extra["status"] != "usable":
                continue
            for key in ("group", "family", "alias", "exact"):
                token = row["identity"][key]
                if token and owners.setdefault((key, token), part) != part:
                    raise ValueError("Shared identity across matched development partitions")
            pools[part].append(row | {"dom": extra["features"],
                                     "timings": {key: extra[key] for key in ("parseMs", "extractMs", "pipelineMs")}})
        matched_counts[part] = dict(counts)
    if covered != projected.keys():
        raise ValueError("Unknown HTML sample IDs in the acquisition receipt")
    return pools, {"shards": shards, "matched": len(projected), "statusCounts": dict(statuses),
                   "partitionCoverage": matched_counts, "canonicalSha256": pin}


def model_input(rows, values, include_url=False):
    data = np.asarray([[row["dom"][name] for name in values] for row in rows], dtype=np.float32)
    if include_url:
        return np.column_stack((np.asarray([row["x"] for row in rows], dtype=np.float32), data))
    return data


def fit_dom(name, train, output):
    algorithm = name.split("-")[-1]
    columns = FEATURES
    if name.startswith("ablation-"):
        group = name.removeprefix("ablation-")
        columns = tuple(column for column in FEATURES if column not in GROUPS[group])
        algorithm = "xgboost"
    include_url = name.startswith("url-")
    model = model_for(algorithm)
    values = model_input(train, columns, include_url)
    start = perf_counter()
    model.fit(values, labels(train))
    seconds = perf_counter() - start
    artifact = output / "model.joblib"
    joblib.dump(model, artifact, compress=3)
    loaded = joblib.load(artifact)
    if not np.allclose(model.predict_proba(values[:8]), loaded.predict_proba(values[:8]), atol=1e-12, rtol=0):
        raise ValueError("DOM checkpoint changed inference after reload")
    return (lambda rows: loaded.predict_proba(model_input(rows, columns, include_url))[:, 1].astype(np.float64)), {
        "fitSeconds": seconds, "modelBytes": artifact.stat().st_size, "modelSha256": hash_file(artifact),
        "featureCount": len(columns) + (14 if include_url else 0)
    }


def profile(score, rows, uses_dom):
    sample = [rows[i] for i in np.linspace(0, len(rows) - 1, min(300, len(rows)), dtype=int)]
    for row in sample[:10]:
        score([row])
    times = []
    for row in sample:
        start = perf_counter()
        score([row])
        times.append((perf_counter() - start) * 1000)
    stages = {"inference": times}
    if uses_dom:
        for name in ("parseMs", "extractMs", "pipelineMs"):
            stages[name] = [row["timings"][name] for row in sample]
        stages["endToEndPairedStageMs"] = np.asarray(times) + stages["pipelineMs"]
    return {name: {"medianMs": float(np.median(values)), "p95Ms": float(np.percentile(values, 95))}
            for name, values in stages.items()}


def run(cohort, output, projections, size):
    pools, audit = load_matched(cohort, projections)
    train = balanced(pools["train"], size)
    if any(len(set(labels(pools[part]))) != 2 for part in VIEWS[1:]):
        raise ValueError("Tuning, calibration and validation require both labels")
    tuning, cal, evaluation = (pools[name] for name in VIEWS[1:])
    output.mkdir(mode=0o700)
    models = {}
    functions = {}
    with threadpool_limits(limits=2):
        for label in ("url-ngram", "url-xgboost", *METHODS, *("ablation-" + group for group in GROUPS)):
            destination = output / label
            destination.mkdir()
            if label in ("url-ngram", "url-xgboost"):
                kind = label.removeprefix("url-")
                predict, fit = fit_model(kind, train, tuning, destination, False)
                score = lambda rows, predict=predict, kind=kind: predict(build_input(kind, rows))
            else:
                score, fit = fit_dom(label, train, destination)
            functions[label] = score
            models[label] = {"fit": fit}
        fusion_start = perf_counter()
        first, second = functions["url-ngram"], functions["url-xgboost"]
        scale_a, scale_b = platt(labels(tuning), first(tuning)), platt(labels(tuning), second(tuning))
        functions["url-fusion"] = lambda rows: blend(probability(scale_a, first(rows)),
                                                     probability(scale_b, second(rows)), 0.75)
        models["url-fusion"] = {"fit": {"fitSeconds": perf_counter() - fusion_start, "referenceWeight": 0.75,
            "componentModelBytes": sum(models[key]["fit"]["modelBytes"] for key in ("url-ngram", "url-xgboost"))}}

        cal_scores = {name: np.asarray(score(cal), dtype=np.float64) for name, score in functions.items()}
        eval_scores = {name: np.asarray(score(evaluation), dtype=np.float64) for name, score in functions.items()}
        for name, score in functions.items():
            cut = thresholds(cal, cal_scores[name])
            models[name].update({"thresholds": cut, "evaluation": evaluate(evaluation, eval_scores[name], cut),
                                 "latency": profile(score, evaluation, name not in ("url-ngram", "url-xgboost", "url-fusion"))})
            print(f"Matched {size} {name} complete", flush=True)

    comparisons = {}
    y = labels(evaluation)
    for reference in ("url-ngram", "url-xgboost", "url-fusion"):
        for candidate in ("dom-xgboost", "url-dom-xgboost"):
            name = f"{reference}+{candidate}"
            points = {"fixed": (0.5, 0.5)}
            points.update({target: (models[reference]["thresholds"][target]["threshold"],
                                     models[candidate]["thresholds"][target]["threshold"])
                           for target in models[reference]["thresholds"]})
            comparisons[name] = {target: None if None in (first_cut, second_cut) else {
                **disagreement(y, eval_scores[reference], eval_scores[candidate], first_cut, second_cut),
                "pairedRecall": paired_recall(evaluation, eval_scores[candidate], second_cut,
                                              eval_scores[reference], first_cut)
            } for target, (first_cut, second_cut) in points.items()}
    report = {"schema": SCHEMA["version"], "schemaSha256": sha256((HERE / "feature-schema.json").read_bytes()
              .replace(b"\r\n", b"\n")).hexdigest(), "audit": audit, "rows": size,
              "identities": {part: ids_sha256(train if part == "train" else pools[part]) for part in VIEWS},
              "usable": {part: {"rows": len(rows), "positive": int(labels(rows).sum())} for part, rows in pools.items()},
              "models": models, "incrementalDetection": comparisons}
    (output / "results.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=private)
    parser.add_argument("output", type=private)
    parser.add_argument("size", type=int, choices=(1000, 20000, 50000))
    parser.add_argument("--projections", nargs="+", type=private, required=True)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
