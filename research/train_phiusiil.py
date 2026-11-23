"""Tune on the development partition and freeze four models before opening the holdout."""

import argparse
from importlib.metadata import version
import platform
from statistics import mean, median, stdev
from time import perf_counter

import joblib
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from threadpoolctl import threadpool_limits

from experiment_data import REPO, identity, load_partition, private_path, read_json, read_manifest, sha256, write_json
from experiment_metrics import classify, negative_domain_scores, ranking, threshold_at_target
from experiment_models import fit_model


CONFIG = REPO / "research/phiusiil-experiment.json"


def audit_features(x, labels, columns, selected):
    positive = labels == 1
    results = {}
    for index, name in enumerate(columns):
        values = x[:, index]
        auc = roc_auc_score(labels, values)
        results[name] = {
            "used": name in selected,
            "phishingMean": float(values[positive].mean()),
            "legitimateMean": float(values[~positive].mean()),
            "phishingZeroRate": float(np.mean(values[positive] == 0)),
            "legitimateZeroRate": float(np.mean(values[~positive] == 0)),
            "singleFeatureDirectionFreeRocAuc": float(max(auc, 1 - auc)),
        }
    if any(results[name]["singleFeatureDirectionFreeRocAuc"] >= 0.98 for name in selected):
        raise ValueError("A selected feature is near-deterministic. Review for leakage before fitting.")
    return results


def fold_summary(folds):
    keys = ("prAucAveragePrecision", "rocAuc", "logLoss", "precision", "recall", "f1", "falsePositiveRate")
    return {key: {"mean": mean(values), "sd": stdev(values)} for key in keys if (
        values := [fold["validation"][key] for fold in folds if fold["validation"][key] is not None]
    ) and len(values) >= 2}


def split_proof(indices, labels, groups):
    train, validation = indices
    if np.intersect1d(groups[train], groups[validation]).size or set(labels[validation]) != {0, 1}:
        raise ValueError("An outer fold contains group leakage or only one class.")
    return {
        "trainingRows": len(train), "validationRows": len(validation),
        "trainingDomains": len(np.unique(groups[train])), "validationDomains": len(np.unique(groups[validation])),
        "validationPhishingRows": int(labels[validation].sum()),
    }


def fit_fold(name, params, x, y, groups, indices, seed, workers):
    train, validation = indices
    start = perf_counter()
    fit = fit_model(name, params, x[train], y[train], groups[train], seed, workers)
    elapsed = perf_counter() - start
    train_scores = fit.estimator.predict_proba(x[train])[:, 1]
    val_scores = fit.estimator.predict_proba(x[validation])[:, 1]
    return {
        "training": ranking(y[train], train_scores),
        "validation": {**ranking(y[validation], val_scores),
                       **classify(y[validation], val_scores, groups[validation], 0.5)},
        "fitSeconds": elapsed, "selectedRounds": fit.rounds,
    }, fit.trace


def tune(name, candidates, x, y, groups, folds, config):
    results, traces = [], []
    for index, params in enumerate(candidates):
        scores, trace = [], None
        for fold, split in enumerate(folds):
            score, current_trace = fit_fold(name, params, x, y, groups, split, config["seed"] + fold, config["workers"])
            scores.append(score)
            if fold == 0:
                trace = current_trace
            print(f"{name} candidate {index + 1}/{len(candidates)} fold {fold + 1}: "
                  f"validation AP {score['validation']['prAucAveragePrecision']:.5f}", flush=True)
        results.append({"parameters": params, "folds": scores, "validationSummary": fold_summary(scores)})
        traces.append(trace)
    winner = max(range(len(results)), key=lambda i: results[i]["validationSummary"]["prAucAveragePrecision"]["mean"])
    return results, winner, traces[winner]


def learning_curve(name, chosen, x, y, groups, fold, config):
    train, validation = fold
    domain_order = np.random.default_rng(config["seed"]).permutation(np.unique(groups[train]))
    points = []
    for fraction in config["curveFractions"]:
        if fraction == 1:
            subset, result = train, chosen["folds"][0]
        else:
            group_subset = domain_order[:int(len(domain_order) * fraction)]
            subset = train[np.isin(groups[train], group_subset)]
            result, _ = fit_fold(name, chosen["parameters"], x, y, groups, (subset, validation),
                                 config["seed"], config["workers"])
        points.append({
            "trainingDomainFraction": fraction, "trainingRows": len(subset),
            "trainingAveragePrecision": result["training"]["prAucAveragePrecision"],
            "validationAveragePrecision": result["validation"]["prAucAveragePrecision"],
        })
    return points


def train(development, output):
    started = perf_counter()
    development, output = private_path(development), private_path(output)
    manifest = read_manifest(development)
    data = load_partition(development, manifest, "train")
    config = read_json(CONFIG)
    columns = manifest["featureColumns"]
    selected = config["usedFeatures"]
    indices = [columns.index(name) for name in selected]
    feature_audit = audit_features(data.features, data.labels, columns, selected)
    print("Training-only feature audit passed. Scheme, port and path features excluded.", flush=True)
    x, y, groups = data.features[:, indices], data.labels, data.groups
    splitter = StratifiedGroupKFold(n_splits=config["folds"], shuffle=True, random_state=config["seed"])
    folds = list(splitter.split(x, y, groups))
    fold_proofs = [split_proof(split, y, groups) for split in folds]
    output.mkdir()
    checks, frozen_models = {}, {}
    with threadpool_limits(limits=1, user_api="blas"):
        for name, candidates in config["candidates"].items():
            results, winner, trace = tune(name, candidates, x, y, groups, folds, config)
            chosen = results[winner]
            curve = learning_curve(name, chosen, x, y, groups, folds[0], config)
            rounds = [item["selectedRounds"] for item in chosen["folds"] if item["selectedRounds"] is not None]
            fixed_rounds = int(median(rounds)) if rounds else None
            start = perf_counter()
            final = fit_model(name, chosen["parameters"], x, y, groups, config["seed"], config["workers"], fixed_rounds)
            seconds = perf_counter() - start
            artifact = output / f"{name}.joblib"
            joblib.dump(final.estimator, artifact, compress=3)
            frozen_models[name] = {
                "file": artifact.name, "sha256": sha256(artifact), "bytes": artifact.stat().st_size,
                "parameters": chosen["parameters"], "fixedRounds": fixed_rounds, "finalFitSeconds": seconds,
            }
            checks[name] = {
                "selectedCandidate": winner, "candidates": results, "learningCurveOuterFold1": curve,
                "earlyStopTraceOuterFold1": trace, "outerFitSeconds": sum(f["fitSeconds"] for c in results for f in c["folds"]),
            }
            print(f"{name} frozen candidate {winner + 1}; final fit {seconds:.2f} s", flush=True)

        # This partition is opened only after all model choices and artifacts have been fixed.
        calibration = load_partition(development, manifest, "validation")
        if np.intersect1d(groups, calibration.groups).size:
            raise ValueError("Training overlaps false-positive calibration domains.")
        for name, artifact in frozen_models.items():
            estimator = joblib.load(output / artifact["file"])
            scores = estimator.predict_proba(calibration.features[:, indices])[:, 1]
            negatives = negative_domain_scores(calibration.labels, scores, calibration.groups)
            artifact["thresholds"] = [threshold_at_target(negatives, target, config["calibrationRisk"])
                                      for target in config["falsePositiveTargets"]]
    group_file = output / "development-groups.txt"
    group_file.write_text("\n".join(np.union1d(groups, calibration.groups)) + "\n", encoding="ascii")
    champion = max(checks, key=lambda name: checks[name]["candidates"][checks[name]["selectedCandidate"]]
                   ["validationSummary"]["prAucAveragePrecision"]["mean"])
    summary = {
        "dataset": identity(manifest), "trainingPartition": manifest["train"], "calibrationPartition": manifest["validation"],
        "config": config, "configSha256": sha256(CONFIG), "featureAuditTrainingOnly": feature_audit,
        "foldPartitions": fold_proofs, "crossValidation": checks, "preselectedChampion": champion,
        "elapsedDevelopmentSeconds": perf_counter() - started,
        "environment": {"platform": platform.platform(), "processor": platform.processor(), "python": platform.python_version(),
                        **{name: version(name) for name in ("scikit-learn", "xgboost-cpu", "numpy", "scipy", "joblib")}},
    }
    write_json(output / "development-report.json", summary)
    write_json(output / "frozen.json", {
        "dataset": identity(manifest), "configSha256": summary["configSha256"], "usedFeatures": selected,
        "models": frozen_models, "preselectedChampion": champion, "developmentReportSha256": sha256(output / "development-report.json"),
        "developmentGroupsSha256": sha256(group_file),
    })
    print(f"All four models and thresholds frozen. Development-only champion: {champion}.", flush=True)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--development-dir", required=True)
    cli.add_argument("--output-dir", required=True)
    args = cli.parse_args()
    train(args.development_dir, args.output_dir)
