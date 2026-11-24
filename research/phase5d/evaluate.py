"""Score frozen checkpoints and evaluate held-out fusion, adaptation and time windows."""

import argparse
from hashlib import file_digest, sha256
import json
import os
from time import perf_counter

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from fusion import blend, pairwise, probability, select
from metrics import CONFIG, cutoffs, evaluate, group_labels, paired_recall
from shared import (PHASE5C, build_input, ids_sha256, labels, load_partition,
                    private, protocol_bytes)


def read(path):
    return json.loads(path.read_bytes())


def hash_file(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def protocol_hash():
    return sha256(protocol_bytes()).hexdigest()


def scorer(name, folder, receipt):
    path = folder / ("model.pt" if name in {"cnn", "transformer"} else "model.joblib")
    if hash_file(path) != receipt["modelSha256"]:
        raise ValueError("Frozen checkpoint checksum changed")
    if name == "transformer":
        from transformer import inputs, predict, restore
        model = restore(path)
        return lambda rows: predict(model, inputs(rows)).astype(np.float64)
    if name == "cnn":
        import torch
        from shared import CharacterCNN, predict_cnn
        model = CharacterCNN()
        model.load_state_dict(torch.load(path, weights_only=True, map_location="cpu"))
        return lambda rows: predict_cnn(model, build_input(name, rows)).astype(np.float64)
    model = joblib.load(path)
    return lambda rows: model.predict_proba(build_input(name, rows))[:, 1].astype(np.float64)


def latency(score, rows):
    sample = [rows[i] for i in np.linspace(0, len(rows) - 1, 300, dtype=int)]
    for row in sample[:10]:
        score([row])
    durations = []
    for row in sample:
        start = perf_counter()
        score([row])
        durations.append((perf_counter() - start) * 1000)
    return {"medianMs": float(np.median(durations)), "p95Ms": float(np.percentile(durations, 95))}


def thresholds(rows, scores):
    return cutoffs(labels(rows), scores, group_labels(rows))


def verify_replay(expected, actual):
    if (expected["idsSha256"] != actual["idsSha256"]
            or any(expected["atHalf"][key] != actual["atHalf"][key] for key in ("tn", "fp", "fn", "tp"))):
        raise ValueError("Phase 5C baseline membership or confusion matrix changed")
    delta = {key: actual[key] - expected[key] for key in ("prAucAveragePrecision", "rocAuc")}
    if any(abs(value) > 1e-6 for value in delta.values()):
        raise ValueError("Phase 5C baseline ranking failed numerical replay")
    delta["lockedOperatingPoints"] = {}
    for target in ("0.01", "0.001"):
        old = expected["atCalibratedConstraints"][target]
        current = actual["atConstraints"][target]
        if (old is None) != (current is None):
            raise ValueError("Baseline low-FPR support changed")
        delta["lockedOperatingPoints"][target] = None if old is None else {
            key: current[key] - old[key] for key in ("recall", "negativeDomainFalsePositiveRate")
        }
    return delta


def evaluate_fusion(functions, data, cached, baseline):
    names = [CONFIG["fusionReference"], *CONFIG["fusionPartners"]]
    fitting = data["fusion-fit"]
    fitting_scores = {name: functions[name](fitting) for name in names}
    started = perf_counter()
    scales, trial = select(labels(fitting), group_labels(fitting), fitting_scores)
    trial["fitSeconds"] = perf_counter() - started
    trial["fitIdsSha256"] = ids_sha256(fitting)
    trial["fitRows"] = len(fitting)
    trial["pairwiseValidationAtHalf"] = pairwise(
        labels(data["validation"]), {name: cached[name]["validation"] for name in names},
        {name: 0.5 for name in names})
    for constraint in ("0.01", "0.001"):
        trial[f"pairwiseValidationAt{constraint}"] = pairwise(
            labels(data["validation"]), {name: cached[name]["validation"] for name in names},
            {name: baseline[name]["thresholds"][constraint]["threshold"] for name in names})
    winner = trial["selected"]
    if winner is None:
        return trial
    first, second = winner["reference"], winner["partner"]
    weight = winner["referenceWeight"]
    trial["componentCheckpointBytes"] = sum(
        baseline[name].get("fit", baseline[name].get("originalBenchmark"))["modelBytes"] for name in (first, second))
    trial["probabilityScales"] = {name: {"coefficient": float(scales[name].coef_[0, 0]),
                                        "intercept": float(scales[name].intercept_[0])}
                                  for name in (first, second)}

    def combine(a, b):
        return blend(probability(scales[first], a), probability(scales[second], b), weight)

    score = lambda rows: combine(functions[first](rows), functions[second](rows))
    cal = thresholds(data["calibration"], combine(cached[first]["calibration"], cached[second]["calibration"]))
    trial["thresholds"] = cal
    trial["latency"] = latency(score, data["validation"])
    trial["evaluation"] = {}
    trial["pairedRecallVsStandalone"] = {}
    for part in ("validation", "uci-validation"):
        blended = combine(cached[first][part], cached[second][part])
        trial["evaluation"][part] = evaluate(data[part], blended, cal)
        trial["pairedRecallVsStandalone"][part] = {
            name: {target: paired_recall(data[part], blended, cut["threshold"], cached[name][part],
                                        baseline[name]["thresholds"][target]["threshold"])
                   for target, cut in cal.items()}
            for name in ("ngram", "cnn")
        }
    return trial


def evaluate_adaptation(root, functions, data, cached, baseline, aux_manifest):
    target_cal = data["uci-calibration"]
    result = {"calibrationRows": len(target_cal), "calibrationIdsSha256": ids_sha256(target_cal),
              "evaluationRows": len(data["uci-validation"]), "experiments": {}}
    for name in ("ngram", "cnn", "xgboost", "transformer"):
        local = thresholds(target_cal, functions[name](target_cal))
        values = cached[name]["uci-validation"]
        result["experiments"][name] = {"thresholds": local, "sourceThresholds": baseline[name]["thresholds"],
            "targetCalibrated": evaluate(data["uci-validation"], values, local),
            "pairedRecallDelta": {target: paired_recall(data["uci-validation"], values, cut["threshold"], values,
                            baseline[name]["thresholds"][target]["threshold"]) for target, cut in local.items()}}
    fit = read(root / "mixed" / "fit.json")
    if (fit["manifestSha256"] != CONFIG["phase5cManifestSha256"] or fit["protocolSha256"] != protocol_hash()
            or fit["targetTrainingViewSha256"] != aux_manifest["partitions"]["uci-adaptation"]["sha256"]):
        raise ValueError("Mixed model did not use frozen adaptation protocol")
    mixed = scorer("ngram", root / "mixed", fit)
    local = thresholds(target_cal, mixed(target_cal))
    result["experiments"]["mixed"] = {"fit": fit, "resources": read(root / "mixed-resources.json"),
        "thresholds": local, "targetCalibrated": evaluate(data["uci-validation"], mixed(data["uci-validation"]), local),
        "latency": latency(mixed, data["uci-validation"])}
    return result


def matched(previous, root, aux, aux_manifest):
    cohort = previous / "cohort"
    manifest = read(cohort / "manifest.json")
    if hash_file(cohort / "manifest.json") != CONFIG["phase5cManifestSha256"]:
        raise ValueError("Phase 5C snapshot no longer matches")
    archived = read(PHASE5C)
    data = {part: load_partition(cohort, manifest, part) for part in ("calibration", "validation", "uci-validation")}
    data.update({part: load_partition(aux, aux_manifest, part) for part in ("fusion-fit", "uci-calibration")})
    output = {}
    for size in (1000, 20000, 50000, 70570):
        directory = root / f"transformer-{size}"
        fit = read(directory / "fit.json")
        if fit["cohortSha256"] != CONFIG["phase5cManifestSha256"]:
            raise ValueError("Transformer training manifest changed")
        subsets = {part: members[:1000] if size == 1000 else members for part, members in data.items()}
        evaluation_parts = ("validation",) if size == 1000 else ("validation", "uci-validation")
        functions = {"transformer": scorer("transformer", directory, fit)}
        old = {row["model"]: row for row in archived.get(str(size), [])}
        if size in (20000, 50000):
            for name, prior in old.items():
                if prior["trainIdsSha256"] != fit["trainIdsSha256"]:
                    raise ValueError("Transformer and baseline training membership differs")
                functions[name] = scorer(name, previous / f"scale-{size}" / name, prior)
        scores = {}
        runs = {}
        for name, score in functions.items():
            scores[name] = {part: score(subsets[part]) for part in ("calibration", *evaluation_parts)}
            cuts = thresholds(subsets["calibration"], scores[name]["calibration"])
            runs[name] = {"thresholds": cuts, "evaluation": {
                part: evaluate(subsets[part], scores[name][part], cuts, with_intervals=size != 1000)
                for part in evaluation_parts
            }}
            if name != "transformer":
                runs[name]["phase5cReplayDelta"] = {
                    part: verify_replay(old[name]["evaluation"][part], runs[name]["evaluation"][part])
                    for part in evaluation_parts
                }
                runs[name]["originalBenchmark"] = {
                    key: old[name][key] for key in ("modelBytes", "fitSeconds", "latencyMedianMs", "latencyP95Ms",
                                                  "resources", "parameters") if key in old[name]
                }
            else:
                runs[name].update({"fit": fit, "resources": read(root / f"transformer-{size}-resources.json"),
                                   "latency": latency(score, subsets["validation"])})
            print(f"Matched {size} {name} complete", flush=True)
        output[str(size)] = runs
        if size == 20000:
            fusion = evaluate_fusion(functions, data, scores, runs)
            adaptation = evaluate_adaptation(root, functions, data, scores, runs, aux_manifest)
    return output, fusion, adaptation


def temporal(root, directory, manifest):
    pin = protocol_hash()
    manifest_pin = hash_file(directory / "manifest.json")
    data = load_partition(directory, manifest, "calibration")
    models = {}
    training_ids = None
    for name in ("transformer", "ngram", "cnn", "xgboost"):
        artifact = root / ("temporal-" + name)
        fit = read(artifact / "fit.json")
        if (fit.get("cohortSha256", fit.get("manifestSha256")) != manifest_pin
                or fit["trainRows"] != CONFIG["temporalBalancedRows"]):
            raise ValueError("Temporal checkpoint did not use frozen training view")
        if training_ids is not None and training_ids != fit["trainIdsSha256"]:
            raise ValueError("Temporal comparison used different training memberships")
        training_ids = fit["trainIdsSha256"]
        score = scorer(name, artifact, fit)
        cuts = thresholds(data, score(data))
        models[name] = (score, {"fit": fit, "thresholds": cuts,
                               "resources": read(root / (f"temporal-{name}-resources.json"))})
    # Persist locked thresholds and verify the protocol before opening either evaluation window.
    frozen = {"protocolSha256": pin, "cohortSha256": manifest_pin, "models": {
        name: {"modelSha256": report["fit"]["modelSha256"], "thresholds": report["thresholds"]}
        for name, (_, report) in models.items()}}
    receipt = root / "temporal-freeze.json"
    try:
        with receipt.open("x", encoding="utf-8") as stream:
            json.dump(frozen, stream, indent=2)
    except FileExistsError:
        if read(receipt) != frozen:
            raise ValueError("Temporal freeze differs from prior threshold receipt") from None
    holdouts = {part: load_partition(directory, manifest, part) for part in ("near", "far")}
    reports = {}
    for name, (score, report) in models.items():
        report["evaluation"] = {part: evaluate(rows, score(rows), report["thresholds"]) for part, rows in holdouts.items()}
        report["latency"] = latency(score, holdouts["near"])
        reports[name] = report
        print(f"Temporal {name} complete", flush=True)
    return reports


def run(previous, root, prepared=None):
    import torch
    prep = prepared or root / "prepared"
    temporal_dir, aux_dir = prep / "temporal", prep / "auxiliary"
    temporal_m, aux_m = read(temporal_dir / "manifest.json"), read(aux_dir / "manifest.json")
    digest = protocol_hash()
    if temporal_m["protocolSha256"] != digest or aux_m["protocolSha256"] != digest:
        raise ValueError("Frozen development protocol changed")
    if prepared is not None:
        original = read(root / "prepared" / "auxiliary" / "manifest.json")
        if any(original["partitions"][name] != aux_m["partitions"][name]
               for name in ("uci-calibration", "uci-adaptation")):
            raise ValueError("The fusion-view rebuild changed an adaptation input")
    fusion_spec = aux_m["partitions"]["fusion-fit"]
    if not fusion_spec["positive"] or not fusion_spec["negative"]:
        raise ValueError("Fusion fitting requires both labels before evaluation can start")
    torch.set_num_threads(2)
    torch.set_num_interop_threads(1)
    with threadpool_limits(limits=2):
        matched_runs, fusion, adaptation = matched(previous, root, aux_dir, aux_m)
        temporal_runs = temporal(root, temporal_dir, temporal_m)
    result = {"protocolSha256": digest, "dataAudit": read(prep / "audit.json"), "matched": matched_runs,
              "fusion": fusion, "adaptation": adaptation, "temporal": temporal_runs}
    with (root / "results.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=private)
    parser.add_argument("root", type=private)
    parser.add_argument("--prepared", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
