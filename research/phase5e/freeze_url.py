"""Freeze the Phase 5D candidate artifacts and operating points before any independent scoring."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import numpy as np
from scipy.special import expit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "phase5d"))
from shared import private
from evaluate import hash_file, read, scorer
from fusion import logistic_input

D_REVISION = "3e08561efb7150c414ceb231f3313c49b27a0c81"
REPORT = ROOT / "docs" / "experiments" / "phase5d" / "results.json"
PREPROCESSING = (
    "evaluation/features.mjs", "extension/reputation.mjs", "research/phase5c/sequence.py",
    "research/phase5c/train.py", "research/phase5d/evaluate.py", "research/phase5d/transformer.py"
)


def repository_hash(name):
    return sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def operating_points(cutoffs):
    return {"fixed": 0.5, **{name: entry["threshold"] for name, entry in cutoffs.items()}}


def freeze(experiments):
    report = read(REPORT)
    matched = report["matched"]["20000"]
    models = {}
    for name in ("ngram", "cnn", "xgboost", "transformer", "mixed"):
        if name == "mixed":
            entry = report["adaptation"]["experiments"][name]
            source = entry["fit"]
            relative = "phase-5d-v1/mixed/model.joblib"
            kind, calibration = "ngram", "UCI development"
        else:
            entry = matched[name]
            source = entry.get("fit", entry.get("originalBenchmark"))
            suffix = ".pt" if name in ("cnn", "transformer") else ".joblib"
            relative = (f"phase-5d-v1/transformer-20000/model{suffix}" if name == "transformer"
                        else f"phase-5c-v1/scale-20000/{name}/model{suffix}")
            kind, calibration = name, "PhreshPhish development"
        expected = source.get("modelSha256")
        if expected is None:
            phase5c = read(ROOT / "docs" / "experiments" / "phase5c" / "metrics.json")
            expected = next(item["modelSha256"] for item in phase5c["20000"] if item["model"] == name)
        artifact = experiments / relative
        if hash_file(artifact) != expected or artifact.stat().st_size != source["modelBytes"]:
            raise ValueError("Frozen model artifact differs from its research receipt")
        models[name] = {"artifact": relative, "kind": kind, "sha256": expected,
                        "bytes": artifact.stat().st_size, "trainingRows": 20000,
                        "calibration": calibration, "operatingPoints": operating_points(entry["thresholds"])}
    fusion = report["fusion"]
    selection = fusion["selected"]
    if (selection["reference"], selection["partner"], selection["referenceWeight"]) != ("ngram", "xgboost", 0.75):
        raise ValueError("Unexpected Phase 5D fusion recipe")
    models["fusion"] = {"components": {"ngram": 0.75, "xgboost": 0.25},
                        "probabilityScales": fusion["probabilityScales"],
                        "calibration": "PhreshPhish development",
                        "operatingPoints": operating_points(fusion["thresholds"])}
    return {"revision": D_REVISION, "sourceReportSha256": repository_hash(str(REPORT.relative_to(ROOT))),
            "preprocessingSha256": {name: repository_hash(name) for name in PREPROCESSING},
            "featureVersion": "url-lexical-v1", "models": models}


def apply_fusion(scores, manifest):
    total = np.zeros_like(scores["ngram"], dtype=np.float64)
    for name, weight in manifest["components"].items():
        scale = manifest["probabilityScales"][name]
        log_odds = logistic_input(scores[name])[:, 0]
        total += weight * expit(scale["coefficient"] * log_odds + scale["intercept"])
    return total


def restore_candidate(experiments, manifest, name):
    if (manifest["revision"] != D_REVISION
            or manifest["sourceReportSha256"] != repository_hash(str(REPORT.relative_to(ROOT)))
            or manifest["preprocessingSha256"] != {key: repository_hash(key) for key in PREPROCESSING}):
        raise ValueError("Frozen URL preprocessing or source report differs")
    item = manifest["models"][name]
    if name == "fusion":
        parts = {key: restore_candidate(experiments, manifest, key) for key in item["components"]}
        return lambda rows: apply_fusion({key: predict(rows) for key, predict in parts.items()}, item)
    artifact = private(experiments / item["artifact"])
    return scorer(item["kind"], artifact.parent, {"modelSha256": item["sha256"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", type=private)
    parser.add_argument("output", type=private)
    args = parser.parse_args()
    report = freeze(args.experiments)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
    print(f"Verified and froze {len(report['models'])} Phase 5D candidates")
