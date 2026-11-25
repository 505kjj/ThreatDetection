"""Create synthetic references for the existing frozen fusion parameters."""

import argparse
import json
from pathlib import Path

import numpy as np
from scipy.special import expit, logit

ROOT = Path(__file__).resolve().parents[2]


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main(experiment):
    phase5d = load(ROOT / "docs/experiments/phase5e/frozen-url.json")["models"]["fusion"]
    phase5g = load(ROOT / "docs/experiments/phase5g/frozen-models.json")
    url = load(experiment / "ngram/reference.json")
    grouped = load(experiment / "ngram-f/reference.json")
    trees = {name: load(experiment / f"xgboost/{name}-reference.json") for name in ("url", "dom")}
    count = len(url["scores"])

    def scale(scores, weight, intercept):
        return expit(weight * logit(np.clip(scores, 1e-6, 1 - 1e-6)) + intercept)

    d = phase5d["probabilityScales"]
    d_scores = (0.75 * scale(url["scores"], d["ngram"]["coefficient"], d["ngram"]["intercept"])
                + 0.25 * scale(trees["url"]["scores"][:count], d["xgboost"]["coefficient"], d["xgboost"]["intercept"]))
    calibration = phase5g["phase5fParameters"]["calibration"]
    f_scores = (0.75 * scale(grouped["scores"], *calibration["url-ngram"])
                + 0.25 * scale(trees["dom"]["scores"][:count], *calibration["dom-weighted"]))
    result = {"fixtures": url["fixtures"], "urlVectors": trees["url"]["vectors"][:count],
              "domVectors": trees["dom"]["vectors"][:count], "tolerance": 2e-6,
              "phase5d": {"scores": d_scores.tolist(), "scales": d, "thresholds": phase5d["operatingPoints"]},
              "phase5f": {"scores": f_scores.tolist(), "scales": calibration,
                           "thresholds": phase5g["models"]["fixed"]["operatingPoints"]}}
    with (experiment / "fusion-reference.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"fixtures": count, "tolerance": result["tolerance"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path)
    args = parser.parse_args()
    if args.experiment.resolve().is_relative_to(ROOT.resolve()):
        parser.error("Experiment must be outside the repository")
    main(args.experiment)
