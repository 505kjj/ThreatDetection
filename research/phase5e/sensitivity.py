"""Measure DOM-blend recall on matched validation rows with unseen feature vectors."""

import argparse
import json
import os

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from compare import FEATURES, balanced, build_input, hash_file, ids_sha256, load_matched, model_input, private, read
from freeze_url import apply_fusion
from metrics import evaluate, paired_recall


def vector(row):
    return tuple(row["dom"][feature] for feature in FEATURES)


def run(cohort, experiment, output, projections):
    report = read(experiment / "results.json")
    pools, audit = load_matched(cohort, projections)
    training = balanced(pools["train"], report["rows"])
    validation = pools["validation"]
    if (ids_sha256(training) != report["identities"]["train"]
            or ids_sha256(validation) != report["identities"]["validation"]
            or audit["canonicalSha256"] != report["audit"]["canonicalSha256"]):
        raise ValueError("Matched sensitivity view differs from the fitted experiment")
    signatures = {vector(row) for row in training}
    retained = [row for row in validation if vector(row) not in signatures]
    counts = {"rows": len(retained), "positive": sum(row["label"] for row in retained),
              "validationRows": len(validation), "excludedRepeatedVectors": len(validation) - len(retained)}
    artifacts = {}
    for name in ("url-ngram", "dom-xgboost"):
        path = experiment / name / "model.joblib"
        if hash_file(path) != report["models"][name]["fit"]["modelSha256"]:
            raise ValueError("Sensitivity checkpoint checksum differs")
        artifacts[name] = joblib.load(path)
    blend = report["models"]["url-dom-fusion"]
    weight = blend["fit"]["referenceWeight"]
    with threadpool_limits(limits=2):
        url = artifacts["url-ngram"].predict_proba(build_input("ngram", retained))[:, 1]
        dom = artifacts["dom-xgboost"].predict_proba(model_input(retained, FEATURES))[:, 1]
        fused = apply_fusion({"ngram": url, "dom-xgboost": dom}, {
            "components": {"ngram": weight, "dom-xgboost": 1 - weight},
            "probabilityScales": {"ngram": blend["fit"]["componentScales"]["url-ngram"],
                                  "dom-xgboost": blend["fit"]["componentScales"]["dom-xgboost"]}
        })
        url_cuts = report["models"]["url-ngram"]["thresholds"]
        blend_cuts = blend["thresholds"]
        result = {"coverage": counts, "url": evaluate(retained, np.asarray(url, dtype=np.float64), url_cuts),
                  "urlDomBlend": evaluate(retained, fused, blend_cuts),
                  "pairedRecallAtOnePercent": paired_recall(retained, fused, blend_cuts["0.01"]["threshold"],
                                                            url, url_cuts["0.01"]["threshold"])}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
    print(json.dumps({"coverage": counts, "pairedRecallAtOnePercent": result["pairedRecallAtOnePercent"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=private)
    parser.add_argument("experiment", type=private)
    parser.add_argument("output", type=private)
    parser.add_argument("--projections", nargs="+", type=private, required=True)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
