"""Prepare estimators and validate Phase 3A feature exports without fitting."""

import argparse
import json
from importlib.metadata import version
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


FEATURE_VERSION = "url-lexical-v1"
FEATURE_COUNT = 14
SPLITS = ("train", "validation", "test")
LABELS = ("phishing", "legitimate")
SEED = 37


def make_estimators():
    """Return independent, unfitted CPU estimator candidates."""
    return {
        "logistic_regression": make_pipeline(
            StandardScaler(), LogisticRegression(random_state=SEED, max_iter=500)
        ),
        "random_forest": RandomForestClassifier(random_state=SEED, n_jobs=1),
        "xgboost": XGBClassifier(
            device="cpu", tree_method="hist", random_state=SEED, n_jobs=1,
            objective="binary:logistic", eval_metric="logloss",
        ),
        "mlp": make_pipeline(
            StandardScaler(),
            MLPClassifier(hidden_layer_sizes=(32, 16), random_state=SEED),
        ),
    }


def check_feature_export(path):
    """Count valid feature rows in their existing split and label buckets."""
    counts = {split: dict.fromkeys(LABELS, 0) for split in SPLITS}
    with Path(path).open("r", encoding="utf-8") as source:
        while line := source.readline(4097):
            if len(line) > 4096:
                raise ValueError("Feature row exceeds its size limit.")
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError("Invalid feature row.") from None
            if (
                not isinstance(row, dict)
                or set(row) != {"featureVersion", "split", "label", "values"}
                or row["featureVersion"] != FEATURE_VERSION
                or row["split"] not in SPLITS
                or row["label"] not in LABELS
                or not isinstance(row["values"], list)
                or len(row["values"]) != FEATURE_COUNT
                or any(type(value) is not int or value < 0 for value in row["values"])
            ):
                raise ValueError("Feature row does not match the Phase 3A contract.")
            counts[row["split"]][row["label"]] += 1
    if not any(sum(labels.values()) for labels in counts.values()):
        raise ValueError("Feature export is empty.")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, help="Optional Phase 3A JSONL feature export")
    args = parser.parse_args()
    report = {
        "estimators": list(make_estimators()),
        "dependencies": {name: version(name) for name in ("scikit-learn", "xgboost-cpu")},
        "featureVersion": FEATURE_VERSION,
        "featureCount": FEATURE_COUNT,
        "trainingPerformed": False,
    }
    if args.features:
        try:
            report["featureRowsBySplit"] = check_feature_export(args.features)
        except (OSError, UnicodeError, ValueError):
            parser.exit(2, "Could not validate the Phase 3A feature export.\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
