import json
import tempfile
import unittest
from pathlib import Path

from sklearn.utils.validation import check_is_fitted
from sklearn.exceptions import NotFittedError

from research.preflight import FEATURE_COUNT, FEATURE_VERSION, check_feature_export, make_estimators


def feature_row(split="train", label="phishing"):
    return {
        "featureVersion": FEATURE_VERSION,
        "split": split,
        "label": label,
        "values": [1] * FEATURE_COUNT,
    }


class ResearchPreflightTests(unittest.TestCase):
    def test_estimators_start_unfitted(self):
        estimators = make_estimators()
        self.assertEqual(
            set(estimators), {"logistic_regression", "random_forest", "xgboost", "mlp"}
        )
        for name, estimator in estimators.items():
            with self.subTest(name=name), self.assertRaises(NotFittedError):
                check_is_fitted(estimator)
        self.assertEqual(estimators["xgboost"].get_params()["device"], "cpu")

    def test_keeps_declared_splits_and_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.jsonl"
            rows = [feature_row(), feature_row("test", "legitimate")]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            self.assertEqual(
                check_feature_export(path),
                {
                    "train": {"phishing": 1, "legitimate": 0},
                    "validation": {"phishing": 0, "legitimate": 0},
                    "test": {"phishing": 0, "legitimate": 1},
                },
            )

    def test_rejects_unexpected_fields_and_feature_shapes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.jsonl"
            for changes in [
                {"split": "random"},
                {"featureVersion": "other"},
                {"values": [1]},
                {"values": [True] * FEATURE_COUNT},
                {"hostname": "synthetic.example.test"},
            ]:
                with self.subTest(fields=changes.keys()):
                    path.write_text(json.dumps({**feature_row(), **changes}), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        check_feature_export(path)
