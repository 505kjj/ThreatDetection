import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

# Match the entry points that run these scripts directly from the research folder.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_phiusiil import claim_holdout
from experiment_metrics import classify, negative_domain_scores, threshold_at_target
from experiment_models import fit_model, stop_partition
from train_phiusiil import audit_features


class ExperimentTests(unittest.TestCase):
    def test_negative_domains_and_conservative_threshold_ties(self):
        labels = np.array([0, 0, 0, 1])
        groups = np.array(["a", "a", "b", "c"])
        scores = np.array([0.4, 0.7, 0.3, 0.8], dtype=np.float32)
        self.assertEqual(len(negative_domain_scores(labels, scores, groups)), 2)
        unsupported = threshold_at_target(np.full(10, 0.4), 0.001, 0.05)
        self.assertIsNone(unsupported["threshold"])
        tied = threshold_at_target(np.full(5000, scores[1], dtype=np.float64), 0.001, 0.05)
        result = classify(labels, scores, groups, tied["threshold"])
        self.assertEqual((result["fp"], result["tp"]), (0, 1))

    def test_train_only_audit_rejects_obvious_feature_leakage(self):
        labels = np.array([0, 0, 1, 1])
        features = np.array([[0, 1], [0, 2], [1, 1], [1, 2]])
        with self.assertRaisesRegex(ValueError, "leakage"):
            audit_features(features, labels, ["leak", "structure"], ["leak"])
        self.assertTrue(audit_features(features, labels, ["leak", "structure"], ["structure"])["structure"]["used"])

    def test_holdout_cannot_be_claimed_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            claim_holdout(output, "fixture")
            with self.assertRaises(FileExistsError):
                claim_holdout(output, "fixture")

    def test_group_early_stops_keep_models_predicting(self):
        generator = np.random.default_rng(37)
        groups = np.repeat(np.arange(100), 2)
        labels = np.tile([0, 1], 100)
        x = generator.normal(size=(200, 3))
        x[:, 0] += labels
        training, stopping = stop_partition(x, labels, groups, 37)
        self.assertEqual(np.intersect1d(groups[training], groups[stopping]).size, 0)
        options = {
            "mlp": {"hidden_layer_sizes": [8], "alpha": 0.01, "batch_size": 16, "max_epochs": 3, "patience": 2},
            "xgboost": {"n_estimators": 4, "max_depth": 2, "learning_rate": 0.2, "patience": 2},
        }
        for name, params in options.items():
            with self.subTest(name=name):
                fit = fit_model(name, params, x, labels, groups, 37, 1)
                self.assertGreater(fit.rounds, 0)
                self.assertEqual(fit.estimator.predict_proba(x).shape, (200, 2))
                self.assertGreaterEqual(len(fit.trace["stopLogLoss"]), fit.rounds)
