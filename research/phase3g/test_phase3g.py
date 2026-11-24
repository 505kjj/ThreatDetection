import unittest

import numpy as np

from analyze import audit_scoring, overlap, part, supports, verify_reproduction


class FrozenLeaf:
    n_features_in_ = 1
    classes_ = [0, 1]

    def predict_proba(self, values):
        positive = values[:, 0]
        return np.column_stack((1 - positive, positive))


class Phase3GTests(unittest.TestCase):
    def test_frozen_weighted_scores_reconstruct_without_fitting(self):
        model = FrozenLeaf()
        bundle = {"mode": "blend", "columns": (0,), "models": [model, model],
                  "calibrators": [model, model], "weights": np.array([.25, .75])}
        rows = np.array([[.2], [.8]], dtype=np.float64)
        got, error = audit_scoring(bundle, rows)
        np.testing.assert_allclose(got, [.2, .8], rtol=0, atol=1e-12)
        self.assertLessEqual(error, 1e-12)
        with self.assertRaisesRegex(ValueError, "weights"):
            audit_scoring(bundle | {"weights": [1, 1]}, rows)

    def test_feature_bins_and_zero_support(self):
        self.assertEqual(["short", "medium", "long"], list(part([9, 10, 20], [10, 20],
                                                                ["short", "medium", "long"])))
        self.assertIsNone(supports(np.array([], dtype=bool))["exact95"])
        self.assertEqual(supports(np.array([True, False]))["missed"], 1)

    def test_patterns_and_pairwise_misses(self):
        plan = {"limits": {"pairedBootstrapResamples": 50, "seed": 219}}
        calls = {"model-a": np.array([False, True, False, True]),
                 "model-b": np.array([False, False, True, True])}
        report = overlap(calls, np.array(["d1", "d2", "d3", "d4"]), plan)
        self.assertEqual(report["decisionPatterns"], {"00": 1, "01": 1, "10": 1, "11": 1})
        pair = report["pairs"]["model-a/model-b"]
        self.assertEqual([1, 1, 1, 1], [pair[key] for key in ("bothDetected", "bothMissed", "leftOnly", "rightOnly")])

    def test_reproduction_rejects_changed_outcomes_even_when_model_hash_matches(self):
        previous = {"cohorts": {"test": 2}, "runtime": {"a": {"sha256": "hash", "storageBytes": 100, "loadMs": 2}}}
        reproduced = previous | {"runtime": {"a": {"sha256": "hash", "storageBytes": 100, "loadMs": 4}}}
        verify_reproduction({"manifestSha256": "hash"}, reproduced, previous)
        with self.assertRaisesRegex(ValueError, "cohorts"):
            verify_reproduction({"manifestSha256": "hash"}, reproduced | {"cohorts": {"test": 3}}, previous)


if __name__ == "__main__":
    unittest.main()
