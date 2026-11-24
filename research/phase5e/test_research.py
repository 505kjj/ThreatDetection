import unittest

import numpy as np

from acquire import ContentRanges, Remaining
from compare import FEATURES, model_input
from freeze_url import apply_fusion
from sensitivity import vector
from shared import SEED


class OfflineResearchTests(unittest.TestCase):
    def test_custody_excludes_publisher_test_names_and_big_ranges(self):
        with self.assertRaisesRegex(ValueError, "development"):
            ContentRanges("test-000", 10, Remaining(10))
        with ContentRanges("train-000", 10, Remaining(1)) as file:
            with self.assertRaisesRegex(OSError, "exceeds budget"):
                file.read(2)
            self.assertEqual(file.bytes, 0)

    def test_model_representation_uses_only_features_and_optional_url_lexical_vector(self):
        row = {"label": 1, "id": "fixture", "dom": dict.fromkeys(FEATURES, 2),
               "x": [1] * 14, "status": "oversized", "timings": {"parseMs": 500}}
        self.assertEqual(model_input([row], FEATURES).shape, (1, len(FEATURES)))
        self.assertTrue(np.all(model_input([row], FEATURES) == 2))
        self.assertEqual(model_input([row], FEATURES, True).shape, (1, len(FEATURES) + 14))

    def test_fusion_preserves_pinned_probabilities_and_weight(self):
        scores = {"ngram": np.array([0.2, 0.8]), "xgboost": np.array([0.8, 0.2])}
        fusion = {"components": {"ngram": 0.75, "xgboost": 0.25},
                  "probabilityScales": {name: {"coefficient": 1, "intercept": 0} for name in scores}}
        np.testing.assert_allclose(apply_fusion(scores, fusion), [0.35, 0.65])

    def test_sensitivity_vector_preserves_schema_order_without_neural_imports(self):
        self.assertEqual(SEED, 143)
        self.assertEqual(vector({"dom": dict.fromkeys(FEATURES, 2)}), (2,) * len(FEATURES))
