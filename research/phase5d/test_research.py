import unittest

import numpy as np
import torch

from fusion import blend, pairwise, platt, probability, select
from metrics import cutoffs, disagreement, evaluate, paired_recall
from shared import represent
from transformer import LENGTH, URLTransformer, fit, inputs, predict


class TransformerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(2)

    def test_tokenizer_matches_phase5c_prefix_and_padding(self):
        examples = [{"id": "id", "partition": "train", "normalizedUrl": "https://fixture.test/☃"},
                    {"id": "id2", "partition": "train", "normalizedUrl": "https://fixture.test/" + "x" * 100}]
        tokens = inputs(examples)
        self.assertEqual(tokens.shape, (2, LENGTH))
        np.testing.assert_array_equal(tokens[0], represent(examples[0], "transformer")[2]["input_ids"][:LENGTH])
        self.assertIn(1, tokens[0])
        self.assertEqual(tokens[0, -1], 0)
        self.assertNotIn(0, tokens[1])

    def test_padding_mask_and_empty_sequences(self):
        torch.manual_seed(143)
        model = URLTransformer().eval()
        first = np.array([[2, 23, 7]])
        padding = np.pad(first, [(0, 0), (0, LENGTH - first.shape[1])])
        np.testing.assert_allclose(predict(model, first), predict(model, padding), atol=1e-7, rtol=0)
        self.assertTrue(np.isfinite(predict(model, np.zeros_like(padding))).all())

    def test_training_and_inference_reproducibility(self):
        tokens = np.array([[7, 3, 0], [8, 9, 0], [7, 1, 0], [8, 4, 0]])
        targets = np.array([0, 1, 0, 1])
        first, first_fit = fit(tokens, targets, tokens, targets, 0.003, 2)
        second, second_fit = fit(tokens, targets, tokens, targets, 0.003, 2)
        self.assertEqual(first_fit, second_fit)
        np.testing.assert_array_equal(predict(first, tokens), predict(second, tokens))


class EvaluationTests(unittest.TestCase):
    def test_cutoffs_keep_unsupported_targets_unknown_and_zero_fpr_has_upper_bound(self):
        rows = [{"id": str(i), "label": i % 2, "identity": {"group": str(i)}} for i in range(8)]
        y = np.array([row["label"] for row in rows])
        scores = np.asarray(y, dtype=float)
        cuts = cutoffs(y, scores, np.array([row["id"] for row in rows]))
        actual = evaluate(rows, scores, cuts)
        self.assertIsNone(actual["atConstraints"]["0.0001"])
        self.assertEqual(actual["atHalf"]["falseAlertDomains"], 0)
        self.assertGreater(actual["atHalf"]["intervals"]["domainFpr95"][1], 0)
        self.assertEqual(actual["rankingIntervals"], {"prAuc95": [1.0, 1.0], "rocAuc95": [1.0, 1.0]})

    def test_fusion_alignment_calibration_and_disagreement(self):
        y = np.array([0, 0, 1, 1])
        a = np.array([0.1, 0.2, 0.7, 0.3])
        b = np.array([0.1, 0.7, 0.7, 0.8])
        self.assertEqual(disagreement(y, a, b, 0.5, 0.5)["secondOnlyTruePositives"], 1)
        self.assertEqual(pairwise(y, {"a": a, "b": b}, {"a": None, "b": 0.5}), {"a+b": None})
        np.testing.assert_allclose(blend(a, b, 0.25), a * 0.25 + b * 0.75)
        self.assertTrue(np.all(np.diff(probability(platt(y, a), np.sort(a))) >= 0))
        with self.assertRaisesRegex(ValueError, "aligned"):
            blend(a, b[:3], 0.5)
        _, analysis = select(y, np.array(["a", "b", "c", "d"]),
                             {"ngram": a, "cnn": b, "xgboost": a, "transformer": b})
        self.assertIsNone(analysis["selected"])

    def test_supported_disjoint_signals_are_eligible_for_fusion(self):
        negatives = 4000
        y = np.concatenate([np.zeros(negatives, dtype=int), np.ones(100, dtype=int)])
        a = np.full(len(y), 0.1)
        b = a.copy()
        a[negatives:negatives + 60] = 0.9
        b[negatives + 40:] = 0.9
        groups = np.array([str(i) for i in range(len(y))])
        _, analysis = select(y, groups, {"ngram": a, "cnn": b, "xgboost": a, "transformer": a})
        self.assertEqual(analysis["selected"]["partner"], "cnn")
        self.assertGreaterEqual(analysis["selected"]["partnerExclusiveRecall"], 0.4)

    def test_paired_recall_uses_shared_domain_resamples(self):
        rows = [{"label": 1, "identity": {"group": "same"}} for _ in range(3)]
        delta = paired_recall(rows, np.array([0.9, 0.6, 0.1]), 0.5, np.array([0.9, 0.3, 0.1]), 0.5)
        self.assertAlmostEqual(delta["delta"], 1 / 3)
        np.testing.assert_allclose(delta["delta95"], [1 / 3, 1 / 3])
