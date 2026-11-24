import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

from membership import Rows, verified_ids
from sequence import CharacterCNN, LENGTH, fit, predict, represent, tokenize
from train import balanced, build_input, evaluate, ids_sha256


class SequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(2)

    def test_tokenizer_padding_unknown_and_prefix_truncation(self):
        below_limit = tokenize("ab☃")
        self.assertEqual(below_limit.shape, (LENGTH,))
        self.assertEqual(below_limit[2], 1)
        self.assertFalse(below_limit[3:].any())
        np.testing.assert_array_equal(tokenize("a" * LENGTH), tokenize("a" * LENGTH + "later"))

    def test_views_preserve_keys_and_derive_only_from_normalized_url(self):
        row = {"id": "fixture", "partition": "validation", "url": "https://fixture.test/?token=placeholder",
               "normalizedUrl": "https://fixture.test/", "x": list(range(14))}
        for kind in ("numeric", "ngram", "cnn", "transformer"):
            self.assertEqual(represent(row, kind)[:2], ("fixture", "validation"))
        np.testing.assert_array_equal(build_input("cnn", [row])[0], represent(row, "cnn")[2])
        self.assertEqual(build_input("ngram", [row])[0], represent(row, "ngram")[2])
        self.assertEqual(build_input("logistic", [row])[0].tolist(), represent(row, "numeric")[2])
        future = represent(row, "transformer")[2]
        np.testing.assert_array_equal(future["attention_mask"], future["input_ids"] != 0)

    def test_training_and_checkpoint_inference(self):
        values = ["https://fixture.test/a", "https://fixture.test/b", "https://demo.test/a", "https://demo.test/b"]
        x = np.stack([tokenize(value) for value in values])
        labels = np.array([0, 1, 0, 1])
        model, metadata = fit(x, labels, x, labels, epochs=2)
        repeated, repeated_metadata = fit(x, labels, x, labels, epochs=2)
        self.assertEqual(metadata, repeated_metadata)
        np.testing.assert_array_equal(predict(model, x), predict(repeated, x))
        with tempfile.TemporaryDirectory() as folder:
            checkpoint = Path(folder) / "fixture.pt"
            torch.save(model.state_dict(), checkpoint)
            restored = CharacterCNN()
            restored.load_state_dict(torch.load(checkpoint, weights_only=True, map_location="cpu"))
            np.testing.assert_array_equal(predict(model, x), predict(restored, x))
        self.assertTrue(np.isfinite(predict(model, np.zeros_like(x))).all())

    def test_matched_membership_and_confusion_matrix(self):
        rows = [{"id": str(i), "label": i % 2, "identity": {"group": str(i)}} for i in range(6)]
        subset = balanced(rows, 4)
        self.assertEqual([row["id"] for row in subset], ["0", "1", "2", "3"])
        report = evaluate(subset, np.array([0.0, 0.9, 0.7, 0.1]), {0.001: {"threshold": None}})
        self.assertEqual(report["idsSha256"], ids_sha256(subset))
        self.assertEqual(report["confusionMatrix"], [[1, 1], [1, 1]])
        self.assertIsNone(report["atCalibratedConstraints"]["0.001"])

    def test_legacy_recovery_checks_each_ordered_feature_and_group(self):
        raw = [{"sourceId": "source-one", "ordinal": 3, "label": 1, "group": "first", "x": [1]},
               {"sourceId": "source-two", "ordinal": 6, "label": 0, "group": "second", "x": [0]}]
        numerical = Rows(np.array([[1], [0]]), np.array([1, 0]), np.array(["first", "second"]), np.array(["", ""]))
        verified_ids(raw, numerical, "phiusiil-uci-967", "fixture")
        self.assertNotEqual(raw[0]["id"], raw[1]["id"])
        with self.assertRaisesRegex(ValueError, "legacy numerical row"):
            verified_ids(list(reversed(raw)), numerical, "phiusiil-uci-967", "fixture")


if __name__ == "__main__":
    unittest.main()
