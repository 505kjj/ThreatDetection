import unittest

import numpy as np
from PIL import Image

from fixtures import invented_mark, padded
from vision import (Features, classify, decode, encode, hash_image, hash_similarity, interpret,
                    letterbox, orb_similarity, within_scope)


class VisualResearchTests(unittest.TestCase):
    def test_rejects_untrusted_markup_and_truncated_raster(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            decode(b"<svg xmlns='http://www.w3.org/2000/svg'><script>throw 1</script></svg>")
        with self.assertRaises(ValueError):
            decode(encode(invented_mark(0))[:-40])

    def test_dimension_budget_and_animation_are_checked(self):
        image = Image.new("RGB", (2049, 5))
        with self.assertRaisesRegex(ValueError, "dimensions"):
            decode(encode(image))
        data = encode(Image.new("RGBA", (12, 12), "red"), save_all=True,
                      append_images=[Image.new("RGBA", (12, 12), "blue")], duration=50)
        with self.assertRaisesRegex(ValueError, "frame count"):
            decode(data)

    def test_alpha_padding_is_removed_without_squeezing_pixels(self):
        image = invented_mark(0)
        np.testing.assert_array_equal(letterbox(image), letterbox(padded(image)))
        with self.assertRaisesRegex(ValueError, "transparent"):
            letterbox(Image.new("RGBA", (14, 14)))

    def test_hash_uses_63_ac_bits_and_returns_self_match(self):
        value = hash_image(letterbox(invented_mark(0)))
        self.assertLess(value, 1 << 63)
        self.assertEqual(hash_similarity(value, value), 1)
        self.assertAlmostEqual(hash_similarity(value, value ^ 1), 62 / 63)

    def test_thresholds_abstain_from_tied_matches_and_missing_descriptors(self):
        features = Features("sha", 1, None, np.ones(1))
        self.assertEqual(classify(features, [("a", features), ("b", features)], "phash"), ("ambiguous", None))
        self.assertIsNone(orb_similarity(None, np.zeros((9, 32), dtype=np.uint8)))

    def test_visual_and_domain_outcomes_are_kept_distinct(self):
        brands = {"bank": {"scopes": ["bank.example"], "sharedHosts": ["bank.docs.example"]}}
        self.assertTrue(within_scope("auth.bank.example", brands["bank"]["scopes"], brands["bank"]["sharedHosts"]))
        self.assertFalse(within_scope("bank.example.foreign.test", brands["bank"]["scopes"], []))
        self.assertFalse(within_scope("example.bank.docs.example", [], brands["bank"]["sharedHosts"]))
        match = [("recognized", "bank")]
        self.assertEqual(interpret("bank.example", match, brands), "recognized-brand-on-authorized-domain")
        self.assertEqual(interpret("shop.example", match, brands), "recognized-brand-on-unverified-domain")
        self.assertEqual(interpret("shop.example", [("unrecognized", None)], brands), "unrecognized-brand")
        self.assertEqual(interpret("shop.example", [], brands), "missing-visual-evidence")
