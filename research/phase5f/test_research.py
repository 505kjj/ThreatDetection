import unittest

import numpy as np

from fusion_lab import selective_outcomes, training_weights
from grouping import collision_audit, grouped_views, signatures
from replay import FEATURES


def row(name, part, label, elements=5, domain=None, **features):
    return {"id": name, "partition": part, "label": label,
            "identity": {"group": domain or name, "family": "", "alias": "", "exact": ""},
            "dom": dict.fromkeys(FEATURES, 0) | {"elements": elements} | features}


class Phase5FTests(unittest.TestCase):
    def test_template_family_and_near_matches_quarantine_transitively(self):
        train = [row("near", "train", 1, 8, "shared"),
                 row("domain-peer", "train", 0, 30, "shared"),
                 row("kept", "train", 0, 30, inputs_password=1)]
        validation = [row("held", "validation", 1, 5)]
        cal = [row("family", "calibration", 1, 6, title_length=5)]
        views, audit = grouped_views({"train": train, "tuning": [], "calibration": cal, "validation": validation})
        self.assertEqual([item["id"] for item in views["train"]], ["kept"])
        self.assertEqual(views["calibration"], [])
        self.assertEqual(audit["largestComponent"], 4)
        self.assertNotEqual(signatures(cal[0])[0], signatures(validation[0])[0])
        self.assertEqual(signatures(cal[0])[1], signatures(validation[0])[1])

    def test_collision_audit_distinguishes_opposite_labels(self):
        audit = collision_audit([row("a", "train", 1), row("b", "train", 0)], [row("c", "validation", 1)])
        self.assertEqual(audit["rows"], 1)
        self.assertEqual(audit["hasOppositeLabelPeer"], 1)

    def test_abstained_phishing_stays_in_recall_denominator(self):
        rows = [row("a", "validation", 1), row("b", "validation", 1), row("c", "validation", 0)]
        result = selective_outcomes(rows, np.array([0.95, 0.80, 0.10]), 0.75,
                                    np.array([False, True, False]), np.array([True, False, True]))[0]
        self.assertEqual(result["overallRecall"], 0.5)
        self.assertEqual(result["abstainedPhishing"], 1)
        self.assertEqual(result["elevatedRiskRows"], 1)

    def test_negative_reweighting_preserves_total_class_weight(self):
        weights = training_weights([row("password", "train", 0, inputs_password=1),
                                    row("ordinary", "train", 0), row("positive", "train", 1)])
        np.testing.assert_allclose(weights, [1.5, 0.5, 1])
