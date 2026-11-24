import unittest
from collections import Counter

import numpy as np

from archive import archive_record, observation_day
from evaluate import detection_counts, suppress_single_class


class ArchiveTests(unittest.TestCase):
    def test_real_submission_date_without_a_synthetic_verification_time(self):
        self.assertEqual(observation_day("added on Feb 21st 2014 4:16 PM"), "2014-02-21")
        self.assertIsNone(observation_day("added on Feb 29th 2014 4:16 PM"))
        self.assertIsNone(observation_day("just now"))

    def test_label_belongs_to_the_pinned_archive_and_requires_provider_reference(self):
        row = {"B": "https://www.phishtank.org/phish_detail.php?phish_id=123",
               "C": "https://sample.test/login", "D": "added on Feb 21st 2014 4:16 PM", "H": "VALID PHISH"}
        audit = Counter()
        first = archive_record(2, row, "phishtank-archive-1", audit, "H")
        self.assertEqual((first["id"], first["label"], first["cohort"]), ("pt-123", 1, "general-transfer"))
        self.assertIsNone(first["verificationDay"])
        self.assertIsNone(first["brand"])
        self.assertIsNone(archive_record(3, row | {"H": "Offline"}, "phishtank-archive-1", audit, "H"))
        self.assertIsNone(archive_record(4, row | {"B": "https://sample.test/"}, "phishtank-archive-1", audit, "H"))
        self.assertEqual(1, audit["notVerified"])
        self.assertEqual(1, audit["invalidReferenceOrUrl"])


class EvaluationTests(unittest.TestCase):
    def test_does_not_treat_single_class_precision_or_f1_as_a_measure(self):
        matrix = {"precision": 1, "f1": 0.5, "recall": 0.25, "precisionBinomial95": [0.1, 1]}
        same = matrix.copy()
        result = {"support": {"phishing": 4, "legitimate": 0}, "brandAmber": matrix.copy(),
                  "candidates": {"rf": {"cutoffs": {"0.001": {"metrics": matrix,
                                                               "advisoryOnlyUnionMetrics": same}}}}}
        suppress_single_class(result)
        self.assertIsNone(matrix["precision"])
        self.assertIsNone(matrix["f1"])
        self.assertEqual(matrix["recall"], 0.25)
        self.assertIsNone(same["precisionBinomial95"])

    def test_counts_true_extra_detections_without_double_counting_fusion(self):
        plan = {"primaryDomainTarget": .001, "secondaryDomainTarget": .01, "candidateOrder": ["rf", "two", "four"]}
        scores = {"rf": np.array([.9, .1, .1, .9]), "two": np.array([.1, .9, .1, .1]),
                  "four": np.array([.1, .9, .1, .9])}
        frozen = {name: {"0.001": .7, "0.01": .5} for name in scores}
        result = detection_counts(scores, frozen, np.array([1, 1, 1, 0]), plan)["0.001"]
        self.assertEqual(result, {"missedByAll": 1, "detectedOnlyByAnyFusion": 1,
                                  "detectedOnlyByRandomForest": 1})


if __name__ == "__main__":
    unittest.main()
