from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

import numpy as np

from cohort import PROTOCOL, checksum, phishvn, read
from score import compare, exact_interval, pair_difference


class ScoreTests(unittest.TestCase):
    def test_archive_selection_requires_verified_provenance_and_dates(self):
        config = read(PROTOCOL)
        with TemporaryDirectory() as temp:
            archive = Path(temp) / "fixture.zip"
            with ZipFile(archive, "w") as output:
                output.writestr("data/dataset_url.csv",
                    "id,url,source,label,tier,collected_at,scenario,status\n"
                    "a,https://quartz.test/access,tinnhiemmang,phishing,gold,2026-04-01,bank,handled\n"
                    "b,https://larch.test/help,tinnhiem_org,benign,gold,2026-04-02,other,trusted\n"
                    "c,https://ruby.test/,tranco,benign,gold,2026-04-03,other,listed\n"
                    "d,https://elm.test/,tinnhiemmang,phishing,silver,2026-04-04,bank,pending\n"
                    "e,https://pine.test/,tinnhiemmang,phishing,gold,2025-12-16,other,handled\n")
            audit = Counter()
            policy = config["sourcePolicy"] | {"archiveSha256": checksum(archive)}
            records = list(phishvn(archive, policy, config["window"], audit))
        self.assertEqual([("a", 1), ("b", 0)], [(row["id"], row["label"]) for row in records])
        self.assertEqual(2, audit["outsideApprovedSourcesOrTier"])
        self.assertEqual(1, audit["outsideObservationWindow"])

    def test_paired_differences_distinguish_extra_and_lost_detections(self):
        y = np.array([1, 1, 0, 0, 1, 0])
        a = np.array([1, 0, 0, 1, 0, 0], dtype=bool)
        b = np.array([0, 1, 1, 0, 0, 0], dtype=bool)
        result = pair_difference(y, np.array(list("abcdef")), a, b, 50, 219)
        self.assertEqual((1, 1, 1, 1), tuple(result[key] for key in
            ("extraPhish", "lostPhish", "extraFalsePositives", "avoidedFalsePositives")))
        self.assertEqual(1, result["sharedErrors"])
        self.assertEqual(0, result["recallDelta"])
        self.assertLessEqual(result["pairedRecallDeltaDomainBootstrap95"][0], 0)

    def test_negative_only_controls_never_produce_recall_fusion_gain_or_ap(self):
        rows = [{"y": 0, "group": "first", "amber": False, "date": "2026-04-01"}]
        config = {"candidateOrder": ["rf"], "primaryDomainTarget": .001, "secondaryDomainTarget": .01,
                  "limits": {"pairedBootstrapResamples": 50, "seed": 2}}
        report = compare(rows, {"rf": np.array([.5])}, {"rf": {"0.001": .8, "0.01": .7}}, config)
        model = report["candidates"]["rf"]
        self.assertIsNone(model["ranking"])
        self.assertIsNone(model["cutoffs"]["0.001"]["metrics"]["recall"])
        self.assertIsNone(model["cutoffs"]["0.001"]["comparedWithRandomForest"]["recallDelta"])
        self.assertEqual(0, exact_interval(0, 1)[0])
        self.assertIsNone(exact_interval(0, 0))


if __name__ == "__main__":
    unittest.main()
