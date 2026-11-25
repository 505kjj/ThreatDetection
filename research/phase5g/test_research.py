import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import numpy as np

from aggregate import evaluate, prevalence_precision
from custodian import IDENTITIES, eligibility, eligible_rows, signed_receipt, template_overlap
from frozen import read
from research.phase5g.preflight import PROTOCOL, project_urls
from replay import FEATURES
from grouping import signatures

PIN = "a" * 64


def record(**changes):
    return {"url": "https://example.com/", "cohort": "general-phishing", "label": 1,
            "observedDay": "2026-10-10", "verifiedDay": "2026-10-11", "sourceRecordSha256": PIN,
            "verificationEvidenceSha256": PIN, "rightsEvidenceSha256": PIN,
            "evidenceClass": "verified-credential-phishing", "campaign": PIN} | changes


class Phase5GTests(unittest.TestCase):
    def setUp(self):
        self.policy = read(PROTOCOL)
        self.receipt = {"reviewedDay": "2026-11-24"}

    def test_phishvn_dating_does_not_clear_source_evidence_gate(self):
        self.assertIsNone(eligibility(record(), self.policy, self.receipt))
        self.assertEqual(eligibility(record(observedDay="2025-02-18"), self.policy, self.receipt),
                         "outside-observation-or-verification-window")
        self.assertEqual(eligibility(record(evidenceClass="publisher-abuse"), self.policy, self.receipt),
                         "unverified-phishing-or-campaign")
        self.assertEqual(eligibility(record(cohort="india-financial", verifiedTargetCountry="IN"),
                                     self.policy, self.receipt), "unverified-financial-target-or-country")

    def test_unverified_popular_benign_data_is_rejected(self):
        row = record(label=0, cohort="benign-auth-payment", evidenceClass="popularity-list")
        self.assertEqual(eligibility(row, self.policy, self.receipt), "unverified-benign-or-owner")

    def test_projection_uses_actual_scheme_and_ignores_query_and_fragment(self):
        first, second, missing = project_urls(["https://example.com/design?private=1#abc",
                                              "http://example.com/design", "example.com/design"])
        self.assertIsNone(missing)
        self.assertEqual(first["normalizedUrl"], "https://example.com/design")
        self.assertEqual(first["identity"]["alias"], second["identity"]["alias"])
        self.assertNotEqual(first["identity"]["exact"], second["identity"]["exact"])
        self.assertEqual([first["x"][0], second["x"][0]], [1, 0])

    def test_prior_alias_and_family_are_counted_without_row_ids(self):
        projected = {"identity": {"exact": "b" * 64, "alias": "c" * 64, "group": "d" * 64, "family": "e" * 64}}
        history = {key: set() for key in IDENTITIES}
        for key in ("alias", "family"):
            history[key].add(projected["identity"][key])
        with TemporaryDirectory() as folder:
            ledger = Path(folder) / "test.jsonl"
            ledger.write_text(json.dumps(record()) + "\n", encoding="utf-8")
            with patch("custodian.project_urls", return_value=[projected]):
                rows, counts = eligible_rows(ledger, history, self.receipt, self.policy)
        self.assertEqual(rows, [])
        self.assertEqual(counts, {"prior-overlap": 1, "prior-alias": 1, "prior-family": 1, "admitted": 0})

    def test_numeric_template_check_catches_adjacent_size_bin(self):
        before = {"dom": dict.fromkeys(FEATURES, 0) | {"elements": 7, "inputs_password": 1}}
        after = {"dom": before["dom"] | {"elements": 8, "title_length": 64}}
        self.assertTrue(template_overlap(after, {signatures(before)[1]}))
        after["dom"]["inputs_password"] = 0
        self.assertFalse(template_overlap(after, {signatures(before)[1]}))

    def test_small_negative_controls_have_an_upper_bound_and_no_recall(self):
        rows = [{"id": str(i), "label": 0, "identity": {"group": str(i)}} for i in range(8)]
        report = evaluate(rows, {"ngram": np.zeros(8)}, {"ngram": {"fixed": 0.5}}, [0.001])
        result = report["models"]["ngram"]["operatingPoints"]["fixed"]
        self.assertEqual(result["fp"], 0)
        self.assertIsNone(result["recall"])
        self.assertAlmostEqual(result["negativeDomainFpr95Upper"], 1 - 0.05 ** (1 / 8))
        self.assertIsNone(result["scenarioPrecisionFromUrlRates"]["0.001"])
        self.assertAlmostEqual(prevalence_precision(0.80, 0.001, 0.001), 0.4446914953, places=8)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH unavailable")
    def test_custodian_signature_detects_modified_receipt(self):
        with TemporaryDirectory() as folder:
            sandbox = Path(folder)
            key, receipt, signers = (sandbox / name for name in ("key", "receipt.json", "allowed"))
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           capture_output=True, check=True)
            signers.write_text("phase5g-custodian " + key.with_suffix(".pub").read_text(), encoding="utf-8")
            receipt.write_bytes(b'{"reviewedDay":"2026-11-24"}\n')
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", self.policy["scoringNamespace"],
                            str(receipt)], capture_output=True, check=True)
            signature = receipt.with_suffix(".json.sig")
            self.assertEqual(signed_receipt(receipt, signature, signers, self.policy), self.receipt)
            receipt.write_bytes(b'{"reviewedDay":"2026-11-25"}\n')
            with self.assertRaisesRegex(ValueError, "signature"):
                signed_receipt(receipt, signature, signers, self.policy)
