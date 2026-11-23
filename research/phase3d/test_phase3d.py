"""Regression tests for the research plan and laptop safety decisions."""

import unittest

import numpy as np

from benchmark import Rows, balance, disjoint, unique_training
from resource_guard import BUSY_SECONDS, MEMORY_STOP, affinity_subset, percent_busy, stop_reason


class PlanTests(unittest.TestCase):
    def test_sampling_is_nested_unique_and_excludes_mixed_domain_labels(self):
        records = Rows(np.arange(9).reshape(-1, 1), np.array([0, 1, 1, 0, 0, 1, 1, 0, 0]),
                       np.array(list("aabbcdefg")), np.array([""] * 9))
        eligible = unique_training(records)
        np.testing.assert_array_equal(eligible.groups, unique_training(records).groups)
        self.assertFalse({"a", "b"} & set(eligible.groups))
        self.assertEqual(len(eligible.groups), len(set(eligible.groups)))
        smaller = balance(eligible, 2)
        larger = balance(eligible, 4)
        self.assertTrue(set(smaller.groups).issubset(set(larger.groups)))
        self.assertEqual(int(np.sum(larger.y)), 2)
        with self.assertRaisesRegex(ValueError, "Insufficient"):
            balance(eligible, 6)

    def test_group_and_family_leakage_are_rejected(self):
        def row(domain, family):
            return Rows(None, None, np.array([domain]), np.array([family]))
        with self.assertRaisesRegex(ValueError, "Shared domain"):
            disjoint(row("a", ""), row("a", ""))
        with self.assertRaisesRegex(ValueError, "Shared lexical family"):
            disjoint(row("a", "family"), row("b", "family"))
        disjoint(row("a", ""), row("b", ""))

    def test_windows_affinity_and_stop_triggers(self):
        self.assertEqual(affinity_subset(0b101100), 0b001100)
        self.assertEqual(affinity_subset(0b010000), 0b010000)
        self.assertAlmostEqual(percent_busy((20, 50), (60, 150)), 60)
        self.assertIsNone(stop_reason(MEMORY_STOP - 1, BUSY_SECONDS - 1))
        self.assertEqual(stop_reason(MEMORY_STOP, 0), "memory-approaching-ceiling")
        self.assertEqual(stop_reason(0, BUSY_SECONDS), "sustained-host-cpu-above-50-percent")


if __name__ == "__main__":
    unittest.main()
