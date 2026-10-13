from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from loaders import load_module

ui = load_module("url_inspector_6.0.py", "url_inspector_reputation_tests")


def iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")


class ReputationTests(unittest.TestCase):
    def test_recent_phishstats_is_current_alert(self):
        result = ui.phishstats_operational_assessment({
            "listed": True,
            "date": iso_days_ago(2),
            "score": 1.0,
        })
        self.assertTrue(result["negative"])
        self.assertFalse(result["advisory"])

    def test_old_low_score_phishstats_is_advisory(self):
        result = ui.phishstats_operational_assessment({
            "listed": True,
            "date": iso_days_ago(180),
            "score": 4.2,
        })
        self.assertFalse(result["negative"])
        self.assertTrue(result["advisory"])

    def test_old_high_score_phishstats_remains_alert(self):
        result = ui.phishstats_operational_assessment({
            "listed": True,
            "date": iso_days_ago(180),
            "score": 5.0,
        })
        self.assertTrue(result["negative"])

    def test_operational_verdict_separates_reputation_from_score(self):
        rep = {
            "phishstats": {
                "available": True,
                "listed": True,
                "date": iso_days_ago(2),
                "score": 1,
            }
        }
        verdict = ui.operational_verdict(rep, score=0, level=1)
        self.assertEqual(verdict["code"], "REPUTATION_ALERT")
        self.assertEqual(verdict["technical_score"], 0)
        self.assertEqual(verdict["technical_level"], 1)

    def test_merge_keeps_negative_reputation_from_input_url(self):
        final_rep = {
            "phishstats": {"available": True, "listed": False},
            "urlhaus": {"available": True, "listed": False},
        }
        input_rep = {
            "phishstats": {
                "available": True,
                "listed": True,
                "date": iso_days_ago(2),
                "score": 1,
            }
        }
        merged = ui.merge_operational_reputation(
            final_rep,
            input_rep,
            initial_url="https://example.test/original",
            final_url="https://example.test/session-token",
        )
        self.assertTrue(merged["phishstats"]["listed"])
        self.assertEqual(merged["phishstats"]["result_scope"], "input_url")
        self.assertEqual(
            ui.operational_verdict(merged, 0, 1)["code"],
            "REPUTATION_ALERT",
        )

    def test_reputation_coverage_is_independent(self):
        rep = {
            "urlhaus": {"available": True, "listed": False},
            "phishstats": {"available": True, "listed": False},
            "openphish": {"available": True, "listed": False},
        }
        coverage = ui.reputation_coverage_summary(rep)
        self.assertEqual(coverage["evaluated_count"], 3)
        self.assertEqual(coverage["total_sources"], 7)
        self.assertEqual(coverage["coverage_percent"], 43)


if __name__ == "__main__":
    unittest.main()
