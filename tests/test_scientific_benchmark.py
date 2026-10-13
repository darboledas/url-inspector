from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from loaders import load_module

bench = load_module("benchmark_url_inspector.py", "benchmark_scientific_tests")


class ScientificBenchmarkTests(unittest.TestCase):
    def _rows(self):
        return [
            {"sample_id": "P1", "url": "https://p1.test/a", "label": 1, "category": "phishing", "source": "phishstats", "mode": "leave-one-out", "status": "ok", "score": 30, "source_timestamp": "2026-10-10T00:00:00Z"},
            {"sample_id": "P2", "url": "https://p2.test/a", "label": 1, "category": "phishing", "source": "openphish", "mode": "leave-one-out", "status": "ok", "score": 5, "source_timestamp": "2026-09-01T00:00:00Z"},
            {"sample_id": "M1", "url": "https://m1.test/a", "label": 1, "category": "malware", "source": "urlhaus", "mode": "leave-one-out", "status": "ok", "score": 50, "source_timestamp": "2026-10-12T00:00:00Z"},
            {"sample_id": "B1", "url": "https://b1.test/", "label": 0, "category": "benign_reference", "source": "tranco", "mode": "leave-one-out", "status": "ok", "score": 0, "source_timestamp": None},
            {"sample_id": "B2", "url": "https://b2.test/", "label": 0, "category": "benign_reference", "source": "tranco", "mode": "leave-one-out", "status": "ok", "score": 15, "source_timestamp": None},
        ]

    def test_wilson_interval_contains_observed_proportion(self):
        low, high = bench.wilson_interval(253, 300)
        self.assertIsNotNone(low)
        self.assertIsNotNone(high)
        p = 253 / 300
        self.assertLess(low, p)
        self.assertGreater(high, p)
        self.assertAlmostEqual(low, 0.7977, places=3)
        self.assertAlmostEqual(high, 0.8801, places=3)

    def test_metric_row_adds_confidence_intervals(self):
        m = bench.metric_row(self._rows(), 8)
        self.assertEqual((m["tp"], m["tn"], m["fp"], m["fn"]), (2, 1, 1, 1))
        self.assertAlmostEqual(m["recall_sensitivity"], 2 / 3)
        self.assertIsNotNone(m["recall_ci95_low"])
        self.assertIsNotNone(m["specificity_ci95_high"])

    def test_prevalence_adjustment(self):
        x = bench.prevalence_adjusted_values(0.84, 0.91, 0.01)
        expected_ppv = (0.84 * 0.01) / ((0.84 * 0.01) + (0.09 * 0.99))
        self.assertAlmostEqual(x["adjusted_ppv"], expected_ppv)
        self.assertGreater(x["adjusted_npv"], 0.99)
        self.assertAlmostEqual(x["expected_tp_per_10000"], 84.0)

    def test_overlap_audit_detects_cross_source_host(self):
        rows = self._rows() + [
            {"sample_id": "P3", "url": "https://p1.test/other", "label": 1, "category": "phishing", "source": "openphish", "mode": "leave-one-out", "status": "ok", "score": 10},
        ]
        audit = bench.corpus_overlap_audit(rows)
        self.assertEqual(audit["cross_source_host_overlap_count"], 1)
        self.assertEqual(audit["cross_source_url_overlap_count"], 0)

    def test_temporal_profile_bins_and_detection(self):
        ref = datetime(2026, 10, 13, tzinfo=timezone.utc)
        profile = bench.temporal_profile(self._rows(), ref, (8,))
        self.assertEqual(profile["n_malicious_evaluable"], 3)
        self.assertEqual(profile["n_with_source_timestamp"], 3)
        bins = {row["age_bin"]: row for row in profile["bins"]}
        self.assertEqual(bins["0-7d"]["n_evaluable"], 2)
        self.assertEqual(bins["0-7d"]["detected"], 2)
        self.assertEqual(bins["31-90d"]["detected"], 0)

    def test_report_generates_scientific_outputs(self):
        payload = {
            "benchmark_version": "1.16",
            "updated_at_utc": "2026-10-13T00:00:00Z",
            "inspector_sha256": "abc",
            "results": self._rows(),
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "results.json"
            src.write_text(json.dumps(payload), encoding="utf-8")
            out = root / "report"
            args = type("Args", (), {
                "results": str(src),
                "output_dir": str(out),
                "reference_time": "2026-10-13T00:00:00Z",
                "prevalence": "0.01,0.10",
            })()
            self.assertEqual(bench.cmd_report(args), 0)
            for name in (
                "benchmark_summary.json",
                "benchmark_summary.txt",
                "thresholds_leave-one-out.csv",
                "source_metrics_leave-one-out.csv",
                "category_metrics_leave-one-out.csv",
                "temporal_metrics_leave-one-out.csv",
                "prevalence_adjusted_leave-one-out.csv",
                "overlap_audit.json",
            ):
                self.assertTrue((out / name).exists(), name)

    def test_temporal_compare_audits_independence(self):
        baseline = self._rows()
        candidate = [dict(r, sample_id="N" + r["sample_id"], url=r["url"].replace(".test", ".new")) for r in self._rows()]
        audit = bench._dataset_overlap_between(baseline, candidate)
        self.assertTrue(audit["independent_by_url_and_host"])
        candidate[0]["url"] = baseline[0]["url"]
        audit2 = bench._dataset_overlap_between(baseline, candidate)
        self.assertFalse(audit2["independent_by_url_and_host"])
        self.assertEqual(audit2["url_overlap_count"], 1)

    def test_compare_generates_temporal_outputs(self):
        baseline_rows = self._rows()
        candidate_rows = [dict(r, sample_id="N" + r["sample_id"], url=r["url"].replace(".test", ".new")) for r in self._rows()]
        baseline_payload = {"benchmark_version": "1.16", "updated_at_utc": "2026-09-01T00:00:00Z", "inspector_sha256": "same", "results": baseline_rows}
        candidate_payload = {"benchmark_version": "1.17", "updated_at_utc": "2026-10-01T00:00:00Z", "inspector_sha256": "same", "results": candidate_rows}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            baseline.write_text(json.dumps(baseline_payload), encoding="utf-8")
            candidate.write_text(json.dumps(candidate_payload), encoding="utf-8")
            out = root / "compare"
            args = type("Args", (), {
                "baseline": str(baseline),
                "candidate": str(candidate),
                "output_dir": str(out),
                "thresholds": "8,20",
            })()
            self.assertEqual(bench.cmd_compare(args), 0)
            self.assertTrue((out / "temporal_comparison.json").exists())
            self.assertTrue((out / "temporal_comparison.txt").exists())
            self.assertTrue((out / "temporal_threshold_deltas.csv").exists())
            data = json.loads((out / "temporal_comparison.json").read_text(encoding="utf-8"))
            self.assertTrue(data["dataset_independence_audit"]["independent_by_url_and_host"])
            self.assertTrue(data["same_inspector_sha256"])


if __name__ == "__main__":
    unittest.main()
