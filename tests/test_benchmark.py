from __future__ import annotations

import types
import unittest

from loaders import load_module

bench = load_module("benchmark_url_inspector.py", "benchmark_mask_tests")


class BenchmarkMaskTests(unittest.TestCase):
    def _dummy_module(self):
        def live(*args, **kwargs):
            return {"available": True, "listed": True}

        return types.SimpleNamespace(
            reputation_urlhaus=live,
            reputation_phishstats=live,
            reputation_openphish=live,
            reputation_phishtank=live,
            reputation_virustotal=live,
            reputation_virustotal_domain=live,
            reputation_virustotal_ips=live,
            reputation_google_safe_browsing=live,
            reputation_abuseipdb=live,
        )

    def test_leave_one_out_masks_phishstats(self):
        module = self._dummy_module()
        bench._apply_reputation_mask(module, "leave-one-out", "phishstats")
        result = module.reputation_phishstats("https://example.test")
        self.assertFalse(result["available"])
        self.assertTrue(result["benchmark_disabled"])
        self.assertTrue(module.reputation_urlhaus("x")["available"])

    def test_heuristic_only_masks_all_external_reputation(self):
        module = self._dummy_module()
        bench._apply_reputation_mask(module, "heuristic-only", "openphish")
        for name in (
            "reputation_urlhaus",
            "reputation_phishstats",
            "reputation_openphish",
            "reputation_phishtank",
            "reputation_virustotal",
            "reputation_google_safe_browsing",
        ):
            result = getattr(module, name)("https://example.test")
            self.assertFalse(result["available"], name)
            self.assertTrue(result["benchmark_disabled"], name)


if __name__ == "__main__":
    unittest.main()
