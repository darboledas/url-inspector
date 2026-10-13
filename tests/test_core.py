from __future__ import annotations

import unittest

from loaders import load_module

ui = load_module("url_inspector_6.0.py", "url_inspector_core_tests")


class CoreTests(unittest.TestCase):
    def test_normalize_url_adds_https(self):
        self.assertEqual(ui.normalize_url("example.com"), "https://example.com")

    def test_normalize_url_rejects_non_http(self):
        with self.assertRaises(ValueError):
            ui.normalize_url("file:///etc/passwd")

    def test_canonical_url_drops_fragment_and_normalizes_host(self):
        value = ui.canonicalize_url_for_lookup("HTTPS://Example.COM/path?q=1#fragment")
        self.assertEqual(value, "https://example.com/path?q=1")

    def test_levenshtein_bounded(self):
        self.assertEqual(ui.levenshtein_bounded("paypal", "paypa1", 1), 1)
        self.assertGreater(ui.levenshtein_bounded("paypal", "example", 1), 1)

    def test_phishstats_does_not_change_calibrated_score(self):
        tls = ui.TLSResult(available=True, valid=True, host="example.com", port=443)
        score, level, factors = ui.calculate_risk(
            "https://example.com",
            "https://example.com",
            [],
            None,
            {},
            tls,
            identity=None,
            html=None,
            reputation={
                "phishstats": {
                    "available": True,
                    "listed": True,
                    "date": "2099-01-01T00:00:00Z",
                    "score": 10,
                }
            },
        )
        self.assertEqual(score, 0)
        self.assertEqual(level, 1)
        self.assertEqual(factors, [])

    def test_calibrated_level_boundary_29(self):
        tls = ui.TLSResult(available=False, valid=False, host="example.com", port=80)
        score, level, _ = ui.calculate_risk(
            "http://example.com",
            "http://example.com",
            [],
            None,
            {},
            tls,
        )
        self.assertEqual(score, 29)
        self.assertEqual(level, 3)


if __name__ == "__main__":
    unittest.main()
