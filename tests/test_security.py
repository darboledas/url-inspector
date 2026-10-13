from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from loaders import load_module

ui = load_module("url_inspector_6.0.py", "url_inspector_security_tests")


class SecurityTests(unittest.TestCase):
    def test_ip_policy(self):
        self.assertFalse(ui._ip_is_public_target("127.0.0.1"))
        self.assertFalse(ui._ip_is_public_target("10.0.0.1"))
        self.assertFalse(ui._ip_is_public_target("::1"))
        self.assertTrue(ui._ip_is_public_target("8.8.8.8"))
        self.assertTrue(ui._ip_is_public_target("1.1.1.1"))

    def test_blocks_localhost_and_credentials(self):
        with self.assertRaises(ui.TargetSafetyError):
            ui.validate_public_target("http://127.0.0.1")
        with self.assertRaises(ui.TargetSafetyError):
            ui.validate_public_target("http://localhost")
        with self.assertRaises(ui.TargetSafetyError):
            ui.validate_public_target("https://user:pass@example.com", resolve=False)

    def test_dns_resolution_all_public_is_allowed(self):
        fake = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 443)),
        ]
        with patch.object(ui.socket, "getaddrinfo", return_value=fake):
            self.assertEqual(ui.validate_public_target("https://public.test"), ["1.1.1.1", "8.8.8.8"])

    def test_dns_resolution_with_private_ip_is_blocked(self):
        fake = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ]
        with patch.object(ui.socket, "getaddrinfo", return_value=fake):
            with self.assertRaises(ui.TargetSafetyError):
                ui.validate_public_target("https://mixed.test")

    def test_dns_pinning_returns_only_validated_address(self):
        with ui._pin_target_resolution("example.test", 443, ["8.8.8.8"]):
            rows = socket.getaddrinfo("example.test", 443, type=socket.SOCK_STREAM)
            self.assertTrue(rows)
            self.assertEqual({row[4][0] for row in rows}, {"8.8.8.8"})

    def test_dns_pinning_delegates_other_hosts_and_restores_resolver(self):
        original = ui.socket.getaddrinfo
        marker = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("9.9.9.9", 80))]
        with patch.object(ui.socket, "getaddrinfo", return_value=marker) as mocked:
            patched_original = ui.socket.getaddrinfo
            with ui._pin_target_resolution("example.test", 443, ["8.8.8.8"]):
                rows = ui.socket.getaddrinfo("other.test", 80, type=socket.SOCK_STREAM)
                self.assertEqual(rows, marker)
                mocked.assert_called()
            self.assertIs(ui.socket.getaddrinfo, patched_original)
        self.assertIs(ui.socket.getaddrinfo, original)

    def test_target_session_ignores_environment_proxies(self):
        if ui.requests is None:
            self.skipTest("requests no disponible")
        session = ui._new_target_session()
        try:
            self.assertFalse(session.trust_env)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
