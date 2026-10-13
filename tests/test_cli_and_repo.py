from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliAndRepositoryTests(unittest.TestCase):
    def test_cli_help(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "url_inspector_6.0.py"), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("URL Inspector 6.0", proc.stdout)

    def test_benchmark_help(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "benchmark_url_inspector.py"), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("benchmark", proc.stdout.lower())

    def test_batch_help(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "batch_url_inspector.py"), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("batch", proc.stdout.lower())

    def test_gitignore_protects_local_secret_file(self):
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("APIKEY.txt", text)
        self.assertIn(".env", text)


if __name__ == "__main__":
    unittest.main()
