from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import batch_url_inspector as batch  # noqa: E402


class BatchTests(unittest.TestCase):
    def test_txt_input_ignores_blank_comments_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "urls.txt"
            p.write_text("# comentario\nhttps://a.test\n\nhttps://a.test\nhttps://b.test\n", encoding="utf-8")
            urls, duplicates = batch.deduplicate_urls(batch.read_input_urls(p))
            self.assertEqual(urls, ["https://a.test", "https://b.test"])
            self.assertEqual(duplicates, 1)

    def test_csv_autodetects_url_column(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "urls.csv"
            p.write_text("id,URL\n1,https://a.test\n2,https://b.test\n", encoding="utf-8")
            self.assertEqual(batch.read_input_urls(p), ["https://a.test", "https://b.test"])

    def test_csv_custom_column(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "urls.csv"
            p.write_text("id,destino\n1,https://a.test\n", encoding="utf-8")
            self.assertEqual(batch.read_input_urls(p, "destino"), ["https://a.test"])

    def test_batch_requires_acknowledgement(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "urls.txt"
            p.write_text("https://a.test\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ROOT / "batch_url_inspector.py"), str(p), "--output-dir", str(Path(td)/"out")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("--acknowledge-risk", proc.stdout)

    def test_dry_run_does_not_need_acknowledgement(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "urls.txt"
            p.write_text("https://a.test\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ROOT / "batch_url_inspector.py"), str(p), "--dry-run"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("DRY-RUN", proc.stdout)

    def test_end_to_end_with_fake_inspector_and_resume(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake = root / "fake_inspector.py"
            fake.write_text(
                "import json,sys\n"
                "from pathlib import Path\n"
                "u=sys.argv[1]; p=Path(sys.argv[sys.argv.index('--json')+1])\n"
                "d={'final_url':u,'registered_domain':'example.test','phishing_assessment':{'score_0_to_100':8,'level_1_to_5':2},'executive_summary':{'operational_verdict':'CAUTELA','reputation_alert':False,'analysis_coverage_score':100,'reputation_coverage_evaluated':3,'reputation_coverage_total':7,'reputation_coverage_percent':43}}\n"
                "p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(d),encoding='utf-8')\n",
                encoding="utf-8",
            )
            inp = root / "urls.txt"
            inp.write_text("https://a.test\nhttps://b.test\n", encoding="utf-8")
            out = root / "out"
            cmd = [sys.executable, str(ROOT / "batch_url_inspector.py"), str(inp), "--inspector", str(fake), "--output-dir", str(out), "--acknowledge-risk", "--delay", "0"]
            first = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stdout)
            data = json.loads((out / "batch_results.json").read_text(encoding="utf-8"))
            self.assertEqual(data["counts"]["total"], 2)
            self.assertTrue(all(x["score_0_to_100"] == 8 for x in data["results"]))
            self.assertTrue(all(x["technical_coverage"] == 100 for x in data["results"]))
            with (out / "batch_results.csv").open("r", encoding="utf-8-sig", newline="") as h:
                self.assertEqual(len(list(csv.DictReader(h))), 2)
            second = subprocess.run(cmd + ["--resume"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertIn("RESUME", second.stdout)

    def test_child_process_forces_utf8_stdio(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake = root / "fake_unicode_inspector.py"
            fake.write_text(
                "import json,os,sys\n"
                "from pathlib import Path\n"
                "if not os.environ.get('PYTHONIOENCODING','').lower().startswith('utf-8'):\n"
                "    raise SystemExit(91)\n"
                "if os.environ.get('PYTHONUTF8') != '1':\n"
                "    raise SystemExit(92)\n"
                "print('● salida Unicode')\n"
                "u=sys.argv[1]; p=Path(sys.argv[sys.argv.index('--json')+1])\n"
                "d={'final_url':u,'registered_domain':'example.test','phishing_assessment':{'score_0_to_100':0,'level_1_to_5':1},'executive_summary':{'operational_verdict':'SIN ALERTA','reputation_alert':False,'analysis_coverage_score':100,'reputation_coverage_evaluated':0,'reputation_coverage_total':7,'reputation_coverage_percent':0}}\n"
                "p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(d),encoding='utf-8')\n",
                encoding="utf-8",
            )
            inp = root / "urls.txt"
            inp.write_text("https://a.test\n", encoding="utf-8")
            out = root / "out"
            cmd = [sys.executable, str(ROOT / "batch_url_inspector.py"), str(inp), "--inspector", str(fake), "--output-dir", str(out), "--acknowledge-risk", "--delay", "0"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout)
            data = json.loads((out / "batch_results.json").read_text(encoding="utf-8"))
            self.assertEqual(data["results"][0]["status"], "ok")



if __name__ == "__main__":
    unittest.main()
