"""Pruebas de la interfaz multiplataforma; no se inspeccionan sitios en Internet."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MENU = ROOT / 'menu_url_inspector.py'
BASIC = {
    'program_version': '1.18.1',
    'generated_at_utc': '2026-10-13T10:00:00+00:00',
    'full_mode': False,
    'input_url': 'https://example.com',
    'final_url': 'https://example.com',
    'registered_domain': 'example.com',
    'phishing_assessment': {'score_0_to_100': 0, 'level_1_to_5': 1, 'factors': []},
    'executive_summary': {'reputation_alert': False, 'reputation_advisory': False, 'reputation_coverage_evaluated': 0, 'reputation_coverage_total': 7},
}


class MenuWindowsLinuxTests(unittest.TestCase):
    def test_motor_sha256_unchanged(self):
        self.assertEqual(hashlib.sha256((ROOT / 'url_inspector_6.0.py').read_bytes()).hexdigest(),
                         '30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a')

    def test_menu_cli_help(self):
        proc = subprocess.run([sys.executable, str(MENU), '--help'], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Sin argumentos', proc.stdout)

    def test_direct_wrapper_passthrough_help(self):
        proc = subprocess.run([sys.executable, str(MENU), 'https://example.com', '--help'],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('--pdf-forensic', proc.stdout)

    def test_exit_without_inspection(self):
        proc = subprocess.run([sys.executable, str(MENU)], input='0\n',
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Programa finalizado', proc.stdout)

    def test_cancel_network_before_new_inspection(self):
        proc = subprocess.run([sys.executable, str(MENU)],
                              input='1\nhttps://example.com\ns\nn\n0\n',
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('no se ha contactado con la URL', proc.stdout)

    def test_offline_from_previous_json_does_not_change_it(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = folder / 'resultados previos.json'
            target = folder / 'informes de salida'
            source.write_text(json.dumps(BASIC, ensure_ascii=False), encoding='utf-8')
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            choices = f'2\n{source}\n{target}\n3\n\n0\n'
            proc = subprocess.run([sys.executable, str(MENU)], input=choices,
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + '\n' + proc.stderr)
            self.assertIn('sin realizar otra inspección.', proc.stdout)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
            pericial = list(target.glob('*_pericial.pdf'))
            ejecutivo = list(target.glob('*_ejecutivo.pdf'))
            self.assertEqual(len(pericial), 1)
            self.assertEqual(len(ejecutivo), 1)
            self.assertGreater(pericial[0].stat().st_size, 3000)
            self.assertGreater(ejecutivo[0].stat().st_size, 3000)
            self.assertTrue(pericial[0].read_bytes().startswith(b'%PDF-'))
            self.assertTrue(ejecutivo[0].read_bytes().startswith(b'%PDF-'))
            self.assertTrue((target / (pericial[0].stem + '_datos.json')).is_file())

    def test_new_analysis_saves_json_once_then_exports_without_reinspection(self):
        spec = importlib.util.spec_from_file_location('menu_test_runtime', MENU)
        menu = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(menu)
        with tempfile.TemporaryDirectory() as temporary:
            inputs = iter(['https://example.com', 's', 's', temporary, '3', ''])
            calls = []
            def simulated_run(argv):
                calls.append(argv)
                if Path(argv[0]).name == 'url_inspector_informes_une.py':
                    self.assertIn('--no-menu', argv)
                    self.assertIn('--json', argv)
                    Path(argv[argv.index('--json') + 1]).write_text(json.dumps(BASIC), encoding='utf-8')
                return 0
            with mock.patch.object(menu, '_ask', side_effect=lambda _: next(inputs)):
                with mock.patch.object(menu, '_run', side_effect=simulated_run):
                    menu._new_analysis()
            self.assertEqual(len(calls), 2)
            self.assertEqual(Path(calls[0][0]).name, 'url_inspector_informes_une.py')
            self.assertEqual(Path(calls[1][0]).name, 'informes_une_197001.py')
            self.assertTrue(list(Path(temporary).glob('*.json')))

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'), 'Bash no disponible')
    def test_linux_launcher_help_without_dependencies(self):
        proc = subprocess.run(['bash', str(ROOT / 'ejecutar_url_inspector_INFORMES_UNE.sh'), '--help'],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Sin argumentos', proc.stdout)

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'), 'Bash no disponible')
    def test_linux_shell_syntax(self):
        proc = subprocess.run(['bash', '-n', str(ROOT / 'ejecutar_url_inspector_INFORMES_UNE.sh')],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == '__main__':
    unittest.main()
