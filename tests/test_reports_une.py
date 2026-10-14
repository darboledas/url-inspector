from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('informes_une_test', ROOT/'informes_une_197001.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

SAMPLE = {
    'program_version':'1.18.1', 'generated_at_utc':'2026-10-13T10:00:00+00:00',
    'full_mode':False, 'input_url':'https://example.com', 'final_url':'https://example.com',
    'registered_domain':'example.com', 'phishing_assessment':{'score_0_to_100':0, 'level_1_to_5':1,'factors':[]},
    'executive_summary':{'reputation_alert':False,'reputation_advisory':False,'reputation_coverage_evaluated':0, 'reputation_coverage_total':7},
}

class ReportUNEOfflineTests(unittest.TestCase):
    def test_original_motor_hash_stable(self):
        raw = (ROOT/'url_inspector_6.0.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '30c9df71e46a8444e02af91e9cc2b50c29b323a38e9b9333373fd63bf954bc6a')

    def test_create_both_pdfs_and_full_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            pericial = Path(tmp)/'pericial.pdf'
            ejecutivo = Path(tmp)/'ejecutivo.pdf'
            module.set_context(metadata={})
            module.export_pdf_forensic_report(SAMPLE, str(pericial))
            module.export_pdf_executive_report(SAMPLE, str(ejecutivo))
            for path in (pericial, ejecutivo):
                self.assertGreater(path.stat().st_size, 3000)
                self.assertTrue(path.read_bytes().startswith(b'%PDF-'))
            sidecar = Path(tmp)/'pericial_datos.json'
            self.assertEqual(json.loads(sidecar.read_text(encoding='utf-8')), SAMPLE)
            self.assertEqual(len(module.file_digest(sidecar)),64)

    def test_metadata_template_is_blank(self):
        template = json.loads((ROOT/'datos_pericia_plantilla.json').read_text(encoding='utf8'))
        self.assertTrue(all(v == '' for v in template.values()))

    def test_reputation_available_even_when_not_configured(self):
        # Refleja el caso observado en PhishStats: ambas banderas originales
        # se conservan, pero el informe no oculta una consulta real.
        entry = {'available': True, 'configured': False, 'listed': False}
        self.assertEqual(module.rep_state(entry), 'Sin coincidencia según consulta disponible')
        self.assertIn('error', module.rep_state({
            'available': False, 'configured': False,
            'error': '403 Client Error: Forbidden'}))
        self.assertEqual(module.rep_state({'available': False, 'configured': False}),
                         'No configurado / no consultado')

    def test_structured_values_are_readable_not_json_dumps(self):
        data = {'A': ['203.0.113.20'], 'checks': [{'status': 200, 'kind': 'final'}]}
        rendered = module._readable_value(data)
        self.assertIn('A:', rendered)
        self.assertIn('status:', rendered)
        self.assertNotIn('{', rendered)
        self.assertNotIn('[', rendered)
        self.assertEqual(module._readable_value([]), 'Sin elementos registrados')

    def test_executive_realistic_coverage_one_page(self):
        # Los entornos CI no requieren PyMuPDF: contar /Type /Page en el PDF.
        import re
        sample = dict(SAMPLE)
        sample['reputation'] = {
            'urlhaus': {'available': False, 'configured': False},
            'phishstats': {'available': True, 'configured': False, 'listed': False},
            'openphish': {'available': True, 'listed': False},
            'phishtank': {'available': False, 'configured': False, 'error': '403 Forbidden'},
            'google_safe_browsing': {'available': False, 'configured': False},
            'virustotal': {'available': False, 'configured': False},
            'abuseipdb': {'available': False, 'configured': False},
        }
        sample['executive_summary'] = dict(SAMPLE['executive_summary'],
            reputation_coverage_evaluated=2, reputation_coverage_total=7,
            operational_verdict='SIN INDICIOS TÉCNICOS SUFICIENTES PARA ELEVAR EL RIESGO',
            analysis_coverage_score=81)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'ejecutivo.pdf'
            module.set_context(metadata={})
            module.export_pdf_executive_report(sample, str(target))
            data = target.read_bytes()
            self.assertEqual(len(re.findall(rb'/Type\s*/Page\b', data)), 1)

    def test_offline_cli_preserves_input_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / 'original.json'
            original.write_text(json.dumps(SAMPLE, ensure_ascii=False), encoding='utf-8')
            before = hashlib.sha256(original.read_bytes()).hexdigest()
            forensic = Path(tmp) / 'pericial.pdf'
            executive = Path(tmp) / 'ejecutivo.pdf'
            proc = subprocess.run([sys.executable, str(ROOT/'informes_une_197001.py'),
                str(original), '--pericial', str(forensic), '--ejecutivo', str(executive)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(before, hashlib.sha256(original.read_bytes()).hexdigest())
            self.assertTrue(forensic.is_file() and executive.is_file())

    def test_offline_cli_help(self):
        proc = subprocess.run([sys.executable, str(ROOT/'informes_une_197001.py'), '--help'],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('--pericial', proc.stdout)

    def test_wrapped_engine_cli_help(self):
        proc = subprocess.run([sys.executable, str(ROOT/'url_inspector_informes_une.py'), '--help'],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('--pdf-forensic', proc.stdout)

if __name__=='__main__':
    unittest.main()

class ReportsCompleteV13(unittest.TestCase):
    def setUp(self):
        module.set_console_log(None)
        module.set_source_json(None)

    def tearDown(self):
        module.set_console_log(None)
        module.set_source_json(None)

    def test_flatten_preserves_every_leaf_and_empty_container(self):
        sample = {'geo': {'ip1': {'asn': 64500, 'empty': []}}, 'tls': {'valid': False,
                  'issuer': 'Test & Co'}, 'missing': None}
        flat = list(module._flatten_all(sample))
        self.assertEqual(dict(flat), {
            'geo.ip1.asn': '64500', 'geo.ip1.empty': '[]',
            'tls.valid': 'false', 'tls.issuer': '"Test & Co"', 'missing': 'null',
        })

    def test_html_contains_all_input_sections_escapes_content(self):
        source = dict(SAMPLE, geolocation={'ip': {'org': 'ACME <script>alert(1)</script>'}},
                      tls={'validation_type': 'DV', 'public_key_bits': 2048},
                      reputation={'phishstats': {'available': True, 'listed': False}})
        with tempfile.TemporaryDirectory() as directory:
            source_file = Path(directory) / 'source.json'
            source_file.write_text(json.dumps(source, ensure_ascii=False), encoding='utf-8')
            module.set_source_json(source_file)
            target = Path(directory) / 'pericial.html'
            module.export_html_forensic_report(source, str(target))
            doc = target.read_text(encoding='utf-8')
            for key in source:
                self.assertIn(f'<h3>{key}</h3>', doc)
            self.assertIn('2048', doc)
            self.assertIn('&lt;script&gt;', doc)
            self.assertNotIn('<script>alert(1)</script>', doc)
            self.assertIn(module.file_digest(source_file), doc)
            self.assertIn('no se guardó la salida literal de consola', doc)

    def test_pdf_includes_full_fields_not_only_json_sidecar(self):
        sample = dict(SAMPLE, geolocation={'ip': {'asn': 64501}},
                      tls={'public_key_bits': 3072},
                      html={'suspicious_findings': ['ejemplo único de inspección completa']})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'pericial.pdf'
            module.export_pdf_forensic_report(sample, str(target))
            from pypdf import PdfReader
            text = '\n'.join(p.extract_text() for p in PdfReader(str(target)).pages)
            self.assertIn('geolocation.ip.asn', text)
            self.assertIn('tls.public_key_bits', text)
            self.assertIn('3072', text)
            self.assertIn('ANEJO 2. Registro original de consola', text)
            self.assertIn('No consta transcripción de consola', text)

    def test_transcript_real_and_hash_in_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            console = Path(directory) / 'original.consola.txt'
            console.write_text('PRUEBA: DNS consultado\nFALLO RDAP <sin respuesta>\n', encoding='utf-8')
            module.set_console_log(console)
            target = Path(directory) / 'informe.html'
            module.export_html_forensic_report(SAMPLE, str(target))
            doc = target.read_text(encoding='utf-8')
            self.assertIn('PRUEBA: DNS consultado', doc)
            self.assertIn('FALLO RDAP &lt;sin respuesta&gt;', doc)
            self.assertIn(module.file_digest(console), doc)

    def test_executive_label_is_not_probabilistic(self):
        low = dict(SAMPLE)
        self.assertIn('RIESGO TÉCNICO BAJO', module._executive_label(low))
        high = dict(SAMPLE, phishing_assessment={'level_1_to_5': 5, 'score_0_to_100': 90})
        self.assertIn('SOSPECHA MUY ELEVADA', module._executive_label(high))
        alert = dict(SAMPLE, executive_summary={'reputation_alert': True})
        self.assertIn('ALERTA', module._executive_label(alert))
        self.assertNotIn('probabilidad', module._executive_label(high).lower())


class ReportsTraceabilityV131(unittest.TestCase):
    """Regresiones documentales descubiertas en el caso BOE del 14/10/2026."""
    def setUp(self):
        module.set_source_json(None)
        module.set_console_log(None)
        module.set_context(metadata={})

    def tearDown(self):
        module.set_source_json(None)
        module.set_console_log(None)

    def test_html_preserves_console_lines_without_crcrlf(self):
        from bs4 import BeautifulSoup
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            source = folder/'resultado.json'
            source.write_bytes(json.dumps(SAMPLE).encode('utf-8'))
            original = folder/'resultado.consola.txt'
            original.write_bytes(b'\r\nA\r\n\r\nB\r\nFINAL\r\n')
            before = original.read_bytes()
            module.set_source_json(source)
            module.set_console_log(original)
            target = folder/'pericial.html'
            module.export_html_forensic_report(SAMPLE, str(target))
            actual = target.read_bytes()
            self.assertNotIn(b'\r\r\n', actual)
            rendered = BeautifulSoup(actual.decode('utf-8'), 'html.parser').select_one('pre.console')
            self.assertEqual(rendered.text, '\nA\n\nB\nFINAL\n')
            self.assertEqual(original.read_bytes(), before)
            self.assertIn(module.file_digest(original), target.read_text('utf-8'))
            self.assertIn('normalizados a LF', target.read_text('utf-8'))

    def test_json_associated_is_exact_copy_of_existing_source(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            source = folder/'resultados.json'
            # Orden, espacios, finales CRLF y ausencia de LF final se preservan.
            source_bytes = json.dumps(SAMPLE, ensure_ascii=False, indent=4).replace('\n', '\r\n').encode('utf-8')
            source.write_bytes(source_bytes)
            module.set_source_json(source)
            target = folder/'pericial.html'
            module.export_html_forensic_report(SAMPLE, str(target))
            assoc = folder/'pericial_datos.json'
            self.assertEqual(assoc.read_bytes(), source_bytes)
            self.assertEqual(module.file_digest(assoc), module.file_digest(source))
            self.assertIn('Copia binaria fiel', target.read_text('utf-8'))
            self.assertEqual(source.read_bytes(), source_bytes)

    def test_fallback_associated_data_does_not_claim_binary_identity(self):
        with tempfile.TemporaryDirectory() as d:
            module.set_source_json(None)
            target = Path(d)/'informe.html'
            module.export_html_forensic_report(SAMPLE, str(target))
            self.assertIn('Serialización derivada', target.read_text('utf-8'))
            self.assertEqual(json.loads((Path(d)/'informe_datos.json').read_text('utf-8')), SAMPLE)

    def test_hash_rendering_never_inserts_spaces(self):
        value = '3A:78:33:8D:0C:D4:8D:19:2C:C0:71:EC:1B:E2:6E:88:34:B2:38:D9:9D:E9:AF:A4:A0:4E:27:F3:9D:FE:B3:FF'
        self.assertEqual(module.safe(value), value)

    def test_generation_timestamp_and_report_version_distinct_from_signature(self):
        import re
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/'pericial.pdf'
            module.export_pdf_forensic_report(SAMPLE, str(target))
            from pypdf import PdfReader
            text = '\n'.join(page.extract_text() for page in PdfReader(str(target)).pages)
            self.assertRegex(text, r'Generación técnica de este\s+borrador \(UTC\)')
            self.assertRegex(text, r'Versión del generador\s+documental')
            self.assertIn(module.REPORT_GENERATOR_VERSION, text)
            self.assertIn('Fecha de emisión y firma', text)
            self.assertRegex(text, r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ')
            h = Path(d)/'pericial.html'
            module.export_html_forensic_report(SAMPLE, str(h))
            html_doc = h.read_text('utf-8')
            self.assertIn('Generación técnica del borrador (UTC)', html_doc)
            self.assertIn('Versión del generador documental', html_doc)
            self.assertIn(module.REPORT_GENERATOR_VERSION, html_doc)


class ReportsCoverageAndIndexV132(unittest.TestCase):
    def setUp(self):
        module.set_source_json(None)
        module.set_console_log(None)
        module.set_context(metadata={})

    def tearDown(self):
        module.set_source_json(None)
        module.set_console_log(None)

    def test_note_explains_scope_and_exclusions(self):
        self.assertIn('cinco', module.TECHNICAL_COVERAGE_NOTE)
        for name in ('RDAP', 'TLS', 'HTTP', 'HTML', 'DNS', 'geolocalización', 'reputación', 'capturas'):
            self.assertIn(name, module.TECHNICAL_COVERAGE_NOTE)
        self.assertIn('100 %', module.TECHNICAL_COVERAGE_NOTE)

    def test_index_heading_can_be_visible_but_not_indexed(self):
        styles = module.get_styles()
        main = module.heading('8. CONCLUSIONES', styles)
        detailed = module.heading('Campo original: geo', styles, 1, toc=False)
        self.assertEqual(main.toc_level, 0)
        self.assertFalse(hasattr(detailed, 'toc_level'))

    def test_html_includes_coverage_caveat_and_full_result(self):
        sample = dict(SAMPLE, executive_summary=dict(SAMPLE['executive_summary'],
                           analysis_coverage_score=100, analysis_coverage_components={
                           'url_resolution':True,'rdap':True,'tls':True,'http':True,'html':True}))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'informe.html'
            module.export_html_forensic_report(sample, str(target))
            doc = target.read_text(encoding='utf-8')
            self.assertIn('no demuestra que se hayan efectuado todas las pruebas posibles', doc)
            self.assertIn('analysis_coverage_components', doc)
            self.assertIn('1.3.2', doc)

    def test_pdf_index_excludes_technical_fields_but_body_preserves_them(self):
        from pypdf import PdfReader
        sample = dict(SAMPLE, geolocation={'203.0.113.8': {'asn': 64520}},
                      executive_summary=dict(SAMPLE['executive_summary'],
                      analysis_coverage_score=100, analysis_coverage_components={
                      'url_resolution':True,'rdap':True,'tls':True,'http':True,'html':True}))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'pericial.pdf'
            module.export_pdf_forensic_report(sample, str(target))
            pages = [p.extract_text() or '' for p in PdfReader(str(target)).pages]
            index_pages = [p for p in pages if 'Índice general' in p]
            self.assertEqual(len(index_pages), 1)
            index = index_pages[0]
            self.assertIn('1. OBJETO', index)
            self.assertIn('8. CONCLUSIONES', index)
            self.assertIn('ANEJO 3.', index)
            self.assertNotIn('Campo original:', index)
            self.assertNotIn('7.3.10.', index)
            all_text = '\n'.join(pages)
            self.assertIn('geolocation.203.0.113.8.asn', all_text)
            self.assertIn('La cobertura técnica del programa mide', all_text)
            self.assertIn('1.3.2', all_text)

    def test_executive_remains_one_page_and_explains_coverage(self):
        from pypdf import PdfReader
        sample = dict(SAMPLE, executive_summary=dict(SAMPLE['executive_summary'],
            analysis_coverage_score=100, reputation_coverage_evaluated=2,
            reputation_coverage_total=7), reputation={
            'urlhaus':{'configured':False}, 'phishstats':{'available':True,'listed':False},
            'openphish':{'available':True,'listed':False}, 'phishtank':{'error':'403 Forbidden'},
            'google_safe_browsing':{'configured':False}, 'virustotal':{'configured':False},
            'abuseipdb':{'configured':False}})
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'ejecutivo.pdf'
            module.export_pdf_executive_report(sample, str(target))
            pages = PdfReader(str(target)).pages
            self.assertEqual(len(pages), 1)
            text = pages[0].extract_text()
            self.assertIn('cinco componentes', text)
            self.assertIn('no prueba exhaustividad', text)
