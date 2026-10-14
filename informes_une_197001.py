#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Presentación de resultados ya calculados. No evalúa URL ni modifica puntuaciones.

Estructura de informe pericial basada en UNE 197001:2019 (no certifica conformidad).
Uso directo: python informes_une_197001.py resultados.json --pericial pericial.pdf --ejecutivo ejecutivo.pdf
Uso integrado: via url_inspector_informes_une.py (sustitución exclusiva de exportadores PDF).
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, PageBreak,
    LongTable, TableStyle, KeepTogether, Image,
)
from reportlab.platypus.tableofcontents import TableOfContents

# Metadatos suministrados por el profesional. No están verificados por el motor.
DATOS_PERICIA: dict[str, Any] = {}
CORE: Any = None
MISSING = 'Pendiente de aportar o verificar'
CONSOLE_LOG: Path | None = None
SOURCE_JSON: Path | None = None
REPORT_GENERATOR_VERSION = '1.3.2'


# Indicador calculado por el motor 1.18.1: pesos 20, 15, 15, 15 y 15
# normalizados respecto a 80. No se recalcula aquí el resultado del motor.
TECHNICAL_COVERAGE_NOTE = (
    'La cobertura técnica del programa mide la disponibilidad ponderada de cinco '
    'componentes: resolución de URL (25 %), RDAP (18,75 %), TLS (18,75 %), '
    'HTTP (18,75 %) y HTML (18,75 %). No pondera el módulo de registros DNS detallados, '
    'geolocalización, reputación externa ni capturas de pantalla. Un valor '
    'del 100 % no demuestra que se hayan efectuado todas las pruebas posibles '
    'ni acredita la legitimidad, la exactitud o la seguridad del sitio.'
)


def _export_timestamp_utc() -> str:
    # Fecha de la representación documental; NO equivale a una fecha de firma o fe pública.
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _save_associated_json(output: dict[str, Any], target: Path) -> str:
    """Cuando el JSON fuente coincide con los datos recibidos, copia sus bytes SIN alterarlos.

    Si no existe fuente verificable, genera una serialización derivada y lo declara.
    Nunca reescribe el archivo original, aunque las rutas coincidan.
    """
    source = SOURCE_JSON
    if source is not None and source.is_file():
        try:
            source_data = json.loads(source.read_text(encoding='utf-8-sig'))
            if source_data == output:
                if source.resolve() != target.resolve():
                    shutil.copyfile(source, target)
                return 'Copia binaria fiel del JSON original; huellas idénticas.'
        except (OSError, UnicodeError, ValueError):
            pass
    target.write_bytes((json.dumps(output, ensure_ascii=False, indent=2, default=str) + '\n').encode('utf-8'))
    return ('Serialización derivada del objeto de resultados recibido; no se afirma '
            'identidad binaria con un original no verificado.')


def set_source_json(path: str | Path | None) -> None:
    global SOURCE_JSON
    SOURCE_JSON = Path(path).expanduser().resolve() if path else None


def _source_reference() -> str:
    if SOURCE_JSON is None or not SOURCE_JSON.is_file():
        return 'No se ha facilitado la ruta del archivo JSON original.'
    return f'{SOURCE_JSON.name} — SHA-256: {file_digest(SOURCE_JSON)}'


def set_console_log(path: str | Path | None) -> None:
    """Indica un registro real; nunca se reconstruye una salida de consola ficticia."""
    global CONSOLE_LOG
    CONSOLE_LOG = Path(path).expanduser().resolve() if path else None


def _console_evidence() -> tuple[str | None, str]:
    if CONSOLE_LOG is None or not CONSOLE_LOG.is_file():
        return None, ('No consta transcripción de consola en los materiales proporcionados. '
                      'El JSON contiene resultados estructurados, pero NO permite reconstruir '
                      'literalmente mensajes ni el orden completo de la salida original.')
    raw = CONSOLE_LOG.read_bytes()
    clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8-sig', errors='replace'))
    # La huella siempre corresponde a los bytes originales, sin alterar el registro.
    return clean, f'Archivo: {CONSOLE_LOG.name}; SHA-256: {hashlib.sha256(raw).hexdigest()}'


def _flatten_all(value: Any, prefix: str = ''):
    """Reproduce TODOS los valores del JSON, sin abreviar ni excluir campos."""
    if isinstance(value, dict):
        if not value:
            yield prefix or '(raíz)', '{}'
        for key, item in value.items():
            label = f'{prefix}.{key}' if prefix else str(key)
            yield from _flatten_all(item, label)
    elif isinstance(value, list):
        if not value:
            yield prefix, '[]'
        for i, item in enumerate(value):
            yield from _flatten_all(item, f'{prefix}[{i}]')
    else:
        yield prefix, json.dumps(value, ensure_ascii=False, default=str)


def _append_full_data(story: list, styles: Any, output: dict[str, Any]) -> None:
    """Anexo exhaustivo imprimible que reproduce cada valor del resultado."""
    for key, val in output.items():
        story.append(heading(f'Campo original: {key}', styles, 1, toc=False))
        for path, exact_value in _flatten_all(val, key):
            # Fragmentación SOLO para maquetación. No se descarta contenido.
            pieces = [exact_value[i:i+950] for i in range(0, len(exact_value), 950)] or ['']
            for index, piece in enumerate(pieces):
                prefix = f'{path} (continuación {index+1})' if index else path
                story.append(paragraph(f'<b>{html.escape(prefix)}</b>: {html.escape(piece)}', styles, 'PTable'))


def _append_console(story: list, styles: Any) -> None:
    log, provenance = _console_evidence()
    story.append(paragraph(html.escape(provenance), styles, 'PSmall'))
    if log is None:
        return
    for num, line in enumerate(log.splitlines(), 1):
        # Línea física de consola, con orden preservado y sin reescritura semántica.
        # Las líneas largas se dividen tipográficamente sin ocultar caracteres.
        if not line:
            story.append(Spacer(1, 3))
            continue
        chunks = [line[i:i+800] for i in range(0, len(line), 800)]
        for i, chunk in enumerate(chunks):
            marker = str(num) if i == 0 else f'{num} cont.'
            story.append(paragraph(f'<b>{marker:>4} |</b> {html.escape(chunk)}', styles, 'PTable'))


def set_context(*, core: Any = None, metadata: dict[str, Any] | None = None) -> None:
    global CORE, DATOS_PERICIA
    CORE = core
    DATOS_PERICIA = dict(metadata or {})


def _readable_value(value: Any, *, depth: int = 0, max_items: int = 7) -> str:
    """Representación legible de datos estructurados, sin volcar JSON bruto.

    Solo se abrevia la presentación. Todos los elementos originales se conservan
    completos en el archivo *_datos.json del anejo pericial.
    """
    if value is None or value == '':
        return 'No disponible'
    if isinstance(value, bool):
        return 'Sí' if value else 'No'
    if isinstance(value, dict):
        if not value:
            return 'Sin elementos registrados'
        if depth >= 3:
            return f'{len(value)} campos; información íntegra en el anejo JSON'
        entries = list(value.items())
        parts = [f'{name}: {_readable_value(item, depth=depth + 1, max_items=4)}'
                 for name, item in entries[:max_items]]
        if len(entries) > max_items:
            parts.append(f'{len(entries) - max_items} campos adicionales en el anejo JSON')
        return '; '.join(parts)
    if isinstance(value, (list, tuple)):
        if not value:
            return 'Sin elementos registrados'
        if depth >= 3:
            return f'{len(value)} elementos; información íntegra en el anejo JSON'
        parts = [f'{n}. {_readable_value(item, depth=depth + 1, max_items=4)}'
                 for n, item in enumerate(value[:max_items], 1)]
        if len(value) > max_items:
            parts.append(f'{len(value) - max_items} elementos adicionales en el anejo JSON')
        return '; '.join(parts)
    return str(value)


def safe(value: Any, *, max_chars: int = 420) -> str:
    string = _readable_value(value)
    if len(string) > max_chars:
        string = string[:max_chars].rstrip() + '… [presentación abreviada; detalle completo en el anejo JSON]'
    # La maquetación no puede insertar espacios en huellas, URL o identificadores.
    # ReportLab permite el ajuste visual mediante wordWrap='CJK' sin alterar la cadena.
    return html.escape(string)


def supplied(key: str) -> str:
    value = DATOS_PERICIA.get(key)
    return str(value) if value not in (None, '') else MISSING


def canonical_bytes(out: dict[str, Any]) -> bytes:
    return json.dumps(out, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def font_names() -> tuple[str, str]:
    choices = [
        ('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
        (r'C:\Windows\Fonts\arial.ttf', r'C:\Windows\Fonts\arialbd.ttf'),
        ('/Library/Fonts/Arial.ttf', '/Library/Fonts/Arial Bold.ttf'),
    ]
    for regular_path, bold_path in choices:
        if Path(regular_path).is_file() and Path(bold_path).is_file():
            try:
                pdfmetrics.registerFont(TTFont('UNEBody', regular_path))
                pdfmetrics.registerFont(TTFont('UNEBodyBold', bold_path))
                pdfmetrics.registerFontFamily('UNEBody', normal='UNEBody', bold='UNEBodyBold')
                return 'UNEBody', 'UNEBodyBold'
            except Exception:
                continue
    return 'Helvetica', 'Helvetica-Bold'


def get_styles():
    regular, bold = font_names()
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name='PTitulo', fontName=bold, fontSize=16.5, leading=22,
                          textColor=colors.HexColor('#15324c'), alignment=TA_CENTER, spaceAfter=10))
    ss.add(ParagraphStyle(name='PSub', fontName=regular, fontSize=10.3, leading=14,
                          alignment=TA_CENTER, spaceAfter=15))
    ss.add(ParagraphStyle(name='PH1', fontName=bold, fontSize=11.2, leading=15,
                          textColor=colors.HexColor('#163b5d'), spaceBefore=12, spaceAfter=7, keepWithNext=True))
    ss.add(ParagraphStyle(name='PH2', fontName=bold, fontSize=9.5, leading=13,
                          textColor=colors.HexColor('#193d5a'), spaceBefore=9, spaceAfter=5, keepWithNext=True))
    ss.add(ParagraphStyle(name='PBody', fontName=regular, fontSize=9.2, leading=14,
                          spaceAfter=7, allowWidows=0, allowOrphans=0))
    ss.add(ParagraphStyle(name='PTable', fontName=regular, fontSize=7.45, leading=10.6, wordWrap='CJK'))
    ss.add(ParagraphStyle(name='PTableHead', fontName=bold, fontSize=7.45, leading=10.6))
    ss.add(ParagraphStyle(name='PHash', fontName=regular, fontSize=6.0, leading=8.2, wordWrap='CJK'))
    ss.add(ParagraphStyle(name='PSmall', fontName=regular, fontSize=7.7, leading=11, spaceAfter=6))
    ss.add(ParagraphStyle(name='PNotice', fontName=bold, fontSize=9.1, leading=13,
                          backColor=colors.HexColor('#eaf1f8'), borderPadding=9,
                          borderColor=colors.HexColor('#779bb8'), borderWidth=0.6, spaceAfter=11))
    return ss


class TotalPagesCanvas(canvas.Canvas):
    """Draw the total number of pages after all pages have been processed."""
    def __init__(self, *args, reference: str = '', **kwargs):
        super().__init__(*args, **kwargs)
        self.page_states: list[dict[str, Any]] = []
        self.reference = reference

    def showPage(self):
        self.page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        count = len(self.page_states)
        regular, _ = font_names()
        for state in self.page_states:
            self.__dict__.update(state)
            self.saveState()
            self.setFont(regular, 7.2)
            self.setStrokeColor(colors.HexColor('#b6c3d1'))
            self.line(1.65*cm, 1.36*cm, A4[0]-1.65*cm, 1.36*cm)
            self.setFillColor(colors.HexColor('#495c6f'))
            self.drawString(1.65*cm, 1.11*cm, safe_ref(self.reference))
            self.drawRightString(A4[0]-1.65*cm, 1.11*cm, f'Página {self._pageNumber} de {count}')
            self.restoreState()
            super().showPage()
        super().save()


def safe_ref(value: str) -> str:
    return value if len(value) <= 68 else value[:65] + '...'


class IndexedDocument(BaseDocTemplate):
    def __init__(self, filename: str, **kwargs):
        super().__init__(filename, pagesize=A4, leftMargin=1.65*cm, rightMargin=1.65*cm,
                         topMargin=1.55*cm, bottomMargin=1.75*cm, **kwargs)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id='body',
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates(PageTemplate(id='all', frames=[frame]))

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and getattr(flowable, 'toc_level', None) is not None:
            level = flowable.toc_level
            self.notify('TOCEntry', (level, flowable.getPlainText(), self.page))


def paragraph(content: str, styles: Any, style: str = 'PBody'):
    return Paragraph(content, styles[style])


def heading(content: str, styles: Any, level: int = 0, *, toc: bool = True):
    item = paragraph(html.escape(content), styles, 'PH1' if level == 0 else 'PH2')
    # Las subsecciones y campos de anejos se leen íntegros en el cuerpo,
    # pero no saturan el índice general de capítulos y anejos UNE.
    if toc:
        item.toc_level = level
    return item


def table(rows: list[tuple[str, Any]], styles: Any, *, width=None, compact: bool = False):
    if width is None:
        width = (4.55*cm, 12.63*cm)
    data = [[paragraph('CAMPO', styles, 'PTableHead'), paragraph('INFORMACIÓN', styles, 'PTableHead')]]
    for k, v in rows:
        # Evitar cortar artificialmente huellas y hashes en el bloque principal.
        hash_value = isinstance(v, str) and bool(re.fullmatch(r'[0-9a-fA-F:]{64,128}', v))
        data.append([paragraph(html.escape(str(k)), styles, 'PTable'),
                     paragraph(safe(v), styles, 'PHash' if hash_value else 'PTable')])
    out = LongTable(data, colWidths=width, repeatRows=1, hAlign='LEFT')
    pad = 3.0 if compact else 5
    out.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e3ebf3')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#c4cbd3')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), pad),
        ('BOTTOMPADDING', (0, 0), (-1, -1), pad),
    ]))
    return out


def section_table(story: list, styles: Any, title: str, rows: list[tuple[str, Any]]):
    story.append(heading(title, styles, 1, toc=False))
    story.append(table(rows or [('Información', 'No disponible')], styles))


def rep_state(entry: Any):
    if not isinstance(entry, dict):
        return 'No evaluado / sin información'
    # Hay servicios (p. ej. PhishStats) con available=True y configured=False.
    # La disponibilidad efectiva de la consulta prevalece al describir el resultado;
    # ambos indicadores sin normalizar se mantienen en el JSON original.
    if entry.get('available') is True:
        if entry.get('listed') is True:
            return 'Coincidencia registrada (interpretación según fuente y contexto)'
        if entry.get('listed') is False:
            return 'Sin coincidencia según consulta disponible'
        return 'Consulta disponible; resultado no determinado'
    error = str(entry.get('error') or '').strip()
    if error and not error.lower().startswith('no configurado'):
        return 'No evaluado: error o respuesta no disponible del proveedor'
    if entry.get('configured') is False:
        return 'No configurado / no consultado'
    return 'No evaluado / fuente no disponible'


def _conclusion(output: dict[str, Any]) -> tuple[str, str]:
    # Reutiliza exactamente la función del motor sin recalcular puntuaciones.
    if CORE is not None:
        return CORE._executive_conclusion(output)
    summary = output.get('executive_summary') or {}
    assessment = output.get('phishing_assessment') or {}
    score = assessment.get('score_0_to_100')
    level = assessment.get('level_1_to_5')
    return (f'Valoración automática registrada: nivel {level}/5 y puntuación {score}/100. '
            f'Veredicto operativo: {summary.get("operational_verdict") or "no disponible"}. '
            'La puntuación heurística no certifica legitimidad ni demuestra por sí sola actividad maliciosa.',
            'Contrastar los resultados con el contexto, las fuentes y la inspección humana.')


def _create_pdf(story, target, *, reference, title):
    target = Path(target).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    doc = IndexedDocument(str(target), title=title, author='URL Inspector — presentación automatizada',
                          subject='Documento basado en resultados de URL Inspector')
    doc.multiBuild(story, canvasmaker=lambda *a, **kw: TotalPagesCanvas(*a, reference=reference, **kw))
    return target


def export_pdf_forensic_report(output: dict[str, Any], path: str) -> None:
    """Exportación pericial estructural UNE 197001:2019, pendiente de revisión y firma."""
    if not isinstance(output, dict) or 'input_url' not in output or 'phishing_assessment' not in output:
        raise ValueError('La salida JSON no contiene los campos principales de URL Inspector.')
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    full_json = target.with_name(target.stem + '_datos.json')
    # Asociar copia exacta del JSON original si se puede comprobar su equivalencia.
    associated_origin = _save_associated_json(output, full_json)
    json_hash = file_digest(full_json)
    exported_utc = _export_timestamp_utc()
    digest = hashlib.sha256(canonical_bytes(output)).hexdigest()
    reference = f'URI6-{digest[:16].upper()} (referencia provisional)'
    styles = get_styles()
    summary = output.get('executive_summary') or {}
    assessed = output.get('phishing_assessment') or {}
    rdap = output.get('rdap') or {}
    tls = output.get('tls') or {}
    identity = output.get('identity_analysis') or {}
    rep = output.get('reputation') or {}
    conclusion, _action = _conclusion(output)
    story: list[Any] = [
        Spacer(1, 1.0*cm),
        paragraph('INFORME PERICIAL TÉCNICO', styles, 'PTitulo'),
        paragraph('Análisis de URL y de indicadores técnicos — estructura basada en UNE 197001:2019', styles, 'PSub'),
        paragraph('BORRADOR AUTOMATIZADO. Pendiente de revisión, individualización, dictamen y firma del perito. '
                  'No acredita por sí mismo cadena de custodia ni conformidad certificada con la norma.', styles, 'PNotice'),
        table([
            ('Código de referencia provisional', reference),
            ('Órgano / destinatario', supplied('organo_destinatario')),
            ('Procedimiento / expediente', supplied('procedimiento')),
            ('Perito: nombre y apellidos', supplied('perito_nombre')),
            ('Titulación', supplied('perito_titulacion')),
            ('Colegio / asociación / entidad (si procede)', supplied('perito_entidad')),
            ('Número de colegiación / certificación (si procede)', supplied('perito_numero')),
            ('Documento identificativo del perito', supplied('perito_identificacion')),
            ('Domicilio profesional', supplied('perito_domicilio')),
            ('Contacto profesional', supplied('perito_contacto')),
            ('Solicitante', supplied('solicitante')),
            ('Identificación del solicitante', supplied('solicitante_identificacion')),
            ('Letrado / procurador (si procede)', supplied('representacion_procesal')),
            ('Fecha y hora de análisis (UTC)', output.get('generated_at_utc')),
            ('Generación técnica de este borrador (UTC)', exported_utc),
            ('Versión del generador documental', REPORT_GENERATOR_VERSION),
            ('Fecha de emisión y firma', supplied('fecha_emision')),
        ], styles),
        Spacer(1, 14),
        paragraph('El contenido automatizado procede de los datos de URL Inspector. '
                  'Los campos facilitados manualmente no han sido comprobados por el programa.', styles, 'PSmall'),
        PageBreak(),
        heading('Declaraciones previas (si proceden)', styles),
        paragraph('<b>Declaración de tachas e imparcialidad:</b> ' + safe(DATOS_PERICIA.get('tachas') or MISSING), styles),
        paragraph('<b>Juramento o promesa y requisito de veracidad:</b> ' + safe(DATOS_PERICIA.get('juramento') or MISSING), styles),
        paragraph('Las declaraciones anteriores no se presumen realizadas por el hecho de generar este PDF. '
                  'Deben incorporarse únicamente si corresponden y después de su comprobación por el perito.', styles, 'PSmall'),
        PageBreak(),
        heading('Índice general', styles, toc=False),
    ]
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name='UNE-TOC0', fontName=font_names()[0], fontSize=9, leading=15, leftIndent=0, firstLineIndent=0, spaceBefore=5),
        ParagraphStyle(name='UNE-TOC1', fontName=font_names()[0], fontSize=8, leading=12, leftIndent=16, firstLineIndent=0),
    ]
    story.append(toc)
    story.append(PageBreak())

    story.append(heading('1. OBJETO', styles))
    story.append(paragraph('Documentar los resultados técnicos automatizados obtenidos mediante URL Inspector '
                           'sobre la dirección electrónica identificada, para su examen e interpretación posterior por el perito.', styles))
    story.append(heading('2. ALCANCE', styles))
    story.append(paragraph('El alcance disponible se limita al análisis de la URL aportada y a las comprobaciones '
                           'efectivamente registradas en el resultado estructurado. No se presupone una investigación '
                           'de dispositivos, transacciones, autoría, titularidad o intención.', styles))
    story.append(table([('URL examinada', output.get('input_url')),
                        ('URL final observada', output.get('final_url')),
                        ('Cuestiones formuladas por el solicitante', supplied('preguntas_encargo')),
                        ('Modo completo', output.get('full_mode'))], styles))
    story.append(heading('3. ANTECEDENTES', styles))
    story.append(paragraph('Información proporcionada sobre hechos anteriores al análisis: ' +
                           safe(DATOS_PERICIA.get('antecedentes') or MISSING), styles))
    story.append(heading('4. CONSIDERACIONES PRELIMINARES', styles))
    story.append(paragraph('La herramienta registra indicadores en un instante determinado. Las respuestas de '
                           'servidores, resolución de nombres, certificados y servicios externos pueden cambiar. '
                           'El registro incluye una hora de generación UTC, pero no una marca temporal independiente '
                           'para cada consulta ni una acreditación de la hora por tercero.', styles))
    story.append(table([('Versión declarada', output.get('program_version')),
                        ('Fecha y hora de resultados (UTC)', output.get('generated_at_utc')),
                        ('URL inicial', output.get('input_url')),
                        ('URL final', output.get('final_url')),
                        ('Resolución completada', (output.get('url_resolution') or {}).get('complete')),
                        ('Error de resolución', (output.get('url_resolution') or {}).get('error')),
                        ('Cobertura técnica (indicador del programa)', summary.get('analysis_coverage_score', summary.get('confidence_score'))),
                        ('Cobertura reputacional: fuentes evaluadas', f'{summary.get("reputation_coverage_evaluated", "?")}/{summary.get("reputation_coverage_total", "?")}')], styles))
    story.append(paragraph(TECHNICAL_COVERAGE_NOTE, styles, 'PSmall'))
    story.append(heading('5. DOCUMENTOS DE REFERENCIA', styles))
    story.append(paragraph('UNE 197001:2019, «Criterios generales para la elaboración de informes periciales» '
                           '(referencia para la estructura de presentación; no constituye certificación de conformidad). '
                           'Resultados estructurados de URL Inspector, versión indicada, reproducidos en el anejo 1. '
                           'La aplicación de otra bibliografía o normativa debe documentarse por el profesional.', styles))
    story.append(heading('6. TERMINOLOGÍA Y ABREVIATURAS', styles))
    story.append(table([
        ('URL', 'Localizador uniforme de recursos; dirección electrónica objeto del análisis.'),
        ('DNS', 'Sistema de nombres de dominio; relaciona nombres y registros de red.'),
        ('RDAP', 'Protocolo de acceso a datos de registro de dominios y otros recursos.'),
        ('TLS', 'Protocolo de protección criptográfica de comunicaciones.'),
        ('HTTP / HTML', 'Protocolo de transferencia de hipertexto / lenguaje de marcado de páginas web.'),
        ('IP / ASN', 'Dirección de protocolo de Internet / número de sistema autónomo.'),
        ('SHA-256', 'Función criptográfica de resumen usada aquí para verificar integridad de bytes.'),
        ('Heurístico', 'Estimación basada en reglas e indicadores; no equivale a demostración concluyente.'),
    ], styles))
    story.append(heading('7. DESARROLLO DEL ESTUDIO', styles))
    story.append(heading('7.1. Elementos objeto de estudio', styles, 1, toc=False))
    story.append(table([('URL aportada', output.get('input_url')),
                        ('Dominio registrable', output.get('registered_domain')),
                        ('Host final', output.get('final_host')),
                        ('IP observadas', ', '.join(output.get('ips') or []) or None),
                        ('Procedencia / aportación de la URL', supplied('procedencia_url')),
                        ('Fecha de recepción de la URL', supplied('fecha_recepcion')),
                        ('Conservación / custodia del elemento', supplied('custodia'))], styles))
    story.append(heading('7.2. Procedimientos y métodos empleados', styles, 1, toc=False))
    story.append(paragraph('Se consignan los procedimientos instrumentales indicados por la salida: resolución de URL, '
                           'redirecciones, identidad de dominio, datos RDAP, TLS y, si el modo y la disponibilidad lo permiten, '
                           'DNS avanzado, HTTP, HTML, infraestructura y servicios externos de reputación. '
                           'El modelo de valoración es heurístico; no se modifica la puntuación original. '
                           'No consta en estos datos el protocolo independiente de adquisición forense, '
                           'cadena de custodia física o certificación de las consultas.', styles))
    story.append(heading('7.3. Resultados obtenidos y análisis', styles, 1, toc=False))
    section_table(story, styles, '7.3.1. Redirecciones e identidad', [
        ('Redirecciones registradas', len(output.get('redirect_chain') or [])),
        ('Cadena de redirecciones', output.get('redirect_chain') or 'No registrada'),
        ('Dominio de referencia más próximo', identity.get('closest_reference_domain')),
        ('Posible typosquatting (indicador)', identity.get('typo_suspected')),
        ('Escrituras mixtas (indicador)', identity.get('mixed_scripts')),
        ('Homoglifos', identity.get('confusable_characters')),
        ('Host Unicode', identity.get('unicode_host')),
    ])
    response = rdap.get('response') or {}
    section_table(story, styles, '7.3.2. RDAP y DNS', [
        ('RDAP disponible', rdap.get('available')),
        ('RDAP fuente', rdap.get('source')),
        ('RDAP error', rdap.get('error')),
        ('Edad calculada del dominio (días)', rdap.get('domain_age_days')),
        ('Eventos RDAP registrados', response.get('events') if isinstance(response, dict) else None),
        *([(f'DNS: {record}', addresses) for record, addresses in
           output['dns'].items()] if isinstance(output.get('dns'), dict)
          else [('Registros DNS', 'No evaluado')]),
    ])
    section_table(story, styles, '7.3.3. TLS', [
        ('Comprobación disponible', tls.get('available')),
        ('Válido (resultado del motor)', tls.get('valid')),
        ('Tipo de validación', tls.get('validation_type')),
        ('Emisor', tls.get('issuer_common_name') or tls.get('issuer')),
        ('Válido desde', tls.get('not_before')),
        ('Válido hasta', tls.get('not_after')),
        ('Huella del certificado', tls.get('sha256_fingerprint')),
        ('Protocolo TLS negociado', tls.get('tls_version')),
        ('Cifrado TLS negociado', tls.get('cipher')),
        ('Nombre del servidor verificado', tls.get('hostname_verified')),
        ('Autoridad de confianza', tls.get('trusted_ca')),
        ('Algoritmo de firma', tls.get('signature_algorithm')),
        ('Tipo de clave pública', tls.get('public_key_type')),
        ('Longitud de clave pública (bits)', tls.get('public_key_bits')),
        ('Nombres alternativos (SAN)', tls.get('sans')),
        ('Políticas del certificado', tls.get('policy_oids')),
        ('Días restantes', tls.get('days_remaining')),
        ('Error', tls.get('error')),
    ])
    story.append(paragraph('TLS describe propiedades de la conexión y del certificado observados; incluso una validación '
                           'correcta no demuestra que el contenido de una página sea legítimo.', styles, 'PSmall'))
    for index, key, title in ((4, 'http', 'HTTP'), (5, 'html', 'HTML'), (6, 'cdn', 'CDN / infraestructura')):
        obj = output.get(key)
        section_table(story, styles, f'7.3.{index}. {title}',
                      list(obj.items()) if isinstance(obj, dict) else [('Resultado', 'No evaluado o no disponible')])
    status_keys = ('urlhaus', 'phishstats', 'openphish', 'phishtank', 'google_safe_browsing',
                   'virustotal', 'virustotal_domain', 'virustotal_ips', 'abuseipdb')
    rows = [(key, rep_state(rep.get(key))) for key in status_keys]
    section_table(story, styles, '7.3.7. Reputación externa', rows)
    story.append(paragraph('La ausencia de una coincidencia en una fuente disponible no demuestra legitimidad. '
                           'Las fuentes no configuradas o inaccesibles no deben interpretarse como resultados limpios. '
                           'Los datos detallados por fuente constan en el anejo de resultados.', styles, 'PSmall'))
    factors = assessed.get('factors') or []
    section_table(story, styles, '7.3.8. Puntuación heurística y factores', [
        ('Puntuación (0-100)', assessed.get('score_0_to_100')),
        ('Nivel (1-5)', assessed.get('level_1_to_5')),
        ('Factores individuales registrados', factors if factors else 'Ninguno registrado'),
        ('Veredicto operativo del programa', summary.get('operational_verdict')),
        ('Alerta reputacional independiente', summary.get('reputation_alert')),
        ('Aviso / antecedente reputacional', summary.get('reputation_advisory')),
    ])
    geo = output.get('geolocation')
    geo_rows = []
    if isinstance(geo, dict):
        for ip, details in geo.items():
            if isinstance(details, dict):
                geo_rows.extend((f'{ip}: {key}', value) for key, value in details.items())
            else:
                geo_rows.append((f'IP {ip}', details))
    section_table(story, styles, '7.3.9. Geolocalización e infraestructura IP',
                  geo_rows or [('Información de geolocalización', 'No consta en los resultados')])
    story.append(paragraph('La geolocalización de una dirección IP identifica, como máximo, '
                           'una localización estimada de infraestructura y no la ubicación física '
                           'demostrada del autor ni de quien administra la página.', styles, 'PSmall'))
    coverage_components = summary.get('analysis_coverage_components')
    section_table(story, styles, '7.3.10. Cobertura y comprobaciones registradas',
                  [(str(key), val) for key, val in coverage_components.items()]
                  if isinstance(coverage_components, dict) else
                  [('Estado de cobertura', 'No consta el desglose por comprobación')])
    story.append(paragraph(TECHNICAL_COVERAGE_NOTE, styles, 'PSmall'))
    story.append(paragraph('Una comprobación marcada como no disponible, fallida o no solicitada '
                           'no constituye un resultado negativo a favor de la legitimidad. '
                           'Las respuestas completas de proveedores y sus errores se conservan '
                           'en el anejo de datos estructurados.', styles, 'PSmall'))
    story.append(heading('7.4. Estado y custodia de los elementos', styles, 1, toc=False))
    shot = output.get('screenshot') or {}
    story.append(table([
        ('Captura indicada como disponible', shot.get('available')),
        ('Archivo de captura declarado', shot.get('path')),
        ('Método/motor de captura declarado', shot.get('engine')),
        ('Custodia externa y actuaciones del perito', supplied('custodia')),
        ('Observación', 'El programa no acredita por sí mismo cadena de custodia ni preservación en origen.'),
    ], styles))
    story.append(heading('8. CONCLUSIONES', styles))
    story.append(paragraph('<b>Resultado automatizado:</b> ' + html.escape(conclusion), styles))
    story.append(paragraph('<b>Dictamen técnico del perito sobre las cuestiones del encargo:</b> ' +
                           safe(DATOS_PERICIA.get('dictamen_perito') or MISSING), styles))
    story.append(paragraph('La clasificación heurística y las coincidencias reputacionales no identifican por sí solas '
                           'al autor de un sitio ni demuestran la comisión de un ilícito. El profesional debe revisar '
                           'la representatividad, contradicciones, limitaciones y contexto antes de emitir su opinión.', styles))
    story.append(heading('Fecha, integridad y firma', styles))
    story.append(table([('Fecha de emisión y firma', supplied('fecha_emision')),
                        ('Firma del perito', supplied('firma_perito')),
                        ('Referencia de informe definitivo', supplied('referencia_definitiva')),
                        ('Integridad del informe firmado', supplied('integridad_informe'))], styles))
    story.append(PageBreak())
    story.append(heading('ANEJO 1. Datos técnicos y huellas', styles))
    story.append(paragraph('El archivo JSON asociado forma parte del conjunto documental de esta exportación. '
                           'La huella SHA-256 indicada se calcula sobre los bytes del fichero escrito. '
                           'Debe conservarse sin alteraciones junto al informe. Estado de la copia: '
                           + html.escape(associated_origin), styles))
    story.append(table([
        ('Archivo JSON asociado', full_json.name),
        ('Modalidad de conservación del JSON asociado', associated_origin),
        ('SHA-256 del archivo JSON asociado', json_hash),
        ('Archivo de análisis original y huella SHA-256', _source_reference()),
        ('SHA-256 de la serialización canónica de resultados', digest),
        ('Versión del motor', output.get('program_version')),
        ('Fecha y hora de análisis registrada (UTC)', output.get('generated_at_utc')),
        ('Generación técnica del borrador (UTC)', exported_utc),
        ('Versión del generador de informes', REPORT_GENERATOR_VERSION),
    ], styles))
    shot_path = shot.get('path')
    if shot.get('available') is True and shot_path:
        shot_file = Path(shot_path)
        if shot_file.is_file():
            story.append(table([('Captura disponible localmente', str(shot_file)),
                                ('SHA-256 calculado de captura', file_digest(shot_file))], styles))
            try:
                img = Image(str(shot_file))
                ratio = min(16.7*cm/img.imageWidth, 15*cm/img.imageHeight, 1)
                img.drawWidth = img.imageWidth * ratio
                img.drawHeight = img.imageHeight * ratio
                story.append(Spacer(1, 8))
                story.append(img)
            except Exception:
                story.append(paragraph('La captura existe pero no se pudo representar en el PDF.', styles, 'PSmall'))
        else:
            story.append(paragraph('Captura mencionada en los resultados, pero el archivo no está disponible '
                                   'para verificarlo ni incorporarlo.', styles, 'PSmall'))
    story.append(PageBreak())
    story.append(heading('ANEJO 2. Registro original de consola', styles))
    story.append(paragraph('Transcripción de stdout y stderr capturada durante la inspección, si existe un archivo de registro. '
                           'Las secuencias de color se omiten únicamente en la presentación; la huella identifica el archivo íntegro. '
                           'La transcripción no equivale a un registro de tráfico de red.', styles))
    _append_console(story, styles)
    if _console_evidence()[0] is not None:
        story.append(PageBreak())
    else:
        story.append(Spacer(1, 18))
    story.append(heading('ANEJO 3. Reproducción exhaustiva de resultados', styles))
    story.append(paragraph('Se reproducen TODOS los campos y valores del resultado estructurado original, '
                           'incluidos errores, ausencias, listas, metadatos de proveedores y parámetros de cobertura. '
                           'No se han aplicado límites de caracteres ni de número de elementos. '
                           'El JSON asociado sigue siendo la fuente de comparación exacta.', styles))
    _append_full_data(story, styles, output)
    story.append(Spacer(1, 18))
    story.append(heading('ANEJO 4. Limitaciones documentales', styles))
    story.append(paragraph('No se adjuntan automáticamente los registros originales de los proveedores, '
                           'los sellos de tiempo de terceros, las actas de adquisición ni la documentación de '
                           'cadena de custodia. Si existen, deben incorporarse y relacionarse por el profesional. '
                           'La fecha y firma del informe final deben completarse tras su revisión.', styles))
    _create_pdf(story, target, reference=reference, title='Informe pericial técnico — estructura UNE 197001:2019')


def _executive_label(output: dict[str, Any]) -> str:
    assessment = output.get('phishing_assessment') or {}
    summary = output.get('executive_summary') or {}
    try:
        level = int(assessment.get('level_1_to_5') or 0)
    except (TypeError, ValueError):
        level = 0
    if summary.get('reputation_alert'):
        return 'ALERTA: COINCIDENCIA NEGATIVA EN FUENTES EXTERNAS'
    if summary.get('reputation_advisory'):
        return 'PRECAUCIÓN: ANTECEDENTE REPUTACIONAL QUE REQUIERE CONTRASTE'
    if level == 5:
        return 'RIESGO TÉCNICO CRÍTICO: SOSPECHA MUY ELEVADA'
    if level == 4:
        return 'RIESGO TÉCNICO MUY ALTO: PÁGINA SOSPECHOSA'
    if level == 3:
        return 'RIESGO TÉCNICO ALTO: INDICIOS RELEVANTES'
    if level == 2:
        return 'RIESGO TÉCNICO MODERADO: PRECAUCIÓN'
    if level == 1:
        return 'RIESGO TÉCNICO BAJO: SIN INDICIOS SUFICIENTES'
    return 'RESULTADO INDETERMINADO: REVISAR EL ANÁLISIS'


def export_pdf_executive_report(output: dict[str, Any], path: str) -> None:
    if not isinstance(output, dict) or 'input_url' not in output or 'phishing_assessment' not in output:
        raise ValueError('La salida JSON no contiene los campos principales de URL Inspector.')
    styles = get_styles()
    # Estilos exclusivos del resumen, sin alterar la maquetación del informe UNE.
    compact_styles = {
        'PTitulo': (15.3, 20, 0, 6),
        'PSub': (9.5, 12.5, 0, 9),
        'PH1': (10.0, 13, 7, 3),
        'PBody': (8.8, 12, 0, 5),
        'PNotice': (8.8, 12, 0, 6),
        'PTable': (7.65, 10.1, 0, 0),
        'PTableHead': (7.65, 10.1, 0, 0),
    }
    for name, (font_size, leading, before, after) in compact_styles.items():
        style = styles[name]
        style.fontSize = font_size
        style.leading = leading
        style.spaceBefore = before
        style.spaceAfter = after
    styles['PNotice'].borderPadding = 7
    assessed = output.get('phishing_assessment') or {}
    summary = output.get('executive_summary') or {}
    rep = output.get('reputation') or {}
    conclusion, action = _conclusion(output)
    reference = f'RESUMEN {hashlib.sha256(canonical_bytes(output)).hexdigest()[:12].upper()}'
    story: list[Any] = [
        paragraph('INFORME EJECUTIVO', styles, 'PTitulo'),
        paragraph('Evaluación automática de una dirección web', styles, 'PSub'),
        table([
            ('Dirección examinada', output.get('input_url')),
            ('Dirección final observada', output.get('final_url')),
            ('Fecha y hora del análisis (UTC)', output.get('generated_at_utc')),
            ('Dominio principal', output.get('registered_domain')),
        ], styles, compact=True),
        heading('Resultado principal', styles),
        Spacer(1, 8),
        paragraph(html.escape(_executive_label(output)), styles, 'PNotice'),
        paragraph(html.escape(conclusion), styles),
        heading('Qué conviene hacer', styles),
        paragraph(html.escape(action), styles),
        heading('Indicadores esenciales', styles),
        table([
            ('Nivel de riesgo (1-5)', assessed.get('level_1_to_5')),
            ('Puntuación de indicadores (0-100)', assessed.get('score_0_to_100')),
            ('Alerta de listas externas', 'Sí' if summary.get('reputation_alert') else 'No registrada'),
            ('Antecedente reputacional', 'Sí' if summary.get('reputation_advisory') else 'No registrado'),
            ('Cobertura técnica (5 componentes)', summary.get('analysis_coverage_score', summary.get('confidence_score'))),
            ('Fuentes reputacionales consultadas', f'{summary.get("reputation_coverage_evaluated", "?")} de {summary.get("reputation_coverage_total", "?")}'),
        ], styles, compact=True),
        heading('Señales observadas', styles),
    ]
    factors = assessed.get('factors') or []
    if factors:
        for f in sorted(factors, key=lambda obj: int(obj.get('points') or 0), reverse=True)[:6]:
            story.append(paragraph(html.escape(str(f.get('description') or 'Sin descripción')), styles))
    else:
        story.append(paragraph('No se registraron factores individuales de riesgo en el resultado suministrado.', styles))
    story.extend([
        heading('Fuentes externas', styles),
        table([(label, rep_state(rep.get(key))) for key, label in (
            ('urlhaus', 'URLhaus'), ('phishstats', 'PhishStats'),
            ('openphish', 'OpenPhish'), ('phishtank', 'PhishTank'),
            ('google_safe_browsing', 'Google Safe Browsing'),
            ('virustotal', 'VirusTotal'), ('abuseipdb', 'AbuseIPDB'))],
            styles, compact=True),
        heading('Límites de la valoración', styles),
        paragraph('La cobertura técnica pondera cinco componentes: resolución de URL, RDAP, TLS, HTTP y HTML; '
                  'excluye los registros DNS detallados, la geolocalización, la reputación y las capturas. '
                  'Un 100 % no prueba exhaustividad ni '
                  'legitimidad. El riesgo es heurístico, no probabilidad de fraude: un valor bajo no garantiza '
                  'seguridad y uno alto no demuestra delito. Las fuentes sin respuesta no se consideran '
                  'resultados negativos. Este resumen no constituye un dictamen pericial firmado.', styles),
    ])
    _create_pdf(story, path, reference=reference, title='URL Inspector — informe ejecutivo')


def export_html_forensic_report(output: dict[str, Any], path: str) -> None:
    """Informe HTML autocontenido, imprimible, con totalidad de datos y consola."""
    if not isinstance(output, dict) or 'input_url' not in output or 'phishing_assessment' not in output:
        raise ValueError('El JSON no contiene los campos principales del inspector.')
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    associated = target.with_name(target.stem + '_datos.json')
    associated_origin = _save_associated_json(output, associated)
    digest = file_digest(associated)
    exported_utc = _export_timestamp_utc()
    log, log_provenance = _console_evidence()
    reference = f'URI6-{hashlib.sha256(canonical_bytes(output)).hexdigest()[:16].upper()} (provisional)'
    esc = lambda value: html.escape(str(value if value is not None else 'No consta'))
    def block(title, text):
        return f'<section><h2>{esc(title)}</h2><p>{esc(text)}</p></section>'
    def listing(data):
        sections=[]
        for key, value in data.items():
            full = json.dumps(value, ensure_ascii=False, indent=2, default=str)
            sections.append(f'<section class="data"><h3>{esc(key)}</h3><pre>{esc(full)}</pre></section>')
        return '\n'.join(sections)
    ident = ''.join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k,v in [
        ('Referencia provisional', reference), ('URL inicial', output.get('input_url')),
        ('URL final', output.get('final_url')), ('Fecha de resultados UTC', output.get('generated_at_utc')),
        ('Generación técnica del borrador (UTC)', exported_utc),
        ('Versión del generador documental', REPORT_GENERATOR_VERSION),
        ('Destinatario', supplied('organo_destinatario')), ('Procedimiento', supplied('procedimiento')),
        ('Perito', supplied('perito_nombre')), ('Titulación', supplied('perito_titulacion')),
        ('Solicitante', supplied('solicitante')), ('Fecha emisión/firma', supplied('fecha_emision'))])
    summary, assessed = output.get('executive_summary') or {}, output.get('phishing_assessment') or {}
    conclusion, _ = _conclusion(output)
    score = f'{assessed.get("score_0_to_100", "?")}/100; nivel {assessed.get("level_1_to_5", "?")}/5'
    sections = [
        block('Declaraciones previas (si proceden)',
              'Tachas: '+supplied('tachas')+'. Juramento o promesa: '+supplied('juramento')+'. Pendientes de verificación por el perito.'),
        block('1. OBJETO', 'Documentar integralmente los resultados técnicos registrados por URL Inspector para revisión del perito.'),
        block('2. ALCANCE', 'Análisis automatizado de la URL aportada. No acredita autoría, intención, delitos ni cadena de custodia independiente. Cuestiones del encargo: '+supplied('preguntas_encargo')),
        block('3. ANTECEDENTES', supplied('antecedentes')),
        block('4. CONSIDERACIONES PRELIMINARES', 'Observaciones puntuales que pueden cambiar con el tiempo. No hay sellos de tiempo independientes acreditados. Resultados de consulta y fallos se registran tal como constan en el JSON. ' + TECHNICAL_COVERAGE_NOTE),
        block('5. DOCUMENTOS DE REFERENCIA', 'UNE 197001:2019: referencia estructural, sin certificación de conformidad. Resultados originales de URL Inspector, que se reproducen a continuación sin omisiones.'),
        block('6. TERMINOLOGÍA Y ABREVIATURAS', 'URL (dirección web), DNS (nombres de dominio), TLS (seguridad del canal), RDAP (información de registro), IP (dirección de Internet), ASN (sistema autónomo), SHA-256 (huella de integridad).'),
        block('7. DESARROLLO DEL ESTUDIO', 'Elementos, procedimientos y datos observados: URL, redirecciones, identidad, IP y geolocalización, DNS, RDAP, TLS, HTTP, HTML, CDN, proveedores reputacionales y valoración heurística. Cada campo del resultado aparece íntegro en el anejo de datos.'),
        block('8. CONCLUSIONES', f'{conclusion} Puntuación: {score}. Dictamen del perito: {supplied("dictamen_perito")}. La clasificación automática no acredita por sí sola legitimidad ni fraude.'),
    ]
    # HTML normaliza los finales de línea. Esta copia de lectura usa LF, mientras
    # el .consola.txt conserva CRLF originales y su huella verificable.
    display_log = log.replace('\r\n', '\n').replace('\r', '\n') if log is not None else None
    console_html = f'<pre class="console">{esc(display_log)}</pre>' if log is not None else '<p>NO DISPONIBLE: no se guardó la salida literal de consola durante la inspección original.</p>'
    content = f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Informe pericial - {esc(output.get('input_url'))}</title>
    <style>
      :root{{--ink:#20354a;--navy:#193e5e;--line:#d7e1e9;--muted:#526577}}
      *{{box-sizing:border-box}} body{{margin:0 auto;max-width:1000px;padding:36px 44px;font-family:Arial,Helvetica,sans-serif;color:var(--ink);line-height:1.48}}
      h1{{font-size:25px;text-align:center;color:var(--navy)}}h2{{font-size:17px;color:var(--navy);border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:26px}}
      h3{{font-size:14px;color:var(--navy);margin:15px 0 7px}}p{{margin:10px 0}}small{{color:var(--muted)}}
      table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{padding:8px 10px;border:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{width:35%;background:#f1f5f9}}
      .notice{{background:#f0f4f7;border-left:4px solid #44718c;padding:14px;margin:22px 0}}
      .data{{break-inside:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f9fb;border:1px solid var(--line);padding:12px;font:11px/1.5 Consolas,'Courier New',monospace}}
      .console{{background:#f5f5f5}}.hash{{overflow-wrap:anywhere}}@media print{{body{{max-width:none;padding:0 10mm;font-size:10pt}}h2,h3{{break-after:avoid}}pre{{white-space:pre-wrap;break-inside:auto}}.data{{break-inside:auto}}}}
    </style></head><body><h1>INFORME PERICIAL TÉCNICO</h1>
    <p style="text-align:center">Estructura basada en UNE 197001:2019</p>
    <div class="notice"><b>BORRADOR AUTOMATIZADO:</b> pendiente de revisión, individualización, dictamen y firma del perito. No certifica cumplimiento de la UNE ni cadena de custodia.</div>
    <table>{ident}</table>
    {''.join(sections)}
    <section><h2>ANEJO 1. Integridad de resultados</h2><p>Archivo original: {esc(_source_reference())}. Archivo asociado: {esc(associated.name)}. SHA-256 del archivo asociado: <span class="hash">{digest}</span>. Modalidad: {esc(associated_origin)}. Generación técnica del borrador (UTC): {esc(exported_utc)}. Versión del generador: {REPORT_GENERATOR_VERSION}. Fuente: datos realmente registrados, sin nuevas conexiones.</p></section>
    <section><h2>ANEJO 2. Transcripción de consola</h2><p>{esc(log_provenance)}. Presentación HTML: saltos de línea normalizados a LF; para comparar bytes y conservar la literalidad original debe usarse el archivo .consola.txt indicado y su huella SHA-256. No se modificó el archivo de origen.</p>{console_html}</section>
    <section><h2>ANEJO 3. Todos los datos estructurados, sin recortes</h2>
    <p>Campos originales completos, incluidos resultados negativos, indisponibilidades y errores; la representación del JSON no sustituye los ficheros originales asociados.</p>
    {listing(output)}</section>
    <section><h2>ANEJO 4. Firma y custodia</h2><p>Firma del perito: {esc(supplied('firma_perito'))}. Fecha de emisión: {esc(supplied('fecha_emision'))}. Custodia acreditada: {esc(supplied('custodia'))}.</p>
    <p>Sin actas externas, registros de adquisición adicionales, sellos de tiempo de terceros ni certificación forense independiente salvo que se adjunten expresamente.</p></section>
    </body></html>"""
    # Escritura binaria: impide que Windows transforme LF o CRLF en CRCRLF.
    target.write_bytes(content.encode('utf-8'))


def load_metadata(path: str | None):
    if not path:
        return {}
    doc = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(doc, dict):
        raise ValueError('El archivo de datos periciales debe contener un objeto JSON.')
    return doc


def main():
    parser = argparse.ArgumentParser(description='Genera informes PDF desde resultados JSON, sin consultar la URL.')
    parser.add_argument('resultados', help='Archivo JSON previamente exportado por URL Inspector')
    parser.add_argument('--pericial', help='Destino del informe pericial UNE (PDF)')
    parser.add_argument('--ejecutivo', help='Destino del informe ejecutivo (PDF)')
    parser.add_argument('--datos-pericia', help='JSON con datos manuales del perito y del encargo')
    parser.add_argument('--pericial-html', help='Destino del informe pericial completo en HTML')
    parser.add_argument('--registro-consola', help='Registro original de consola guardado durante la inspección (.txt)')
    args = parser.parse_args()
    if not args.pericial and not args.ejecutivo and not args.pericial_html:
        parser.error('Debe indicar --pericial y/o --ejecutivo.')
    output = json.loads(Path(args.resultados).read_text(encoding='utf-8-sig'))
    # Se reutiliza también la redacción ejecutiva original en la conversión offline.
    import importlib.util
    source = Path(__file__).with_name('url_inspector_6.0.py')
    core = None
    if source.is_file():
        import sys
        spec = importlib.util.spec_from_file_location('url_inspector_une_offline', source)
        if spec and spec.loader:
            core = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = core
            spec.loader.exec_module(core)
    set_context(core=core, metadata=load_metadata(args.datos_pericia))
    set_source_json(args.resultados)
    automatic_log = Path(args.resultados).with_suffix('.consola.txt')
    set_console_log(args.registro_consola or (str(automatic_log) if automatic_log.is_file() else None))
    if args.pericial_html:
        export_html_forensic_report(output, args.pericial_html)
        print(f'Informe pericial HTML: {Path(args.pericial_html).resolve()}')
    if args.pericial:
        export_pdf_forensic_report(output, args.pericial)
        print(f'Informe pericial: {Path(args.pericial).resolve()}')
    if args.ejecutivo:
        export_pdf_executive_report(output, args.ejecutivo)
        print(f'Informe ejecutivo: {Path(args.ejecutivo).resolve()}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
