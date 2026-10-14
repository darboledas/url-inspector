#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capa de presentación y captura de consola, independiente del motor calibrado.

No modifica url_inspector_6.0.py, sus comprobaciones, riesgos o tiempos de consulta.
Registra stdout/stderr del motor en un archivo de evidencia cuando existe una
salida JSON o se solicita una ruta de registro.
"""
from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
from pathlib import Path

import informes_une_197001 as reportes


class _Tee:
    def __init__(self, stream, buffer):
        self.stream = stream
        self.buffer = buffer

    def write(self, text):
        self.buffer.write(text)
        return self.stream.write(text)

    def flush(self):
        self.stream.flush()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _arg_path(args, *names):
    for i, item in enumerate(args):
        if item in names and i + 1 < len(args):
            return args[i + 1]
        for name in names:
            if item.startswith(name + '='):
                return item.split('=', 1)[1]
    return None


def _strip_extension_args(args):
    forwarded = [args[0]]
    metadata_path = console_path = pericial_html = None
    index = 1
    while index < len(args):
        argument = args[index]
        found = False
        for option in ('--datos-pericia', '--registro-consola', '--pericial-html'):
            if argument == option or argument.startswith(option+'='):
                if argument == option:
                    if index + 1 >= len(args):
                        raise SystemExit(f'Falta la ruta tras {option}')
                    value = args[index+1]
                    index += 1
                else:
                    value = argument.split('=', 1)[1]
                if option == '--datos-pericia':
                    metadata_path = value
                elif option == '--registro-consola':
                    console_path = value
                else:
                    pericial_html = value
                found = True
                break
        if not found:
            forwarded.append(argument)
        index += 1
    return forwarded, metadata_path, console_path, pericial_html


def main():
    forwarded, metadata_path, log_path_arg, pericial_html = _strip_extension_args(sys.argv)
    source = Path(__file__).with_name('url_inspector_6.0.py')
    spec = importlib.util.spec_from_file_location('url_inspector_motor_estable', source)
    if spec is None or spec.loader is None:
        raise RuntimeError('No se encuentra el motor original.')
    core = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = core
    spec.loader.exec_module(core)
    metadata = reportes.load_metadata(metadata_path)
    reportes.set_context(core=core, metadata=metadata)
    core.export_pdf_forensic_report = reportes.export_pdf_forensic_report
    core.export_pdf_executive_report = reportes.export_pdf_executive_report
    core.export_pdf_report = reportes.export_pdf_forensic_report

    cli = forwarded[1:]
    json_target = _arg_path(cli, '--json')
    pericial_target = _arg_path(cli, '--pdf-forensic', '--pdf')
    if pericial_html and not json_target:
        # Sólo se añade exportación estructurada; no hay nuevas consultas.
        json_target = str(Path(pericial_html).with_suffix('.json'))
        forwarded.extend(['--json', json_target])
    log_target = log_path_arg or (str(Path(json_target).with_suffix('.consola.txt')) if json_target else None)
    sys.argv = forwarded

    if '--help' in cli or '-h' in cli:
        return core.main()

    capture = io.StringIO()
    original_out, original_err = sys.stdout, sys.stderr
    try:
        sys.stdout = _Tee(original_out, capture)
        sys.stderr = _Tee(original_err, capture)
        result = core.main()
    finally:
        sys.stdout, sys.stderr = original_out, original_err
        if log_target:
            path = Path(log_target).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            # Los códigos ANSI se omiten en el TXT para lectura. No se añaden
            # mensajes inventados; se conserva literalmente el contenido textual.
            log = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', capture.getvalue())
            path.write_text(log, encoding='utf-8')
            print(f'Registro real de consola guardado en: {path}')
            reportes.set_console_log(path)

    # La primera exportación que realiza el motor puede comenzar antes de
    # escribir el mensaje final. Se completa la presentación desde el mismo
    # JSON una vez terminada la inspección (SIN contactar otra vez a la URL).
    if result in (None, 0) and (pericial_target or pericial_html):
        source_result = Path(json_target) if json_target else None
        if (not source_result or not source_result.is_file()) and pericial_target:
            pdf = Path(pericial_target)
            source_result = pdf.with_name(pdf.stem + '_datos.json')
        if source_result is not None and source_result.is_file():
            reportes.set_source_json(source_result)
            output = json.loads(source_result.read_text(encoding='utf-8-sig'))
            if pericial_target:
                reportes.export_pdf_forensic_report(output, pericial_target)
                print('Pericial PDF actualizado con la transcripción íntegra de consola.')
            if pericial_html:
                reportes.export_html_forensic_report(output, pericial_html)
                print(f'Pericial HTML completo: {Path(pericial_html).resolve()}')
        else:
            print('No se ha localizado el JSON de la inspección para elaborar el anexo completo.', file=sys.stderr)
            return 1
    return result


if __name__ == '__main__':
    raise SystemExit(main())
