#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Menú único Windows/Linux para usar el motor 1.18.1 SIN modificarlo.

Opción 1: ejecuta una nueva inspección, conserva su JSON y genera informes.
Opción 2: genera PDFs desde un JSON previo, sin acceder a la red.
Argumentos CLI: se envían sin alteraciones al lanzador compatible existente.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
RESULT_DIR = ROOT / 'informes_locales'


def _ask(message: str) -> str | None:
    try:
        return input(message).strip()
    except (EOFError, KeyboardInterrupt):
        print('\nOperación cancelada.')
        return None


def _choice(title: str, options: dict[str, str]) -> str | None:
    while True:
        print('\n' + title)
        for key, label in options.items():
            print(f'  {key}. {label}')
        answer = _ask('Seleccione una opción: ')
        if answer is None:
            return None
        if answer in options:
            return answer
        print('Opción no válida. Inténtelo de nuevo.')


def _destination() -> Path | None:
    raw = _ask(f'Carpeta para resultados [por defecto: {RESULT_DIR}]: ')
    if raw is None:
        return None
    path = Path(raw).expanduser() if raw else RESULT_DIR
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path.resolve()
    except OSError as exc:
        print(f'No se puede crear la carpeta de resultados: {exc}')
        return None


def _stem(value: str) -> str:
    """Nombre neutral sin segmentos peligrosos ni datos completos de URL."""
    host = urlsplit(value).hostname or 'url'
    return re.sub(r'[^A-Za-z0-9._-]+', '_', host)[:60].strip('._-') or 'url'


def _unique_prefix(host: str, directory: Path) -> Path:
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    return directory / f'url_inspector_{_stem(host)}_{stamp}'


def _run(argv: list[str]) -> int:
    # Nunca usar shell=True. Los datos escritos por el usuario son argumentos.
    try:
        return subprocess.run([sys.executable, *argv], cwd=ROOT, check=False).returncode
    except OSError as exc:
        print(f'No se pudo lanzar el programa: {exc}')
        return 1


def _pdf_selection() -> str | None:
    return _choice('Informes a generar:', {
        '1': 'Informe pericial PDF + HTML (estructura UNE 197001:2019)',
        '2': 'Solo informe ejecutivo',
        '3': 'Pericial PDF + HTML completo y ejecutivo PDF',
        '4': 'Solo informe pericial HTML completo',
        '0': 'No generar informes (conservar solo JSON)',
    })


def _metadata(chosen: str) -> str | None:
    if chosen not in ('1', '3', '4'):
        return ''
    data = _ask('Archivo JSON opcional con datos del perito [Enter = sin datos]: ')
    if data is None:
        return None
    if data:
        path = Path(data).expanduser()
        if not path.is_file():
            print('No existe el archivo de datos periciales. No se generan PDFs.')
            return None
        try:
            obj = json.loads(path.read_text(encoding='utf-8-sig'))
            if not isinstance(obj, dict):
                raise ValueError('Debe ser un objeto JSON.')
        except (OSError, ValueError) as exc:
            print(f'Datos periciales incorrectos: {exc}')
            return None
        return str(path.resolve())
    return ''


def _create_reports(json_file: Path, destination: Path, *, name: str) -> None:
    chosen = _pdf_selection()
    if chosen is None or chosen == '0':
        print(f'Resultados JSON conservados en: {json_file}')
        return
    metadata = _metadata(chosen)
    if metadata is None:
        print(f'Se conserva el JSON original: {json_file}')
        return
    # El nombre identifica la exportación, no modifica el contenido JSON.
    base = _unique_prefix(name, destination)
    cmd = [str(ROOT / 'informes_une_197001.py'), str(json_file)]
    if chosen in ('1', '3'):
        cmd.extend(['--pericial', str(base) + '_pericial.pdf'])
    if chosen in ('1', '3', '4'):
        cmd.extend(['--pericial-html', str(base) + '_pericial.html'])
    if chosen in ('2', '3'):
        cmd.extend(['--ejecutivo', str(base) + '_ejecutivo.pdf'])
    if metadata:
        cmd.extend(['--datos-pericia', metadata])
    rc = _run(cmd)
    if rc:
        print(f'ERROR al generar informes (código {rc}). El JSON sigue disponible: {json_file}')
    else:
        print(f'Resultados utilizados: {json_file}')
        print('Los PDFs y/o HTML se han generado sin realizar otra inspección.')


def _new_analysis() -> None:
    url = _ask('URL completa (http:// o https://): ')
    if not url:
        return
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.netloc:
        print('Introduzca una URL absoluta con http:// o https://.')
        return
    full = _ask('¿Realizar análisis completo? [S/n]: ')
    if full is None:
        return
    confirm = _ask('Se contactará con el sitio y, en su caso, proveedores externos. ¿Continuar? [s/N]: ')
    if confirm is None or confirm.lower() not in ('s', 'si', 'sí'):
        print('Inspección cancelada; no se ha contactado con la URL.')
        return
    folder = _destination()
    if folder is None:
        return
    path = Path(str(_unique_prefix(url, folder)) + '.json')
    cmd = [str(ROOT / 'url_inspector_informes_une.py'), url, '--no-menu', '--json', str(path)]
    if full.lower() not in ('n', 'no'):
        cmd.append('--full')
    rc = _run(cmd)
    if rc or not path.is_file():
        print(f'Inspección incompleta o fallida (código {rc}); no se generarán PDF automáticos.')
        if path.exists():
            print(f'Compruebe el estado del JSON antes de reutilizarlo: {path}')
        return
    print(f'Análisis finalizado. JSON conservado en: {path}')
    _create_reports(path, folder, name=url)


def _previous_analysis() -> None:
    value = _ask('Ruta del archivo JSON de un análisis anterior: ')
    if not value:
        return
    json_file = Path(value).expanduser()
    if not json_file.is_file():
        print('No se encuentra el JSON indicado.')
        return
    try:
        content = json.loads(json_file.read_text(encoding='utf-8-sig'))
        if not isinstance(content, dict) or not isinstance(content.get('input_url'), str) or not isinstance(content.get('phishing_assessment'), dict):
            raise ValueError('No tiene los campos principales esperados de URL Inspector.')
    except (OSError, ValueError) as exc:
        print(f'JSON no válido: {exc}')
        return
    folder = _destination()
    if folder is None:
        return
    print('Modo sin inspección: se reutilizan los resultados técnicos registrados.')
    _create_reports(json_file.resolve(), folder, name=content['input_url'])


def main(args: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if args is None else args)
    if argv:
        if argv[0] in ('-h', '--help'):
            print('Menú para URL Inspector 6.0 — complemento de informes UNE 197001:2019')
            print('  Sin argumentos: abre el menú Windows/Linux.')
            print('  Con argumentos: invoca la CLI original ampliada del inspector.')
            print('  Ejemplo: python menu_url_inspector.py https://example.com --full')
            print('  Informe offline: python informes_une_197001.py resultados.json --pericial p.pdf --pericial-html p.html --ejecutivo e.pdf')
            return 0
        return _run([str(ROOT / 'url_inspector_informes_une.py'), *argv])

    while True:
        option = _choice('URL INSPECTOR 6.0 — INFORMES', {
            '1': 'Analizar una URL nueva',
            '2': 'Generar informes desde un JSON anterior',
            '0': 'Salir',
        })
        if option is None or option == '0':
            print('Programa finalizado.')
            return 0
        if option == '1':
            _new_analysis()
        elif option == '2':
            _previous_analysis()


if __name__ == '__main__':
    raise SystemExit(main())
