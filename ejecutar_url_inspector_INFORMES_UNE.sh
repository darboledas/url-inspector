#!/usr/bin/env bash
# Acceso Linux al mismo menú del complemento UNE. No altera el motor 1.18.1.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# La ayuda debe funcionar incluso antes de instalar las dependencias.
if [[ "${1:-}" == '--help' || "${1:-}" == '-h' ]]; then
  if [[ -x .venv/bin/python ]]; then
    exec .venv/bin/python menu_url_inspector.py --help
  elif command -v python3 >/dev/null 2>&1; then
    exec python3 menu_url_inspector.py --help
  else
    exec python menu_url_inspector.py --help
  fi
fi

if [[ -x .venv/bin/python ]]; then
  PY=.venv/bin/python
else
  if command -v python3 >/dev/null 2>&1; then
    BASE=python3
  elif command -v python >/dev/null 2>&1; then
    BASE=python
  else
    echo 'ERROR: Python 3.11 o superior no está instalado.' >&2
    exit 1
  fi
  echo 'Creando entorno virtual local .venv...'
  "$BASE" -m venv .venv || {
    echo 'ERROR: no se pudo crear .venv. Instale el paquete python3-venv de su distribución.' >&2
    exit 1
  }
  PY=.venv/bin/python
fi

if ! "$PY" -c 'import requests,tldextract,dns,bs4,cryptography,reportlab' >/dev/null 2>&1; then
  echo 'Instalando dependencias en .venv (requiere conexión la primera vez)...'
  "$PY" -m pip install -r requirements_v6.txt
fi
exec "$PY" menu_url_inspector.py "$@"
