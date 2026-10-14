@echo off
setlocal
cd /d "%~dp0"

REM Mostrar ayuda sin crear el entorno ni instalar paquetes.
if /I "%~1"=="--help" goto :quick_help
if /I "%~1"=="-h" goto :quick_help

REM Entorno aislado del complemento, sin instalar paquetes globalmente.
set "PY_VENV=%~dp0.venv\Scripts\python.exe"
REM Definir PY_BASE ANTES del bloque entre parentesis:
REM cmd.exe expande %VARIABLE% al interpretar el bloque completo.
where py >nul 2>nul
if not errorlevel 1 (
  set "PY_BASE=py -3"
) else (
  set "PY_BASE=python"
)
if not exist "%PY_VENV%" (
  echo Creando entorno virtual local .venv...
  %PY_BASE% -m venv "%~dp0.venv"
  if errorlevel 1 goto :error
)

"%PY_VENV%" -c "import requests,tldextract,dns,bs4,cryptography,reportlab" >nul 2>nul
if errorlevel 1 (
  echo Instalando dependencias en .venv. La primera instalacion requiere conexion...
  "%PY_VENV%" -m pip install -r requirements_v6.txt
  if errorlevel 1 goto :error
)

"%PY_VENV%" menu_url_inspector.py %*
set "RESULT=%errorlevel%"
if "%~1"=="" pause
exit /b %RESULT%

:error
echo ERROR: compruebe que Python 3.11 o superior esta instalado y que venv/pip funcionan.
pause
exit /b 1

:quick_help
where py >nul 2>nul
if not errorlevel 1 (
  py -3 menu_url_inspector.py --help
) else (
  python menu_url_inspector.py --help
)
exit /b %errorlevel%
