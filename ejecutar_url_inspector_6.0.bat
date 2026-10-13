@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py"
) else (
  set "PY=python"
)

%PY% -c "import requests,tldextract,dns,bs4,cryptography,reportlab" >nul 2>nul
if not %errorlevel%==0 (
  echo Instalando dependencias de URL Inspector 6.0...
  %PY% -m pip install -r requirements_v6.txt
  if not %errorlevel%==0 (
    echo.
    echo ERROR: no se pudieron instalar las dependencias.
    pause
    exit /b 1
  )
)

if "%~1"=="" (
  echo.
  echo Uso: ejecutar_url_inspector_6.0.bat URL [opciones]
  echo Ejemplo sencillo: ejecutar_url_inspector_6.0.bat https://example.com --full
  echo Al terminar aparecera un menu para elegir los informes.
  echo.
  pause
  exit /b 0
)

%PY% url_inspector_6.0.py %*
endlocal
