@echo off
setlocal
cd /d "%~dp0"

echo [1/3] Compilando...
python -m py_compile url_inspector_6.0.py benchmark_url_inspector.py batch_url_inspector.py
if errorlevel 1 exit /b 1

echo [2/3] Ejecutando suite offline...
python -m unittest discover -s tests -p "test_*.py" -v
if errorlevel 1 exit /b 1

echo [3/3] Smoke CLI...
python url_inspector_6.0.py --help >nul
if errorlevel 1 exit /b 1
python benchmark_url_inspector.py --help >nul
if errorlevel 1 exit /b 1
python batch_url_inspector.py --help >nul
if errorlevel 1 exit /b 1

echo.
echo TODO OK - pruebas superadas.
exit /b 0
