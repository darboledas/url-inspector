@echo off
setlocal
cd /d "%~dp0"

:menu
cls
echo ============================================================
echo      URL INSPECTOR 6.0 - PAQUETE 1.14 / BENCHMARK
echo ============================================================
echo.
echo 1. Construir corpus NUEVO independiente de 600 URLs (NO visita objetivos)
echo 2. Prueba corta de 10 URLs del corpus nuevo en VM (leave-one-out)
echo 3. Benchmark completo del corpus nuevo en VM (leave-one-out)
echo 4. Generar informe de validacion
echo 5. Benchmark heuristic-only del corpus nuevo en VM
echo 0. Salir
echo.
set /p op=Opcion: 
if "%op%"=="1" goto build
if "%op%"=="2" goto test10
if "%op%"=="3" goto full
if "%op%"=="4" goto report
if "%op%"=="5" goto heur
if "%op%"=="0" goto end
goto menu

:build
echo.
echo Construccion INDEPENDIENTE: excluye todas las URL y hosts del corpus de regresion.
echo Requiere URLHAUS_AUTH_KEY. PhishStats y OpenPhish no requieren clave para este build.
python benchmark_url_inspector.py build --output benchmark_corpus_validation.json --benign 300 --phishtank 0 --phishstats 100 --openphish 100 --urlhaus 100 --tranco-pool 10000 --seed 20261011 --exclude-corpus benchmark_corpus_regression.json --require-all-sources
pause
goto menu

:test10
call :confirm
if errorlevel 1 goto menu
python benchmark_url_inspector.py run --corpus benchmark_corpus_validation.json --inspector url_inspector_6.0.py --mode leave-one-out --limit 10 --timeout 75 --output benchmark_results_validation10.json --acknowledge-risk
pause
goto menu

:full
call :confirm
if errorlevel 1 goto menu
python benchmark_url_inspector.py run --corpus benchmark_corpus_validation.json --inspector url_inspector_6.0.py --mode leave-one-out --timeout 75 --output benchmark_results_validation600.json --resume --acknowledge-risk
pause
goto menu

:report
python benchmark_url_inspector.py report --results benchmark_results_validation600.json --output-dir benchmark_report_validation600
pause
goto menu

:heur
call :confirm
if errorlevel 1 goto menu
python benchmark_url_inspector.py run --corpus benchmark_corpus_validation.json --inspector url_inspector_6.0.py --mode heuristic-only --timeout 75 --output benchmark_results_validation600_heuristic.json --resume --acknowledge-risk
pause
goto menu

:confirm
echo.
echo ADVERTENCIA: esta opcion CONTACTA URLs de phishing/malware.
echo Debe ejecutarse exclusivamente dentro de una VM desechable/aislada.
set /p ok=Escriba SI para continuar: 
if /I not "%ok%"=="SI" exit /b 1
exit /b 0

:end
endlocal
