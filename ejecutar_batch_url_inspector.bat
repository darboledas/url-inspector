@echo off
setlocal
cd /d "%~dp0"
python batch_url_inspector.py %*
endlocal
