@echo off
set PORT=%ESMIR_BACKEND_PORT%
if "%PORT%"=="" set PORT=8001
echo [*] Starting ESMIR SOC Platform Backend on http://127.0.0.1:%PORT% ...
cd /d "%~dp0..\backend"
call "..\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port %PORT% --reload
