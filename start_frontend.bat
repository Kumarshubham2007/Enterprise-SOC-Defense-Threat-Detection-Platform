@echo off
echo [*] Starting ESMIR SOC Platform Frontend on http://localhost:5173 ...
cd /d "%~dp0..\frontend"
call node "node_modules\vite\bin\vite.js"
