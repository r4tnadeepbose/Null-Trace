@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [NullTrace] Creating virtual environment ...
    python -m venv .venv || goto :fail
    echo [NullTrace] Installing dependencies ...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :fail
)

".venv\Scripts\python.exe" scan.py %*
if errorlevel 1 pause
exit /b 0

:fail
echo [NullTrace] Setup failed. Install Python 3.10+ from https://www.python.org/downloads/
pause
exit /b 1
