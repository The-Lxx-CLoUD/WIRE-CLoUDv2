@echo off
REM =============================================================
REM WIRE-CLOUD launcher for Windows
REM Must be run as Administrator (right-click -> Run as administrator)
REM Requires Npcap installed first: https://npcap.com
REM (check "Install Npcap in WinPcap API-compatible Mode" during setup)
REM =============================================================

cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo [ERROR] Please right-click this file and choose "Run as administrator".
    echo [خطا] لطفا روی فایل راست کلیک کرده و "Run as administrator" را انتخاب کنید.
    echo.
    pause
    exit /b 1
)

where python >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] Python was not found in PATH. Install it from https://python.org
    pause
    exit /b 1
)

if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [*] Installing dependencies...
python -m pip install --quiet --upgrade pip
pip install --quiet -r backend\requirements.txt

echo.
echo [*] Make sure Npcap is installed: https://npcap.com
echo [*] Starting WIRE-CLOUD...
echo.
python backend\app.py

pause
