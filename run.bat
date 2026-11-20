@echo off
echo ==============================================================
echo       Controlled Reconnaissance Lab - Startup Script
echo ==============================================================
echo.

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [*] Launching Controlled Reconnaissance Lab with 'py'...
    py app.py
    goto end
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [*] Launching Controlled Reconnaissance Lab with 'python'...
    python app.py
    goto end
)

if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    echo [*] Launching with detected Python 3.13...
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" app.py
    goto end
)

echo [!] Error: Python 3 not found on PATH. Please ensure Python is installed.
pause

:end
