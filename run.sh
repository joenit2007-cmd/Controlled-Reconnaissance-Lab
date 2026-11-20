#!/usr/bin/env bash
# ==============================================================
#      Controlled Reconnaissance Lab - Linux / Kali Startup
# ==============================================================
set -e

echo "[*] Checking Python environment..."
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
elif command -v python &>/dev/null; then
    PYTHON_CMD=python
else
    echo "[!] Error: Python 3 is required but not installed."
    exit 1
fi

echo "[*] Launching Controlled Reconnaissance Lab on http://127.0.0.1:5000 ..."
$PYTHON_CMD app.py
