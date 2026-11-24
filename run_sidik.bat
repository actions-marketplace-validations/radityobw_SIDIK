@echo off
title SIDIK - Secret Identification and Dependency Inspection Kit
cd /d "%~dp0"

set "PY_CMD=python"
if exist ".venv\Scripts\python.exe" set "PY_CMD=.venv\Scripts\python.exe"

if "%~1"=="" (
    "%PY_CMD%" sidik.py --gui
    pause
) else (
    "%PY_CMD%" sidik.py %*
)
