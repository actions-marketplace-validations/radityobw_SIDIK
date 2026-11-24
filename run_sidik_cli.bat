@echo off
chcp 65001 >nul
title SIDIK - Interactive Security Console
cd /d "%~dp0"

set "PY_CMD=python"
if exist ".venv\Scripts\python.exe" set "PY_CMD=.venv\Scripts\python.exe"

if "%~1"=="" (
    "%PY_CMD%" sidik.py -i
) else (
    "%PY_CMD%" sidik.py %*
    pause
)
