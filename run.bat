@echo off
setlocal
set SCRIPT_DIR=%~dp0
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
) else (
    echo [HATA] .venv ortami bulunamadi. Lutfen once sanal ortami kurun.
    pause
)
