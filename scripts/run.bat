@echo off
setlocal
set REPO_DIR=%~dp0..
if exist "%REPO_DIR%\.venv\Scripts\python.exe" (
    pushd "%REPO_DIR%"
    "%REPO_DIR%\.venv\Scripts\python.exe" -m pulseops %*
    popd
) else (
    echo [HATA] .venv ortami bulunamadi. Lutfen once sanal ortami kurun.
    pause
)
