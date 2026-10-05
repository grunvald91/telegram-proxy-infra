@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "CODEX_PY=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%CODEX_PY%" (
  "%CODEX_PY%" bot.py
  goto done
)
where py >nul 2>nul
if %errorlevel%==0 (
  py bot.py
) else (
  python bot.py
)
:done
pause
