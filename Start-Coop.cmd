@echo off
setlocal
cd /d "%~dp0"
set "COOP_PYTHON=%~dp0.coop-runtime\python.exe"
if exist "%COOP_PYTHON%" goto launch
set "COOP_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%COOP_PYTHON%" goto launch
set "COOP_PYTHON=python"
where python >nul 2>nul
if errorlevel 1 (
  echo Python is required to run the co-op launcher.
  pause
  exit /b 1
)
:launch
"%COOP_PYTHON%" -c "import cryptography" >nul 2>nul
if errorlevel 1 (
  echo Co-op dependencies are missing. Run this once with your Python:
  echo python -m pip install -r reconstruction\requirements.txt
  pause
  exit /b 1
)
rem Automatic update (switch off: set COOP_AUTO_UPDATE=0 or create coop-update\no-auto-update).
rem Everything below is ONE block: cmd parses it before running it, so the update may
rem replace this file. COOP_UPDATE_ARGS is empty; tests point it at a local release.
(
  if exist "%~dp0coop_autoupdate.py" "%COOP_PYTHON%" -I -B "%~dp0coop_autoupdate.py" %COOP_UPDATE_ARGS%
  if errorlevel 10 if not errorlevel 11 "%~dp0Azeroth-Survivors-Together-Updater.exe" --no-pause %COOP_UPDATE_ARGS%
  if exist "%~dp0coop_autoupdate.py" set "COOP_UPDATE_CHECKED=1"
  "%COOP_PYTHON%" "%~dp0coop_launcher.py" %*
  if errorlevel 1 pause
  exit /b
)
