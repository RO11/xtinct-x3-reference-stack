@echo off
setlocal
cd /d "%~dp0"

set "X3_LAB_PYTHON="
if exist "%~dp0runtime\python\python.exe" set "X3_LAB_PYTHON=%~dp0runtime\python\python.exe"

if defined X3_LAB_PYTHON (
  "%X3_LAB_PYTHON%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
  if errorlevel 1 goto :bundled_runtime_invalid
  echo Starting X3 Preview ^& QA Lab with its bundled Python runtime...
  "%X3_LAB_PYTHON%" -B server.py %*
  goto :finished
)

where py >nul 2>&1
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
  if not errorlevel 1 (
    echo Starting X3 Preview ^& QA Lab with the Python launcher...
    py -3 -B server.py %*
    goto :finished
  )
)

where python >nul 2>&1
if errorlevel 1 goto :runtime_missing
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 goto :runtime_missing
echo Starting X3 Preview ^& QA Lab with Python from PATH...
python -B server.py %*
goto :finished

:bundled_runtime_invalid
echo.
echo X3 Preview ^& QA Lab could not start its bundled Python runtime.
echo Re-extract the complete ZIP, then verify it against the published SHA-256.
echo.
pause
exit /b 1

:runtime_missing
echo.
echo X3 Preview ^& QA Lab could not find Python 3.10 or newer.
echo This is the source-portable package, not a self-contained executable.
echo Install Python from https://www.python.org/downloads/windows/
echo Then double-click this launcher again. Node and PlatformIO are not needed to preview the synthetic demo.
echo.
pause
exit /b 1

:finished
set "X3_SIM_EXIT=%ERRORLEVEL%"
if not "%X3_SIM_EXIT%"=="0" (
  echo.
  echo X3 Preview ^& QA Lab stopped with error %X3_SIM_EXIT%.
  pause
)
exit /b %X3_SIM_EXIT%
