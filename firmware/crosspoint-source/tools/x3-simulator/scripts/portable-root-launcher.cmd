@echo off
setlocal
set "X3_LAB_APP=%~dp0app\firmware\crosspoint-source\tools\x3-simulator"
if not exist "%X3_LAB_APP%\run-x3-simulator.cmd" (
  echo X3 Preview ^& QA Lab is incomplete.
  echo Extract the entire ZIP before launching it.
  pause
  exit /b 2
)
call "%X3_LAB_APP%\run-x3-simulator.cmd" %*
exit /b %ERRORLEVEL%
