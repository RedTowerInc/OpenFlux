@echo off
setlocal

echo Stopping OpenFlux Windows exit node...
taskkill /IM OpenFluxExitNode.exe /F >nul 2>&1
if "%errorlevel%"=="0" (
  echo OpenFlux exit node stopped.
) else (
  echo OpenFlux exit node was not running.
)

pause
