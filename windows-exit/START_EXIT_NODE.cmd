@echo off
setlocal EnableExtensions
cd /d "%~dp0"

title OpenFlux Windows Exit Node

rem Auto-elevate: WinDivert requires Administrator privileges.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Requesting Administrator privileges...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

if not exist "%~dp0OpenFluxExitNode.exe" (
  echo [ERROR] OpenFluxExitNode.exe not found in this folder.
  pause
  exit /b 2
)

if not exist "%~dp0WinDivert.dll" (
  echo [ERROR] WinDivert.dll not found in this folder.
  pause
  exit /b 3
)

if not exist "%~dp0WinDivert64.sys" (
  echo [ERROR] WinDivert64.sys not found in this folder.
  pause
  exit /b 4
)

if not exist "%~dp0config.cmd" (
  echo [ERROR] config.cmd not found.
  pause
  exit /b 5
)

call "%~dp0config.cmd"
if not defined YANDEX_URL (
  echo [ERROR] YANDEX_URL is empty in config.cmd.
  pause
  exit /b 6
)

echo.
echo ============================================================
echo  OpenFlux Windows EXIT NODE
echo ============================================================
echo  Yandex transport: %YANDEX_URL%
echo  Keep this window OPEN while the phone uses OpenFlux.
echo  Press Ctrl+C to stop.
echo ============================================================
echo.

"%~dp0OpenFluxExitNode.exe" --exit-node --transport yandex --url "%YANDEX_URL%" --debug
set "RC=%errorlevel%"

echo.
echo OpenFlux stopped with exit code %RC%.
echo If it failed, take a screenshot of this window and send it to ChatGPT.
pause
exit /b %RC%
