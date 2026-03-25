@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "PS_ARGS="

if /i "%~1"=="--sign" set "PS_ARGS=%PS_ARGS% -Sign"
if /i "%~1"=="--skip-setup" set "PS_ARGS=%PS_ARGS% -SkipSetup"
if /i "%~2"=="--sign" set "PS_ARGS=%PS_ARGS% -Sign"
if /i "%~2"=="--skip-setup" set "PS_ARGS=%PS_ARGS% -SkipSetup"

echo [INFO] Running unified release pipeline via scripts\build_release.ps1 %PS_ARGS%
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build_release.ps1" %PS_ARGS%
if errorlevel 1 (
  echo [ERROR] build_release.ps1 failed.
  exit /b 1
)

echo [DONE] Artifacts are in "%~dp0dist"
exit /b 0
