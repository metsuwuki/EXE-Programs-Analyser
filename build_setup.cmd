@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "PS_ARGS="
if /i "%~1"=="--skip-portable" set "PS_ARGS=-SkipPortable"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build_setup.ps1" %PS_ARGS%
exit /b %ERRORLEVEL%
