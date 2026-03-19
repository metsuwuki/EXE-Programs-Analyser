@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "PS_ARGS="

:parse_args
if "%~1"=="" goto run_setup
if /i "%~1"=="--skip-portable" set "PS_ARGS=%PS_ARGS% -SkipPortable"
shift
goto parse_args

:run_setup

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build_setup.ps1" %PS_ARGS%
exit /b %ERRORLEVEL%
