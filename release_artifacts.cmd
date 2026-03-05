@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

echo [1/3] Build portable package...
call "%~dp0build_portable.cmd"
if errorlevel 1 (
  echo [ERROR] build_portable.cmd failed.
  exit /b 1
)

echo [2/3] Run security precheck (hash + Defender scan)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\pre_release_security_check.ps1" -DistPath ".\dist\EXE_Analyzer"
if errorlevel 1 (
  echo [ERROR] pre_release_security_check.ps1 failed.
  exit /b 1
)

echo [3/3] Done.
echo Artifacts: "%~dp0dist\EXE_Analyzer"
exit /b 0
