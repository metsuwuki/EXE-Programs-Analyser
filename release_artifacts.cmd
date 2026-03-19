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

echo [3/4] Build setup installer (optional if Inno Setup is installed)...
call "%~dp0build_setup.cmd" --skip-portable
if errorlevel 1 (
  echo [WARN] Setup build skipped. Portable artifact is ready.
  echo [WARN] Install Inno Setup and run build_setup.cmd to produce Metsuki_EXE_Analyzer_Setup_*.exe
)

echo [4/4] Done.
echo Portable: "%~dp0dist\EXE_Analyzer"
echo Setup:    "%~dp0dist\Metsuki_EXE_Analyzer_Setup_*.exe"

REM Handle --sign and --skip-setup flags
set "PS_ARGS="

if /i "%~1"=="--sign" (
  set "PS_ARGS=-Sign"
) else if /i "%~1"=="--skip-setup" (
  set "PS_ARGS=-SkipSetup"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build_release.ps1" %PS_ARGS%
if errorlevel 1 (
  echo [ERROR] build_release.ps1 failed.
  exit /b 1
)

echo [DONE] Artifacts are in "%~dp0dist"
exit /b 0
