@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "CARGO_CMD=cargo"
where cargo >nul 2>nul
if errorlevel 1 (
  if exist "%USERPROFILE%\.cargo\bin\cargo.exe" (
    set "CARGO_CMD=%USERPROFILE%\.cargo\bin\cargo.exe"
  ) else (
    echo [ERROR] cargo not found. Install Rust toolchain first.
    pause
    exit /b 1
  )
)

echo [1/4] Building release binaries...
"%CARGO_CMD%" build --release --bins
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

set "DIST=%~dp0dist\EXE_Analyzer"
echo [2/4] Preparing dist folder: "%DIST%"
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\logs"
mkdir "%DIST%\.engine"

echo [3/4] Copying files...
copy /y "%~dp0target\release\exe_tester_web_gui.exe" "%DIST%\exe_tester_web_gui.exe" >nul
copy /y "%~dp0target\release\exe_tester.exe" "%DIST%\.engine\analyzer_core.exe" >nul
attrib +h "%DIST%\.engine" >nul 2>nul
attrib +h "%DIST%\.engine\analyzer_core.exe" >nul 2>nul
if exist "%~dp0assets\metsuki_logo.png" copy /y "%~dp0assets\metsuki_logo.png" "%DIST%\metsuki_logo.png" >nul
if exist "%~dp0assets\logo.png" copy /y "%~dp0assets\logo.png" "%DIST%\logo.png" >nul
if exist "%~dp0assets\icon.ico" copy /y "%~dp0assets\icon.ico" "%DIST%\icon.ico" >nul
if exist "%~dp0metsuki_logo.png" copy /y "%~dp0metsuki_logo.png" "%DIST%\metsuki_logo.png" >nul
if exist "%~dp0logo.png" copy /y "%~dp0logo.png" "%DIST%\logo.png" >nul
if exist "%~dp0icon.ico" copy /y "%~dp0icon.ico" "%DIST%\icon.ico" >nul

echo [4/4] Finalizing minimal portable package...

echo.
echo =====================================================
echo Portable package ready:
echo %DIST%
echo -----------------------------------------------------
echo Primary UI binary: exe_tester_web_gui.exe
echo Internal engine is packaged under .engine\ (hidden, required)
echo =====================================================
echo.
exit /b 0
