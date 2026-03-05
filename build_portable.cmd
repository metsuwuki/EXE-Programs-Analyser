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

echo [3/4] Copying files...
copy /y "%~dp0target\release\exe_tester_gui.exe" "%DIST%\exe_tester_gui.exe" >nul
copy /y "%~dp0target\release\exe_tester.exe" "%DIST%\exe_tester.exe" >nul
copy /y "%~dp0README.md" "%DIST%\README.md" >nul
if exist "%~dp0logo.png" copy /y "%~dp0logo.png" "%DIST%\logo.png" >nul
if exist "%~dp0EXE_icon.ico" copy /y "%~dp0EXE_icon.ico" "%DIST%\EXE_icon.ico" >nul
if exist "%~dp0exe_icon.ico" copy /y "%~dp0exe_icon.ico" "%DIST%\exe_icon.ico" >nul

echo [4/4] Creating launcher...
(
  echo @echo off
  echo setlocal
  echo chcp 65001 ^>nul
  echo cd /d "%%~dp0"
  echo start "" "%%~dp0exe_tester_gui.exe"
  echo exit /b %%ERRORLEVEL%%
) > "%DIST%\Start Analyzer GUI.cmd"
if exist "%DIST%\Start Analyzer GUI.vbs" del /q "%DIST%\Start Analyzer GUI.vbs"

echo.
echo =====================================================
echo Portable package ready:
echo %DIST%
echo -----------------------------------------------------
echo Run: "Start Analyzer GUI.cmd"
echo =====================================================
echo.
exit /b 0
