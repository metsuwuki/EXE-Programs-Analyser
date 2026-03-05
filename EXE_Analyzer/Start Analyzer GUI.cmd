@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
start "" "%~dp0exe_tester_gui.exe"
exit /b %ERRORLEVEL%
