@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
wscript.exe "%~dp0Start Analyzer GUI.vbs" >nul 2>&1
exit /b %ERRORLEVEL%
