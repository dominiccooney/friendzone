@echo off
setlocal
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0trace-viewer.ps1" %*
exit /b %errorlevel%