@echo off
setlocal
title Tactical Bot - Service Uninstaller

set SERVICE_NAME=TacticalBotSentinel
set NSSM=%~dp0..\bin\nssm.exe

:: בדיקת הרשאות Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator!
    pause
    exit /b 1
)

echo Stopping %SERVICE_NAME%...
"%NSSM%" stop %SERVICE_NAME%

echo Removing service...
"%NSSM%" remove %SERVICE_NAME% confirm

echo.
echo Done. Service removed.
pause
