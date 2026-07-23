@echo off
title Tactical Bot - Stop Service

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator!
    pause
    exit /b 1
)

echo Stopping TacticalBotSentinel...
"%~dp0..\bin\nssm.exe" stop TacticalBotSentinel
echo.
echo Done. Bot is offline.
pause
