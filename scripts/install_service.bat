@echo off
setlocal
title Tactical Bot - Service Installer

set SERVICE_NAME=TacticalBotSentinel
set BOT_DIR=%~dp0..
set PYTHON_EXE=%BOT_DIR%\.venv\Scripts\python.exe
set MAIN_SCRIPT=%BOT_DIR%\main.py
set NSSM=%BOT_DIR%\bin\nssm.exe
set LOG_DIR=%BOT_DIR%\logs

:: בדיקת הרשאות Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator!
    pause
    exit /b 1
)

:: בדיקת קיום NSSM
if not exist "%NSSM%" (
    echo ERROR: nssm.exe not found at: %NSSM%
    echo Download from: https://nssm.cc/download
    echo Place nssm.exe inside the 'bin' folder.
    pause
    exit /b 1
)

:: יצירת תיקיית לוגים
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Installing %SERVICE_NAME% as Windows Service...

"%NSSM%" install %SERVICE_NAME% "%PYTHON_EXE%" -u "%MAIN_SCRIPT%"
"%NSSM%" set %SERVICE_NAME% AppDirectory "%BOT_DIR%"
"%NSSM%" set %SERVICE_NAME% DisplayName "Tactical Bot - Sentinel"
"%NSSM%" set %SERVICE_NAME% Description "Autonomous Security Monitoring Telegram Bot"
"%NSSM%" set %SERVICE_NAME% Start SERVICE_AUTO_START
"%NSSM%" set %SERVICE_NAME% AppExit Default Restart

:: הגדרת לוגים עם rotation יומי (10MB max)
"%NSSM%" set %SERVICE_NAME% AppStdout "%LOG_DIR%\sentinel_out.log"
"%NSSM%" set %SERVICE_NAME% AppStderr "%LOG_DIR%\sentinel_err.log"
"%NSSM%" set %SERVICE_NAME% AppRotateFiles 1
"%NSSM%" set %SERVICE_NAME% AppRotateOnline 1
"%NSSM%" set %SERVICE_NAME% AppRotateSeconds 86400
"%NSSM%" set %SERVICE_NAME% AppRotateBytes 10485760

:: PYTHONUNBUFFERED=1 קריטי - בלי זה הלוגים לא נכתבים בזמן אמת
"%NSSM%" set %SERVICE_NAME% AppEnvironmentExtra "PYTHONUNBUFFERED=1"

echo Starting service...
"%NSSM%" start %SERVICE_NAME%

echo.
echo SUCCESS: Service installed and running!
echo Service: %SERVICE_NAME%
echo Logs:    %LOG_DIR%
echo Manage:  services.msc
pause
