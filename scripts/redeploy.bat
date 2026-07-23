@echo off
setlocal
title Tactical Bot - Redeploy Service

set SERVICE_NAME=TacticalBotSentinel
set BOT_DIR=%~dp0..
set NSSM=%BOT_DIR%\bin\nssm.exe

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

echo ========================================
echo Tactical Bot - Service Redeployment
echo ========================================
echo.

:: 1. עצירת השירות הקיים
echo [1/4] Stopping existing service...
"%NSSM%" stop %SERVICE_NAME%
if %errorlevel% neq 0 (
    echo WARNING: Service may not be running or already stopped
)
echo.

:: 2. המתנה לעצירה מלאה
echo [2/4] Waiting for service to fully stop...
timeout /t 3 /nobreak >nul
echo.

:: 3. בדיקת תלות ועדכונים
echo [3/4] Checking dependencies...
if exist "%BOT_DIR%\requirements.txt" (
    echo Installing/updating Python dependencies...
    call "%BOT_DIR%\.venv\Scripts\activate.bat"
    pip install -r "%BOT_DIR%\requirements.txt" --quiet
    if %errorlevel% neq 0 (
        echo WARNING: Some dependencies may have failed to install
    )
)
echo.

:: 4. הפעלה מחדש של השירות
echo [4/4] Starting service...
"%NSSM%" start %SERVICE_NAME%
if %errorlevel% neq 0 (
    echo ERROR: Failed to start service
    echo Checking service status...
    "%NSSM%" status %SERVICE_NAME%
    pause
    exit /b 1
)

echo.
echo ========================================
echo SUCCESS: Service redeployed successfully!
echo ========================================
echo Service: %SERVICE_NAME%
echo Status:  Running
echo Logs:    %BOT_DIR%\logs\
echo.
echo Service will restart automatically if it crashes.
echo Use 'services.msc' for manual management.
echo.
pause
