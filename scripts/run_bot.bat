@echo off
title Tactical Bot - Sentinel
cd /d "%~dp0.."
if not exist logs mkdir logs
echo [%date% %time%] Sentinel starting... >> logs\sentinel.log
REM Using .venv (Python 3.12) with full package support
call .venv\Scripts\activate.bat
.venv\Scripts\python.exe -u main.py >> logs\sentinel.log 2>&1
echo [%date% %time%] Sentinel process ended. >> logs\sentinel.log
pause
