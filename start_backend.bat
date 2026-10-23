@echo off
title CyberSentinel AI - Backend Server
echo ===================================================
echo Starting CyberSentinel AI Backend Server (FastAPI)...
echo ===================================================
cd /d "%~dp0backend"
call venv\Scripts\activate.bat
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
pause
