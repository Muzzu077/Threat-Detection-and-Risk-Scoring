@echo off
title ThreatPulse Launcher
echo ============================================
echo   ThreatPulse - Starting All Services
echo ============================================
echo.

:: Start FastAPI Backend (includes Telegram bot poller)
echo [1/3] Starting FastAPI Backend (port 8000)...
start "ThreatPulse-API" cmd /k "cd /d E:\Muzammil\Threat-Detection-and-Risk-Scoring && set PYTHONIOENCODING=utf-8 && .venv\Scripts\python.exe -m uvicorn api.main:app --host 0.0.0.0 --port 8000"

:: Wait for API to be ready
timeout /t 5 /nobreak >nul

:: Start Ingestion Service
echo [2/3] Starting Ingestion Service (watchdog)...
start "ThreatPulse-Ingestion" cmd /k "cd /d E:\Muzammil\Threat-Detection-and-Risk-Scoring && set PYTHONIOENCODING=utf-8 && .venv\Scripts\python.exe -u -m src.ingestion_service"

:: Start Frontend
echo [3/3] Starting React Frontend (port 5173)...
start "ThreatPulse-Frontend" cmd /k "cd /d E:\Muzammil\Threat-Detection-and-Risk-Scoring\frontend && npx vite --port 5173"

echo.
echo ============================================
echo   All services started!
echo   Dashboard:      http://localhost:5173
echo   API:            http://localhost:8000
echo   API Docs:       http://localhost:8000/docs
echo   Login:          admin / threatpulse
echo   Telegram Bot:   Callback handler running
echo ============================================
echo.
echo To generate live traffic, run in a new terminal:
echo   cd E:\Muzammil\Threat-Detection-and-Risk-Scoring
echo   set PYTHONIOENCODING=utf-8
echo   .venv\Scripts\python.exe utils\simulate_live_traffic.py
echo.
pause
