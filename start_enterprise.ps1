# PowerShell script to launch Enterprise Edition
$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting Context-Aware Security System (Enterprise)" -ForegroundColor Green

# 1. Create Ingest Folder
if (-not (Test-Path "logs_ingest")) {
    New-Item -ItemType Directory -Force -Path "logs_ingest" | Out-Null
    Write-Host "Created 'logs_ingest' directory."
}

# 2. Check Python
$pythonCmd = "python"
try {
    & $pythonCmd --version | Out-Null
} catch {
    $pythonCmd = "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe"
}

# 3. Start Ingestion Service in Background
Write-Host "Starting Real-Time Ingestion Service (Background)..." -ForegroundColor Cyan
$ingestJob = Start-Process -FilePath $pythonCmd -ArgumentList "src/ingestion_service.py" -PassThru -NoNewWindow
Write-Host "Background Service PID: $($ingestJob.Id)" -ForegroundColor Cyan

# 4. Start Traffic Simulator
Write-Host "Starting Live Traffic Generator (Background)..." -ForegroundColor Cyan
$trafficJob = Start-Process -FilePath $pythonCmd -ArgumentList "-u utils/simulate_live_traffic.py" -PassThru -NoNewWindow
Write-Host "Traffic Gen PID: $($trafficJob.Id)" -ForegroundColor Cyan

# 5. Start Dashboard
Write-Host "Launching Dashboard..." -ForegroundColor Green
Write-Host "Default Login: admin / admin123" -ForegroundColor Yellow

& $pythonCmd -m streamlit run dashboard/app.py

# Cleanup when dashboard closes
Stop-Process -Id $ingestJob.Id -ErrorAction SilentlyContinue
Stop-Process -Id $trafficJob.Id -ErrorAction SilentlyContinue
