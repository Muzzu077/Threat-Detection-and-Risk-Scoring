# ThreatPulse Enterprise Launch Script v2.2
# Fixed: Uses system Python (not venv), uses cmd.exe for npm.cmd

Write-Host ""
Write-Host "  THREATPULSE ENTERPRISE v2.0 STARTING..." -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor DarkCyan

$root = $PSScriptRoot
if (-not $root -or $root -eq '') {
    $root = Split-Path -Parent (Resolve-Path $MyInvocation.MyCommand.Path)
}
Set-Location $root

# ── Detect correct Python (the one that has our packages) ───────────────────
$sysPythonCmd = Get-Command python -ErrorAction SilentlyContinue
$sysPython = if ($sysPythonCmd) { $sysPythonCmd.Source } else { $null }

$pythonCandidates = @(
    $sysPython,
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe",
    "python3",
    "python"
) | Where-Object { $_ -and $_ -ne '' }

$pyExe = $null
foreach ($candidate in $pythonCandidates) {
    $test = & $candidate -c "import pandas; print('ok')" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $pyExe = $candidate
        Write-Host "  Python: $pyExe" -ForegroundColor DarkGray
        break
    }
}

if (-not $pyExe) {
    Write-Host "  ERROR: Cannot find Python with required packages." -ForegroundColor Red
    Write-Host "         Run: pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

# ── Detect npm ──────────────────────────────────────────────────────────────
$sysNpmCmd = Get-Command npm -ErrorAction SilentlyContinue
$npmCmd = if ($sysNpmCmd) { $sysNpmCmd.Source } else { $null }

if (-not $npmCmd) {
    # Common locations
    if (Test-Path "C:\Program Files\nodejs\npm.cmd") { $npmCmd = "C:\Program Files\nodejs\npm.cmd" }
    elseif (Test-Path "$env:APPDATA\npm\npm.cmd") { $npmCmd = "$env:APPDATA\npm\npm.cmd" }
}
Write-Host "  npm:    $npmCmd" -ForegroundColor DarkGray

# ── 1. Start Ingestion Service ───────────────────────────────────────────────
Write-Host ""
Write-Host "  [1/4] Starting Log Ingestion Service..." -ForegroundColor Green
$ingestion = Start-Process `
    -FilePath $pyExe `
    -ArgumentList @("-m", "src.ingestion_service") `
    -WorkingDirectory $root `
    -PassThru -NoNewWindow
Write-Host "        PID: $($ingestion.Id)" -ForegroundColor DarkGray

Start-Sleep -Seconds 2

# ── 2. Start Traffic Simulator ───────────────────────────────────────────────
Write-Host "  [2/4] Starting Traffic Simulator..." -ForegroundColor Green
$simulator = Start-Process `
    -FilePath $pyExe `
    -ArgumentList @("utils/simulate_live_traffic.py") `
    -WorkingDirectory $root `
    -PassThru -NoNewWindow
Write-Host "        PID: $($simulator.Id)" -ForegroundColor DarkGray

Start-Sleep -Seconds 1

# ── 3. Start FastAPI Backend ─────────────────────────────────────────────────
Write-Host "  [3/4] Starting FastAPI Backend on port 8000..." -ForegroundColor Green
$fastapi = Start-Process `
    -FilePath $pyExe `
    -ArgumentList @("-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload") `
    -WorkingDirectory $root `
    -PassThru -NoNewWindow
Write-Host "        PID: $($fastapi.Id)" -ForegroundColor DarkGray

Start-Sleep -Seconds 3

# ── 4. Start React Frontend ──────────────────────────────────────────────────
Write-Host "  [4/4] Starting React Frontend on port 5173..." -ForegroundColor Green
$frontendDir = Join-Path $root "frontend"

if ($npmCmd) {
    # npm.cmd must be launched via cmd.exe. We use 'npm' directly so cmd.exe resolves to npm.cmd and not npm.ps1
    $frontend = Start-Process `
        -FilePath "cmd.exe" `
        -ArgumentList "/c", "npm run dev -- --host 127.0.0.1" `
        -WorkingDirectory $frontendDir `
        -PassThru -NoNewWindow
    Write-Host "        PID: $($frontend.Id)" -ForegroundColor DarkGray
} else {
    Write-Host "        npm not found - start frontend manually: cd frontend ; npm run dev" -ForegroundColor Yellow
    $frontend = $null
}

Start-Sleep -Seconds 4

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host "  ALL SERVICES STARTED" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  React Dashboard   :  http://localhost:5173" -ForegroundColor White
Write-Host "  FastAPI API       :  http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs (Swagger):  http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "  Login: admin / threatpulse" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""

Start-Sleep -Seconds 2
Start-Process "http://localhost:5173"

# ── Keep-alive + clean shutdown ──────────────────────────────────────────────
try {
    while ($true) { Start-Sleep -Seconds 5 }
}
finally {
    Write-Host ""
    Write-Host "  Shutting down services..." -ForegroundColor Red
    @($ingestion, $simulator, $fastapi, $frontend) | ForEach-Object {
        if ($_ -and -not $_.HasExited) {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  Done." -ForegroundColor DarkGray
}
