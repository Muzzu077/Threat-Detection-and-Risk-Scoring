# ThreatPulse + DVWA Attack Lab -Unified Launch Script
# Starts: API, Frontend, Ingestion, Simulator, Docker Desktop, DVWA Stack

Write-Host ""
Write-Host "  THREATPULSE + DVWA ATTACK LAB STARTING..." -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor DarkCyan

$root = $PSScriptRoot
if (-not $root -or $root -eq '') { $root = Split-Path -Parent (Resolve-Path $MyInvocation.MyCommand.Path) }
Set-Location $root

# ── Load startup config from .env ─────────────────────────────────────────
$enableSimulator = $true
$enableDvwa = $true
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile
    $simLine = $envContent | Where-Object { $_ -match "^ENABLE_TRAFFIC_SIMULATOR\s*=" }
    if ($simLine) { if (($simLine -split "=", 2)[1].Trim().ToLower() -eq "false") { $enableSimulator = $false } }
    
    $dvwaLine = $envContent | Where-Object { $_ -match "^ENABLE_DVWA_LAB\s*=" }
    if ($dvwaLine) { if (($dvwaLine -split "=", 2)[1].Trim().ToLower() -eq "false") { $enableDvwa = $false } }
}

# ── Detect Python ─────────────────────────────────────────────────────────
$sysPythonCmd = Get-Command python -ErrorAction SilentlyContinue
$sysPython = if ($sysPythonCmd) { $sysPythonCmd.Source } else { $null }
$pythonCandidates = @($sysPython, "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe", "python3", "python") | Where-Object { $_ -and $_ -ne '' }

$pyExe = $null
foreach ($candidate in $pythonCandidates) {
    $test = & $candidate -c "import pandas; print('ok')" 2>&1
    if ($LASTEXITCODE -eq 0) { $pyExe = $candidate; Write-Host "  Python: $pyExe" -ForegroundColor DarkGray; break }
}
if (-not $pyExe) { Write-Host "  ERROR: Cannot find Python with required packages. Run: pip install -r requirements.txt" -ForegroundColor Red; exit 1 }

# ── Detect npm.cmd (must be .cmd for cmd.exe launch) ─────────────────────
$npmCmd = $null
$npmCmdPaths = @("C:\Program Files\nodejs\npm.cmd", "$env:APPDATA\npm\npm.cmd")
foreach ($p in $npmCmdPaths) { if (Test-Path $p) { $npmCmd = $p; break } }
if (-not $npmCmd) {
    $npmExe = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($npmExe) { $npmCmd = $npmExe.Source }
}
if ($npmCmd) { Write-Host "  npm:    $npmCmd" -ForegroundColor DarkGray
} else { Write-Host "  npm:    NOT FOUND" -ForegroundColor Yellow }

# ── Detect Docker ─────────────────────────────────────────────────────────
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
$hasDocker = $null -ne $dockerCmd
if ($hasDocker) { Write-Host "  Docker: $($dockerCmd.Source)" -ForegroundColor DarkGray
} else { Write-Host "  Docker: NOT FOUND -DVWA stack will be skipped" -ForegroundColor Yellow }

Write-Host ""

# ── 0. Seed demo account ─────────────────────────────────────────────────
Write-Host "  [0/6] Seeding demo account..." -ForegroundColor Cyan
& $pyExe "utils/seed_demo_account.py" 2>&1 | ForEach-Object { Write-Host "       $_" -ForegroundColor DarkGray }

# ── 1. Start Ingestion Service ────────────────────────────────────────────
Write-Host ""
Write-Host "  [1/6] Starting Log Ingestion Service..." -ForegroundColor Green
$ingestion = Start-Process -FilePath $pyExe -ArgumentList @("-m", "src.ingestion_service") -WorkingDirectory $root -PassThru -NoNewWindow
Write-Host "        PID: $($ingestion.Id)" -ForegroundColor DarkGray
Start-Sleep -Seconds 2

# ── 2. Start Traffic Simulator ────────────────────────────────────────────
if ($enableSimulator) {
    Write-Host "  [2/6] Starting Traffic Simulator..." -ForegroundColor Green
    $simulator = Start-Process -FilePath $pyExe -ArgumentList @("utils/simulate_live_traffic.py") -WorkingDirectory $root -PassThru -NoNewWindow
    Write-Host "        PID: $($simulator.Id)" -ForegroundColor DarkGray
    Start-Sleep -Seconds 1
} else { Write-Host "  [2/6] Traffic Simulator is DISABLED in .env" -ForegroundColor Yellow; $simulator = $null }

# ── 3. Start FastAPI Backend ──────────────────────────────────────────────
Write-Host "  [3/6] Starting FastAPI Backend on port 8000..." -ForegroundColor Green
$fastapi = Start-Process -FilePath $pyExe -ArgumentList @("-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload") -WorkingDirectory $root -PassThru -NoNewWindow
Write-Host "        PID: $($fastapi.Id)" -ForegroundColor DarkGray
Start-Sleep -Seconds 8

# ── 4. Start React Frontend ──────────────────────────────────────────────
Write-Host "  [4/6] Starting React Frontend on port 5173..." -ForegroundColor Green
$frontendDir = Join-Path $root "frontend"
$frontend = $null
if ($npmCmd) {
    $frontend = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$npmCmd`" run dev -- --host 127.0.0.1" -WorkingDirectory $frontendDir -PassThru -NoNewWindow
    Write-Host "        PID: $($frontend.Id)" -ForegroundColor DarkGray
} else { Write-Host "        npm.cmd not found - start frontend manually: cd frontend; npm run dev" -ForegroundColor Yellow }
Start-Sleep -Seconds 4

# ── 5 & 6. DVWA Attack Lab (Docker) ──────────────────────────────────────
$dvwaStarted = $false
if ($hasDocker -and $enableDvwa) {
    Write-Host "  [5/6] Generating DVWA shipper API key..." -ForegroundColor Green
    & $pyExe "utils/ensure_dvwa_api_key.py" 2>&1 | ForEach-Object { Write-Host "       $_" -ForegroundColor DarkGray }

    Write-Host "  [6/6] Starting DVWA Attack Lab (Docker)..." -ForegroundColor Green

    $dockerRunning = $false
    try { docker info 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $dockerRunning = $true } } catch {}

    if (-not $dockerRunning) {
        Write-Host "        Docker daemon not running -starting Docker Desktop..." -ForegroundColor Yellow
        $dockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dockerDesktop) {
            Start-Process -FilePath $dockerDesktop
            Write-Host "        Waiting for Docker daemon..." -ForegroundColor DarkGray
            $deadline = (Get-Date).AddSeconds(120)
            while ((Get-Date) -lt $deadline) {
                try { docker info 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $dockerRunning = $true; Write-Host "        Docker daemon is ready" -ForegroundColor DarkGray; break } } catch {}
                Start-Sleep -Seconds 3
            }
        }
        if (-not $dockerRunning) { Write-Host "        Docker Desktop failed to start -skipping DVWA stack" -ForegroundColor Red }
    }

    if ($dockerRunning) {
        $dvwaDir = Join-Path $root "dvwa-stack"
        Write-Host "        Building and starting containers..." -ForegroundColor DarkGray
        & docker compose -f "$dvwaDir\docker-compose.yml" up --build -d 2>&1 | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
        if ($LASTEXITCODE -eq 0) {
            $dvwaStarted = $true
            Write-Host "        DVWA stack is running" -ForegroundColor Green
        } else {
            Write-Host "        docker compose failed -retrying in 10s..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            & docker compose -f "$dvwaDir\docker-compose.yml" up --build -d 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $dvwaStarted = $true; Write-Host "        DVWA stack is running (retry)" -ForegroundColor Green
            } else { Write-Host "        DVWA stack failed. Run manually: cd dvwa-stack; docker compose up --build -d" -ForegroundColor Red }
        }
    }
} elseif (-not $hasDocker) {
    Write-Host "  [5/6] Skipped -Docker not installed" -ForegroundColor Yellow
    Write-Host "  [6/6] Skipped -Docker not installed" -ForegroundColor Yellow
} else {
    Write-Host "  [5/6] DVWA Lab is DISABLED in .env" -ForegroundColor Yellow
    Write-Host "  [6/6] DVWA Lab is DISABLED in .env" -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host "  ALL SERVICES STARTED" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  React Dashboard   :  http://localhost:5173" -ForegroundColor White
Write-Host "  FastAPI API       :  http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs (Swagger):  http://localhost:8000/docs" -ForegroundColor White
if ($dvwaStarted) {
    Write-Host "  DVWA (via nginx)  :  http://localhost:8080" -ForegroundColor White
    Write-Host "  DVWA Attacks      :  Running (12 modules cycling)" -ForegroundColor White
}
Write-Host ""
Write-Host "  Login: demo@threatpulse.com / ThreatPulse2025" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""

Start-Sleep -Seconds 2
Start-Process "http://localhost:5173"

# ── Keep-alive + clean shutdown ───────────────────────────────────────────
try { while ($true) { Start-Sleep -Seconds 5 } }
finally {
    Write-Host ""
    Write-Host "  Shutting down services..." -ForegroundColor Red
    @($ingestion, $simulator, $fastapi, $frontend) | ForEach-Object {
        if ($_ -and -not $_.HasExited) { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($dvwaStarted) {
        Write-Host "  Stopping DVWA Docker stack..." -ForegroundColor Red
        $dvwaDir = Join-Path $root "dvwa-stack"
        docker compose -f "$dvwaDir\docker-compose.yml" down 2>&1 | Out-Null
    }
    Write-Host "  All services stopped." -ForegroundColor DarkGray
}
