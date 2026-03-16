# Reset Data Utility Script

Write-Host ""
Write-Host "  THREATPULSE - RESET DATA" -ForegroundColor Yellow
Write-Host "  ================================================" -ForegroundColor DarkYellow

$root = $PSScriptRoot
if (-not $root -or $root -eq '') {
    $root = Split-Path -Parent (Resolve-Path $MyInvocation.MyCommand.Path)
}
Set-Location $root

Write-Host "  1. Deleting SQLite Databases..." -ForegroundColor Cyan

# Kill python processes to release file locks
Write-Host "  [Safety] Stopping any background Python or Node processes..."
Stop-Process -Name "python*" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "uvicorn" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "node" -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 1

$dbFiles = @("security_events.db", "dashboard\security_events.db", "data\threatpulse.db")
foreach ($f in $dbFiles) {
    if (Test-Path $f) {
        try {
            Remove-Item -Path $f -Force -ErrorAction Stop
            Write-Host "     Deleted: $f" -ForegroundColor DarkGray
        } catch {
            Write-Host "     ❌ WARN: Could not delete $f. File is likely LOCKED by a running process." -ForegroundColor Red
            Write-Host "     Please fully CLOSE your start_enterprise terminal before resetting." -ForegroundColor Yellow
        }
    }
}

Write-Host "  2. Clearing Ingestion Logs..." -ForegroundColor Cyan
if (Test-Path "logs_ingest") {
    try {
        Remove-Item -Path "logs_ingest\*.csv" -Force -ErrorAction Stop
        Write-Host "     Cleared CSV feeds." -ForegroundColor DarkGray
    } catch {
        Write-Host "     ⚠️  Partially cleared logs_ingest\ (some might be locked)." -ForegroundColor Yellow
    }
}

Write-Host "  3. Clearing SOAR Action Logs..." -ForegroundColor Cyan
if (Test-Path "data") {
    $soarFiles = @("blocked_ips.txt", "disabled_accounts.txt", "rate_limits.json")
    foreach ($f in $soarFiles) {
        $path = "data\$f"
        if (Test-Path $path) {
            Clear-Content -Path $path -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkYellow
Write-Host "  RESET SUCCESSFUL." -ForegroundColor Green
Write-Host "  All databases and synthetic logs have been wiped." -ForegroundColor White
Write-Host "  Restarting 'start_enterprise.ps1' will start completely fresh." -ForegroundColor DarkGray
Write-Host ""
