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
Remove-Item -Path "security_events.db", "dashboard\security_events.db", "data\threatpulse.db" -Force -ErrorAction SilentlyContinue

Write-Host "  2. Clearing Ingestion Logs..." -ForegroundColor Cyan
if (Test-Path "logs_ingest") {
    Remove-Item -Path "logs_ingest\*.csv" -Force -ErrorAction SilentlyContinue
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
