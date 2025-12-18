# PowerShell script to robustly find Python and run the project
$ErrorActionPreference = "Stop"

Write-Host "Searching for Python configuration..." -ForegroundColor Cyan

# 1. Attempt to find a working Python executable
$candidates = @("python", "python3", "py")
$pythonCmd = $null

foreach ($cmd in $candidates) {
    try {
        $result = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($result) {
            # Check if it actually runs (not just the Store stub that fails)
            & $cmd --version | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $pythonCmd = $cmd
                break
            }
        }
    } catch {
        # Ignore errors
    }
}

# 2. If standard commands fail, check known Store paths
if (-not $pythonCmd) {
    $storePath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe"
    if (Test-Path $storePath) {
        $pythonCmd = $storePath
    }
}

if (-not $pythonCmd) {
    Write-Host "Python not found in standard locations." -ForegroundColor Red
    Write-Host "Please ensure Python 3.x is installed and added to your PATH."
    exit 1
}

Write-Host "Using Python: $pythonCmd" -ForegroundColor Green

# 3. Install/Check Requirements
Write-Host "Checking requirements..." -ForegroundColor Cyan
& $pythonCmd -m pip install -r requirements.txt | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Pip install had issues. Continuing..." -ForegroundColor Yellow
}

# 4. Generate Data
Write-Host "Generating synthetic data..." -ForegroundColor Cyan
& $pythonCmd utils/generate_data.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "Data generation failed." -ForegroundColor Red
    exit 1
}

# 5. Run Dashboard
Write-Host "Launching Dashboard..." -ForegroundColor Green
# We use -m streamlit to ensure we use the streamlit installed for this python
& $pythonCmd -m streamlit run dashboard/app.py
