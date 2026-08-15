$ErrorActionPreference = "Stop"

Write-Host "========================================"
Write-Host " OpenForge Windows Build"
Write-Host "========================================"

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

Write-Host ""
Write-Host "[1/4] Python"
python --version

Write-Host ""
Write-Host "[2/4] Creating virtual environment"
if (!(Test-Path ".venv")) {
    python -m venv .venv
}

& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip

Write-Host ""
Write-Host "[3/4] Installing backend dependencies"

if (Test-Path "projects\securechat\requirements.txt") {
    & ".\.venv\Scripts\python.exe" -m pip install -r projects\securechat\requirements.txt
}

Write-Host ""
Write-Host "[4/4] Build verification"

& ".\.venv\Scripts\python.exe" -m compileall projects

Write-Host ""
Write-Host "========================================"
Write-Host " BUILD COMPLETE"
Write-Host "========================================"
