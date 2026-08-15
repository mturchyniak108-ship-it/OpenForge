$ErrorActionPreference = "Stop"

Write-Host "========================================"
Write-Host " OpenForge EXE Build"
Write-Host "========================================"

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

if (!(Test-Path ".venv")) {
    python -m venv .venv
}

& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install pyinstaller

New-Item -ItemType Directory -Force -Path "dist" | Out-Null

Write-Host ""
Write-Host "Building OpenForge executable..."

& ".\.venv\Scripts\python.exe" -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name OpenForge `
    projects\backend\main.py

Write-Host ""
Write-Host "========================================"
Write-Host " EXE BUILD COMPLETE"
Write-Host "========================================"

Get-ChildItem "dist"
