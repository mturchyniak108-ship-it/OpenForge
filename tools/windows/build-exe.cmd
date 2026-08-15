@echo off
setlocal

cd /d "%~dp0..\.."

powershell.exe -ExecutionPolicy Bypass -File "tools\windows\build-exe.ps1"

if errorlevel 1 (
    echo.
    echo EXE BUILD FAILED
    exit /b 1
)

echo.
echo EXE BUILD SUCCESSFUL
