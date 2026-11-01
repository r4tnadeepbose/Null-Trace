param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "[Null-Trace] Building portable $Version from $Root"

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[Null-Trace] Creating virtual environment"
    python -m venv .venv
}

$Python = ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip | Out-Null
& $Python -m pip install -r requirements.txt | Out-Null
& $Python -m pip install pyinstaller | Out-Null

Write-Host "[Null-Trace] Running tests"
& $Python -m unittest discover -s tests

Write-Host "[Null-Trace] Freezing with PyInstaller"
& $Python -m PyInstaller --noconfirm --clean packaging\nulltrace.spec

$OutDir = "dist\Null-Trace"
if (-not (Test-Path "$OutDir\Null-Trace.exe")) {
    throw "PyInstaller did not produce $OutDir\Null-Trace.exe"
}

Copy-Item LICENSE, README.md -Destination $OutDir -Force

$Zip = "dist\Null-Trace-$Version-win64.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Compress-Archive -Path "$OutDir\*" -DestinationPath $Zip

Write-Host ""
Write-Host "[Null-Trace] Done"
Write-Host "  folder : $OutDir"
Write-Host "  archive: $Zip"
Write-Host ""
Write-Host "The build is unsigned. Windows SmartScreen will warn on first run;"
Write-Host "that is expected for a local build."
