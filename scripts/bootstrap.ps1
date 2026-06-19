param(
    [switch]$Dev
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    python -m venv .venv
}

& $VenvPython -m pip install --upgrade pip

if ($Dev) {
    & $VenvPython -m pip install -r requirements-dev.txt
} else {
    & $VenvPython -m pip install -r requirements.txt
}

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
}

Write-Host "Bootstrap complete."
Write-Host "Run: powershell -ExecutionPolicy Bypass -File scripts/run.ps1"
