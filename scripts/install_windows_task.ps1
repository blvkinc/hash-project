param(
    [string]$TaskName = "IntegrityGuard",
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$AtStartup,
    [switch]$Dev
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$RunScript = Join-Path $ProjectRoot "scripts\run.ps1"
$BootstrapScript = Join-Path $ProjectRoot "scripts\bootstrap.ps1"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    $bootstrapArgs = @("-ExecutionPolicy", "Bypass", "-File", $BootstrapScript)
    if ($Dev) {
        $bootstrapArgs += "-Dev"
    }
    & powershell.exe @bootstrapArgs
}

if (-not (Test-Path (Join-Path $ProjectRoot ".env")) -and (Test-Path (Join-Path $ProjectRoot ".env.example"))) {
    Copy-Item (Join-Path $ProjectRoot ".env.example") (Join-Path $ProjectRoot ".env")
}

$argument = "-NoProfile -ExecutionPolicy Bypass -File `"$RunScript`" -HostName $HostName -Port $Port"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument -WorkingDirectory $ProjectRoot
$trigger = if ($AtStartup) {
    New-ScheduledTaskTrigger -AtStartup
} else {
    New-ScheduledTaskTrigger -AtLogOn
}
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "IntegrityGuard local file integrity monitor" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed and started scheduled task '$TaskName'."
Write-Host "Dashboard: http://localhost:$Port"
