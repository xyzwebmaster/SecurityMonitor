#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecurityMonitor installation script
.DESCRIPTION
    Sets up the monitoring script to run automatically at Windows startup,
    creates a scheduled task, and starts monitoring immediately.
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$monitorScript = Join-Path $scriptDir "SecurityMonitor.ps1"
$taskName = "SecurityMonitor"

Write-Host "=== SecurityMonitor Setup ===" -ForegroundColor Cyan

# 1. Execution policy
Write-Host "[1/5] Checking PowerShell execution policy..."
$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentPolicy -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
    Write-Host "  -> ExecutionPolicy set to RemoteSigned" -ForegroundColor Green
} else {
    Write-Host "  -> Current policy: $currentPolicy (OK)" -ForegroundColor Green
}

# 2. Create log directories
Write-Host "[2/5] Creating directories..."
$dirs = @("$scriptDir\Logs", "$scriptDir\Baselines")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
Write-Host "  -> Log and Baseline directories created" -ForegroundColor Green

# 3. Create scheduled task (auto-starts at logon)
Write-Host "[3/5] Creating scheduled task..."
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "  -> Existing task removed" -ForegroundColor Yellow
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScript`" -Silent"

$trigger = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "System security monitoring tool - auto start" | Out-Null
Write-Host "  -> Scheduled task created (auto-starts at every logon)" -ForegroundColor Green

# 4. Start immediately
Write-Host "[4/5] Starting monitoring now..."
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$state = (Get-ScheduledTask -TaskName $taskName).State
if ($state -eq "Running") {
    Write-Host "  -> Monitoring is running in the background" -ForegroundColor Green
} else {
    Write-Host "  -> Status: $state (try starting manually)" -ForegroundColor Yellow
}

# 5. Verification
Write-Host "[5/5] Verifying..."
Start-Sleep -Seconds 5
$logExists = Test-Path "$scriptDir\Logs\monitor_$(Get-Date -Format 'yyyy-MM-dd').log"
if ($logExists) {
    Write-Host "  -> Log file created, monitoring is active" -ForegroundColor Green
} else {
    Write-Host "  -> Log file not yet created, baseline may still be generating" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Status:" -ForegroundColor Cyan
Write-Host "  Auto-start    : ENABLED (at every logon)" -ForegroundColor White
Write-Host "  Current state : $state" -ForegroundColor White
Write-Host ""
Write-Host "Commands:" -ForegroundColor Cyan
Write-Host "  Check status : Get-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "  Stop         : Stop-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "  Start        : Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "  Remove       : Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor White
Write-Host ""
Write-Host "Log files  : $scriptDir\Logs\" -ForegroundColor Cyan
Write-Host "Baselines  : $scriptDir\Baselines\" -ForegroundColor Cyan
