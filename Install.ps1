#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecurityMonitor installation script
.DESCRIPTION
    Sets up the monitoring script to run automatically at Windows startup,
    creates a scheduled task, desktop shortcut, and starts monitoring immediately.
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$monitorScript = Join-Path $scriptDir "SecurityMonitor.ps1"
$taskName = "SecurityMonitor"

Write-Host "=== SecurityMonitor Setup ===" -ForegroundColor Cyan

# 0. Download project files from GitHub if SecurityMonitor.ps1 is missing (one-liner install)
if (-not (Test-Path $monitorScript)) {
    Write-Host "[0/6] Downloading SecurityMonitor from GitHub..." -ForegroundColor Yellow
    $repoZip = Join-Path $env:TEMP "SecurityMonitor.zip"
    $extractDir = Join-Path $env:TEMP "SecurityMonitor_extract"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://github.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool/archive/refs/heads/master.zip" -OutFile $repoZip -UseBasicParsing
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
        Expand-Archive -Path $repoZip -DestinationPath $extractDir -Force
        $innerDir = Get-ChildItem $extractDir | Select-Object -First 1
        $targetDir = Join-Path $env:USERPROFILE "SecurityMonitor"
        if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
        Copy-Item -Path "$($innerDir.FullName)\*" -Destination $targetDir -Recurse -Force
        Remove-Item $repoZip -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        # Update paths to the new location
        $scriptDir = $targetDir
        $monitorScript = Join-Path $scriptDir "SecurityMonitor.ps1"
        Write-Host "  -> Downloaded to $targetDir" -ForegroundColor Green
    } catch {
        Write-Host "  -> Download failed: $_" -ForegroundColor Red
        Write-Host "     Please download manually from https://github.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool" -ForegroundColor Yellow
        exit 1
    }
}

# 1. Execution policy
Write-Host "[1/6] Checking PowerShell execution policy..."
$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentPolicy -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
    Write-Host "  -> ExecutionPolicy set to RemoteSigned" -ForegroundColor Green
} else {
    Write-Host "  -> Current policy: $currentPolicy (OK)" -ForegroundColor Green
}

# 2. Create log directories
Write-Host "[2/6] Creating directories..."
$dirs = @("$scriptDir\Logs", "$scriptDir\Baselines")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
Write-Host "  -> Log and Baseline directories created" -ForegroundColor Green

# 3. Create scheduled task (auto-starts at logon)
Write-Host "[3/6] Creating scheduled task..."
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

# 4. Create desktop shortcut (points to Launcher.ps1)
Write-Host "[4/6] Creating desktop shortcut..."
$launcherScript = Join-Path $scriptDir "Launcher.ps1"
$desktopPath = [System.Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "SecurityMonitor.lnk"
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcherScript`""
    $shortcut.WorkingDirectory = $scriptDir
    $shortcut.Description = "SecurityMonitor - Start or open dashboard"
    $shortcut.IconLocation = "shell32.dll,77"
    $shortcut.Save()
    Write-Host "  -> Desktop shortcut created: $shortcutPath" -ForegroundColor Green
} catch {
    Write-Host "  -> Could not create desktop shortcut: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 5. Start immediately
Write-Host "[5/6] Starting monitoring now..."
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$state = (Get-ScheduledTask -TaskName $taskName).State
if ($state -eq "Running") {
    Write-Host "  -> Monitoring is running in the background" -ForegroundColor Green
    # Signal the running instance to open its dashboard
    Start-Sleep -Seconds 2
    $signalFile = Join-Path $env:TEMP "SecurityMonitor_OpenDashboard.signal"
    [System.IO.File]::WriteAllText($signalFile, "open")
    Write-Host "  -> Dashboard opening..." -ForegroundColor Green
} else {
    Write-Host "  -> Status: $state (try starting manually)" -ForegroundColor Yellow
}

# 6. Verification
Write-Host "[6/6] Verifying..."
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
