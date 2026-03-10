#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecurityMonitor Launcher — starts the monitor if not already running,
    or opens the dashboard if it is.
#>

$scriptDir  = $PSScriptRoot
$mainScript = Join-Path $scriptDir "SecurityMonitor.ps1"
$mutexName  = "Global\SecurityMonitor_Running"

# Try to acquire a system-wide named mutex.
# If another instance already holds it, we know the monitor is running.
$createdNew = $false
try {
    $mutex = [System.Threading.Mutex]::new($true, $mutexName, [ref]$createdNew)
} catch {
    # Mutex already exists and we can't open it — treat as running
    $createdNew = $false
}

if ($createdNew) {
    # We got the mutex → no instance is running. Release it (the real
    # instance will create its own) and start SecurityMonitor.
    try { $mutex.ReleaseMutex(); $mutex.Dispose() } catch {}

    Start-Process powershell -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden',
        '-File', "`"$mainScript`""
    ) -Verb RunAs

    Write-Host "[+] SecurityMonitor started." -ForegroundColor Green
} else {
    # Mutex exists → monitor is already running.
    # Send a signal via a temp flag file so the running instance opens its dashboard.
    try { if ($mutex) { $mutex.Dispose() } } catch {}

    $signalFile = Join-Path $env:TEMP "SecurityMonitor_OpenDashboard.signal"
    [System.IO.File]::WriteAllText($signalFile, "open")

    Write-Host "[+] SecurityMonitor is already running — opening dashboard." -ForegroundColor Cyan
}
