<#
.SYNOPSIS
    Whitehat Security Launcher — starts the monitor if not already running,
    or opens the dashboard if it is.
    Does NOT require admin itself; it elevates via -Verb RunAs.
#>

$scriptDir  = $PSScriptRoot
$mainScript = Join-Path $scriptDir "SecurityMonitor.ps1"
$mutexName  = "Global\WHS_Running"

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
    # instance will create its own) and start Whitehat Security as admin.
    try { $mutex.ReleaseMutex(); $mutex.Dispose() } catch {}

    try {
        Start-Process powershell -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-WindowStyle', 'Hidden',
            '-File', "`"$mainScript`""
        ) -Verb RunAs
    } catch {
        # User cancelled UAC or other error
        exit
    }
} else {
    # Mutex exists → monitor is already running.
    # Send a signal via a temp flag file so the running instance opens its dashboard.
    try { if ($mutex) { $mutex.Dispose() } } catch {}

    $signalFile = Join-Path $env:TEMP "WHS_OpenDashboard.signal"
    [System.IO.File]::WriteAllText($signalFile, "open")
}
