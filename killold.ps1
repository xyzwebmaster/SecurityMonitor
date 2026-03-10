$myPid = $PID
$procs = Get-Process powershell, pwsh -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $myPid }
foreach ($p in $procs) {
    try {
        $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").CommandLine
        if ($cmd -match 'SecurityMonitor') {
            Write-Host "Killing SecurityMonitor PID $($p.Id)"
            Stop-Process -Id $p.Id -Force
        }
    } catch {}
}
Write-Host "Starting SecurityMonitor v7.0..."
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\garga\SecurityMonitor\SecurityMonitor.ps1' -Verb RunAs
Write-Host "Done."
