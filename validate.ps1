$t = $null
$e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('C:\Users\garga\SecurityMonitor\SecurityMonitor.ps1', [ref]$t, [ref]$e)
if ($e.Count -gt 0) {
    foreach ($err in $e) { Write-Host $err.ToString() }
    exit 1
} else {
    Write-Host "SYNTAX OK"
    exit 0
}
