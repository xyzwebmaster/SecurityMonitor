#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hardware and System Security Monitoring Tool
.DESCRIPTION
    Continuously monitors network connections, processes, firmware hash integrity,
    driver changes, and security events. Produces timestamped evidence logs.
    On first run, shows a GUI to let the user choose which alert types to receive.
.AUTHOR
    SecurityMonitor - Forensic Monitoring
.VERSION
    7.0.0
#>

param(
    [int]$IntervalSeconds = 10,
    [string]$LogDir = "$PSScriptRoot\Logs",
    [string]$BaselineDir = "$PSScriptRoot\Baselines",
    [switch]$Silent
)

# --- NOTIFICATION PREFERENCES GUI ---
$ConfigFile = Join-Path $PSScriptRoot "notification_config.json"
$script:ConfigFilePath = $ConfigFile

function Show-ConfigGUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "SecurityMonitor - Notification Settings"
    $form.Size = New-Object System.Drawing.Size(520, 580)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.ForeColor = [System.Drawing.Color]::White
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    # Title label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Choose which changes you want to be notified about:"
    $titleLabel.Location = New-Object System.Drawing.Point(20, 15)
    $titleLabel.Size = New-Object System.Drawing.Size(470, 30)
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 255)
    $form.Controls.Add($titleLabel)

    $subtitleLabel = New-Object System.Windows.Forms.Label
    $subtitleLabel.Text = "You will receive a Windows desktop notification for each selected category."
    $subtitleLabel.Location = New-Object System.Drawing.Point(20, 45)
    $subtitleLabel.Size = New-Object System.Drawing.Size(470, 25)
    $subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $subtitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
    $form.Controls.Add($subtitleLabel)

    # Checkbox definitions: key, label, description
    $options = @(
        @{ Key = "Firmware";    Label = "Firmware Integrity Changes";        Desc = "Driver/firmware file hash modifications, deletions, new files (.sys, .efi, .rom, .bin)" },
        @{ Key = "Driver";      Label = "Driver Changes";                    Desc = "New drivers loaded or existing drivers removed from the system" },
        @{ Key = "Service";     Label = "New Services";                      Desc = "Newly installed or registered Windows services" },
        @{ Key = "Connection";  Label = "Unknown Network Connections";       Desc = "Outbound connections from unrecognized/unwhitelisted processes" },
        @{ Key = "Process";     Label = "Unsigned Processes";                Desc = "New processes running without a valid digital signature" },
        @{ Key = "Listener";    Label = "New Listening Ports";               Desc = "New ports opened for incoming connections by non-system processes" },
        @{ Key = "Registry";    Label = "Registry Startup Key Changes";      Desc = "Modifications to Run/RunOnce registry keys used for persistence" },
        @{ Key = "Security";    Label = "Security Events";                   Desc = "Remote logons, failed login attempts, new user accounts, new services in Event Log" },
        @{ Key = "RDP";         Label = "Remote Desktop (RDP) Status";       Desc = "Alert when Remote Desktop is enabled on this machine" },
        @{ Key = "Hosts";       Label = "Hosts File Modifications";          Desc = "Changes to the hosts file that could redirect DNS queries" }
    )

    $checkboxes = @{}
    $yPos = 80
    foreach ($opt in $options) {
        $cb = New-Object System.Windows.Forms.CheckBox
        $cb.Text = $opt.Label
        $cb.Location = New-Object System.Drawing.Point(25, $yPos)
        $cb.Size = New-Object System.Drawing.Size(450, 22)
        $cb.Checked = $true
        $cb.ForeColor = [System.Drawing.Color]::White
        $cb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $form.Controls.Add($cb)
        $checkboxes[$opt.Key] = $cb

        $descLabel = New-Object System.Windows.Forms.Label
        $descLabel.Text = $opt.Desc
        $descLabel.Location = New-Object System.Drawing.Point(45, ($yPos + 22))
        $descLabel.Size = New-Object System.Drawing.Size(440, 18)
        $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $descLabel.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
        $form.Controls.Add($descLabel)

        $yPos += 44
    }

    # -- Threat details toggle --
    $yPos += 10
    $sepLine = New-Object System.Windows.Forms.Panel
    $sepLine.Location = New-Object System.Drawing.Point(20, $yPos)
    $sepLine.Size = New-Object System.Drawing.Size(450, 1)
    $sepLine.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $form.Controls.Add($sepLine)
    $yPos += 10

    $threatCbInit = New-Object System.Windows.Forms.CheckBox
    $threatCbInit.Text = "Detailed Threat Info and Severity Levels"
    $threatCbInit.Location = New-Object System.Drawing.Point(25, $yPos)
    $threatCbInit.Size = New-Object System.Drawing.Size(450, 22)
    $threatCbInit.Checked = $false
    $threatCbInit.ForeColor = [System.Drawing.Color]::White
    $threatCbInit.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($threatCbInit)

    $threatDescInit = New-Object System.Windows.Forms.Label
    $threatDescInit.Text = "When enabled, shows color-coded severity levels and threat/recommendation details."
    $threatDescInit.Location = New-Object System.Drawing.Point(45, ($yPos + 22))
    $threatDescInit.Size = New-Object System.Drawing.Size(440, 18)
    $threatDescInit.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $threatDescInit.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
    $form.Controls.Add($threatDescInit)
    $yPos += 44

    # Select All / Deselect All buttons
    $selectAllBtn = New-Object System.Windows.Forms.Button
    $selectAllBtn.Text = "Select All"
    $selectAllBtn.Location = New-Object System.Drawing.Point(20, ($yPos + 10))
    $selectAllBtn.Size = New-Object System.Drawing.Size(110, 32)
    $selectAllBtn.FlatStyle = "Flat"
    $selectAllBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $selectAllBtn.ForeColor = [System.Drawing.Color]::White
    $selectAllBtn.Add_Click({ foreach ($cb in $checkboxes.Values) { $cb.Checked = $true } })
    $form.Controls.Add($selectAllBtn)

    $deselectAllBtn = New-Object System.Windows.Forms.Button
    $deselectAllBtn.Text = "Deselect All"
    $deselectAllBtn.Location = New-Object System.Drawing.Point(140, ($yPos + 10))
    $deselectAllBtn.Size = New-Object System.Drawing.Size(110, 32)
    $deselectAllBtn.FlatStyle = "Flat"
    $deselectAllBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $deselectAllBtn.ForeColor = [System.Drawing.Color]::White
    $deselectAllBtn.Add_Click({ foreach ($cb in $checkboxes.Values) { $cb.Checked = $false } })
    $form.Controls.Add($deselectAllBtn)

    # Save button
    $saveBtn = New-Object System.Windows.Forms.Button
    $saveBtn.Text = "Save and Start Monitoring"
    $saveBtn.Location = New-Object System.Drawing.Point(280, ($yPos + 10))
    $saveBtn.Size = New-Object System.Drawing.Size(200, 32)
    $saveBtn.FlatStyle = "Flat"
    $saveBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 200)
    $saveBtn.ForeColor = [System.Drawing.Color]::White
    $saveBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $saveBtn.Add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Close() })
    $form.Controls.Add($saveBtn)
    $form.AcceptButton = $saveBtn

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $config = @{}
        foreach ($key in $checkboxes.Keys) {
            $config[$key] = $checkboxes[$key].Checked
        }
        $config["ShowThreatDetails"] = $threatCbInit.Checked
        return $config
    } else {
        # User closed the window - enable everything by default
        $config = @{}
        foreach ($opt in $options) { $config[$opt.Key] = $true }
        $config["ShowThreatDetails"] = $false
        return $config
    }
}

# Load or create notification config
if (Test-Path $ConfigFile) {
    $script:NotifyConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    Write-Host "[+] Notification preferences loaded from config" -ForegroundColor Green
} else {
    Write-Host "[*] First run detected - opening notification settings..." -ForegroundColor Cyan
    $guiResult = Show-ConfigGUI
    $guiResult | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
    $script:NotifyConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    Write-Host "[+] Notification preferences saved" -ForegroundColor Green
}

# Helper to check if a category is enabled
function Test-NotifyEnabled {
    param([string]$Category)
    $val = $script:NotifyConfig.PSObject.Properties[$Category]
    if ($null -eq $val) { return $true }
    return $val.Value -eq $true
}

# --- AUTO-START REGISTRATION ---
$taskName = "SecurityMonitor"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask) {
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        if ($scriptPath) {
            $action = New-ScheduledTaskAction `
                -Execute "powershell.exe" `
                -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -Silent"
            $trigger = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit (New-TimeSpan -Days 365)
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings `
                -Description "System security monitoring - auto start on boot" | Out-Null
            Write-Host "[+] Auto-start registered: will run on every Windows logon" -ForegroundColor Green
        }
    } catch {
        Write-Host "[~] Could not register auto-start task: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] Auto-start already registered" -ForegroundColor Green
}

# --- DESKTOP SHORTCUT (points to Launcher.ps1 - smart start/open) ---
$desktopPath = [System.Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "SecurityMonitor.lnk"
$launcherPath = Join-Path $PSScriptRoot "Launcher.ps1"
# Always recreate shortcut to ensure it points to Launcher.ps1
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcherPath`""
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.Description = "SecurityMonitor - Start or open dashboard"
    $shortcut.IconLocation = "shell32.dll,77"
    $shortcut.Save()
    Write-Host "[+] Desktop shortcut created/updated: $shortcutPath" -ForegroundColor Green
} catch {
    Write-Host "[~] Could not create desktop shortcut: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- CONFIGURATION ---
$ErrorActionPreference = "SilentlyContinue"
$script:StartTime = Get-Date
$script:AlertCount = 0
$script:MonitorAlertQueue = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())

# Background I/O cache - heavy cmdlets run in background runspace, Watch-* read from here
$script:MonitorCache = [hashtable]::Synchronized(@{
    Connections = $null     # Get-NetTCPConnection results
    Processes = $null       # Get-Process results
    Listeners = $null       # Get-NetTCPConnection -State Listen
    RegistryTamper = $null  # Pre-read registry values for tampering checks
    RegistryKeys = $null    # Get-ItemProperty for critical keys
    HostsHash = $null       # hosts file hash
    Ready = $false
    Cycle = 0
})

# Color-coded output functions
function Write-Status  { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan;    Write-Console $Msg "INFO" }
function Write-Ok      { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green;   Write-Console $Msg "OK" }
function Write-Alert   { param($Msg) Write-Host "[!] ALERT: $Msg" -ForegroundColor Red; Write-Console "ALERT: $Msg" "ERROR" }
function Write-Warn    { param($Msg) Write-Host "[~] $Msg" -ForegroundColor Yellow;  Write-Console $Msg "WARN" }

# --- Console output helper (writes to GUI Console tab) ---
function Write-Console {
    param(
        [string]$Message,
        [string]$Level = "INFO"   # INFO, OK, WARN, ERROR, DEBUG
    )
    $ts = Get-Date -Format "HH:mm:ss.fff"
    $prefix = switch ($Level) {
        "OK"    { "[+]" }
        "WARN"  { "[~]" }
        "ERROR" { "[!]" }
        "DEBUG" { "[D]" }
        default { "[*]" }
    }
    $line = "[$ts] $prefix $Message"
    try {
        if ($script:ConsoleBox) {
            $box = $script:ConsoleBox
            $color = switch ($Level) {
                "OK"    { [System.Drawing.Color]::FromArgb(0, 200, 100) }
                "WARN"  { [System.Drawing.Color]::FromArgb(255, 200, 60) }
                "ERROR" { [System.Drawing.Color]::FromArgb(255, 80, 80) }
                "DEBUG" { [System.Drawing.Color]::FromArgb(120, 120, 150) }
                default { [System.Drawing.Color]::FromArgb(200, 200, 220) }
            }
            $box.SelectionStart = $box.TextLength
            $box.SelectionLength = 0
            $box.SelectionColor = $color
            $box.AppendText("$line`r`n")
            $box.ScrollToCaret()
        }
    } catch {}
    $hostColor = switch ($Level) { "OK" { "Green" } "WARN" { "Yellow" } "ERROR" { "Red" } "DEBUG" { "DarkGray" } default { "Cyan" } }
    Write-Host $line -ForegroundColor $hostColor
}

# --- CREATE DIRECTORIES ---
foreach ($dir in @($LogDir, $BaselineDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

$LogFile         = Join-Path $LogDir "monitor_$(Get-Date -Format 'yyyy-MM-dd').log"
$AlertFile       = Join-Path $LogDir "alerts_$(Get-Date -Format 'yyyy-MM-dd').log"
$ConnectionLog   = Join-Path $LogDir "connections_$(Get-Date -Format 'yyyy-MM-dd').log"
$ProcessLog      = Join-Path $LogDir "processes_$(Get-Date -Format 'yyyy-MM-dd').log"
$FirmwareBaseline = Join-Path $BaselineDir "firmware_hashes.json"
$DriverBaseline   = Join-Path $BaselineDir "driver_baseline.json"
$ServiceBaseline  = Join-Path $BaselineDir "service_baseline.json"

# --- LOG FUNCTIONS ---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Target = $LogFile
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $hostname = $env:COMPUTERNAME
    $entry = "[$ts] [$hostname] [$Level] $Message"
    Add-Content -Path $Target -Value $entry -Encoding UTF8
    if ($Level -eq "ALERT") {
        Add-Content -Path $AlertFile -Value $entry -Encoding UTF8
    }
}

# --- ALERT HISTORY (for GUI detail view) ---
$script:AlertHistory = [System.Collections.ArrayList]@()
$script:DashboardForm = $null

# --- AI THREAT DETECTION DATA ---
$script:AiThreatHistory = [System.Collections.ArrayList]@()
$script:AiThreatCount = 0
$script:AiScanRunning = $false
$script:AiLastScanTime = $null
$script:HollowsHunterPath = Join-Path $PSScriptRoot "Tools\hollows_hunter.exe"
$script:AiToolsDir = Join-Path $PSScriptRoot "Tools"

# ============================================================================
#  AI THREAT DETECTION ENGINE (fully local - no cloud)
#  Uses: HollowsHunter (memory injection scanner) + PowerShell behavioral heuristics
# ============================================================================

function Add-AiThreat {
    param([string]$Engine, [string]$Risk, [string]$ProcessName, [string]$Finding, [hashtable]$Details = @{})
    $threat = @{
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Engine      = $Engine
        Risk        = $Risk
        ProcessName = $ProcessName
        Finding     = $Finding
        Details     = $Details
    }
    [void]$script:AiThreatHistory.Add($threat)
    $script:AiThreatCount++

    # Update ListView if available
    try {
        if ($script:AiThreatListView -and -not $script:AiThreatListView.IsDisposed) {
            $riskColor = switch ($Risk) {
                "CRIT" { [System.Drawing.Color]::FromArgb(255, 80, 90) }
                "HIGH" { [System.Drawing.Color]::FromArgb(255, 170, 80) }
                "MED"  { [System.Drawing.Color]::FromArgb(120, 190, 255) }
                default { [System.Drawing.Color]::FromArgb(140, 140, 160) }
            }
            $item = New-Object System.Windows.Forms.ListViewItem($threat.Timestamp)
            [void]$item.SubItems.Add($Risk)
            [void]$item.SubItems.Add($Engine)
            [void]$item.SubItems.Add($ProcessName)
            [void]$item.SubItems.Add($Finding)
            $item.Tag = $script:AiThreatHistory.Count - 1
            $item.ForeColor = $riskColor
            $script:AiThreatListView.Items.Insert(0, $item)
        }
    } catch {}
}

function Start-AiThreatScan {
    if ($script:AiScanRunning) { return }
    $script:AiScanRunning = $true

    try {
        if ($script:AiScanStatusLabel) { $script:AiScanStatusLabel.Text = "Scanning..." }
        if ($script:AiStatusLabel) { $script:AiStatusLabel.Text = "Scan in progress..." }
        if ($script:AiScanBtn) { $script:AiScanBtn.Enabled = $false }
    } catch {}

    $findings = [System.Collections.ArrayList]@()
    $hhPath = $script:HollowsHunterPath

    # ── ENGINE 1: HollowsHunter (memory injection scanner) ──
    $hhAvailable = Test-Path $hhPath
    if ($hhAvailable) {
        try {
            $outDir = Join-Path $env:TEMP "hh_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $hhPath
            $psi.Arguments = "/json /quiet /dir `"$outDir`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $proc.WaitForExit(120000)
            if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }

            $scanJson = Join-Path $outDir "scan_report.json"
            if (Test-Path $scanJson) {
                $report = Get-Content $scanJson -Raw | ConvertFrom-Json
                if ($report.scanned) {
                    foreach ($s in $report.scanned) {
                        if ($s.is_managed -or $s.replaced -or $s.hdr_mod -or $s.iat_hooked -or $s.implanted -or $s.unreachable_file -or $s.patched) {
                            $suspTypes = @()
                            if ($s.replaced)         { $suspTypes += "Replaced/Hollowed" }
                            if ($s.hdr_mod)          { $suspTypes += "Header Modified" }
                            if ($s.iat_hooked)       { $suspTypes += "IAT Hooked" }
                            if ($s.implanted)        { $suspTypes += "Code Implanted" }
                            if ($s.patched)          { $suspTypes += "Memory Patched" }
                            if ($s.unreachable_file) { $suspTypes += "Unreachable File" }
                            $risk = if ($s.replaced -or $s.implanted) { "CRIT" } elseif ($s.iat_hooked -or $s.hdr_mod) { "HIGH" } else { "MED" }
                            $pName = try { (Get-Process -Id $s.pid -ErrorAction SilentlyContinue).ProcessName } catch { "PID:$($s.pid)" }
                            if (-not $pName) { $pName = "PID:$($s.pid)" }
                            [void]$findings.Add(@{
                                Engine = "HollowsHunter"; Risk = $risk; Process = $pName
                                Finding = "Memory anomaly: $($suspTypes -join ', ')"
                                Details = [ordered]@{
                                    "PID" = "$($s.pid)"; "Process" = $pName
                                    "Detection" = ($suspTypes -join ", ")
                                    "Scanned Modules" = "$($s.scanned)"; "Suspicious Modules" = "$($s.suspicious)"
                                    "Analysis" = "Process memory differs from disk image - possible injection or tampering"
                                }
                            })
                        }
                    }
                }
            }
            try { Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        } catch {}
    }

    # ── ENGINE 2: Behavioral Heuristics (pure PowerShell) ──
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessId -ne 0 -and $_.ProcessId -ne 4 } |
            Select-Object ProcessId, Name, ParentProcessId, CommandLine, ExecutablePath
    } catch { $procs = @() }
    $procMap = @{}
    foreach ($p in $procs) { $procMap[$p.ProcessId] = $p }

    # Build self-exclusion set: own PID + all ancestor/child PIDs belonging to SecurityMonitor
    $selfPids = [System.Collections.Generic.HashSet[int]]::new()
    [void]$selfPids.Add($PID)
    # Add parent chain (Launcher → PowerShell hosting SecurityMonitor)
    $curPid = $PID
    for ($i = 0; $i -lt 5; $i++) {
        $parent = $procMap[$curPid]
        if (-not $parent) { break }
        $ppid = $parent.ParentProcessId
        if ($ppid -le 4) { break }
        [void]$selfPids.Add($ppid)
        $curPid = $ppid
    }
    # Add child processes spawned by us
    foreach ($p in $procs) {
        if ($selfPids.Contains($p.ParentProcessId)) { [void]$selfPids.Add($p.ProcessId) }
    }
    # Second pass for grandchildren
    foreach ($p in $procs) {
        if ($selfPids.Contains($p.ParentProcessId)) { [void]$selfPids.Add($p.ProcessId) }
    }
    # Also whitelist by command line containing our script path
    $selfScriptPath = $PSCommandPath
    if (-not $selfScriptPath) { $selfScriptPath = "SecurityMonitor.ps1" }

    # 2a. Suspicious parent-child relationships
    try {
        $suspParentChild = @(
            @{ Parent = "winword.exe";   Children = @("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe") },
            @{ Parent = "excel.exe";     Children = @("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe") },
            @{ Parent = "outlook.exe";   Children = @("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe") },
            @{ Parent = "svchost.exe";   Children = @("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe") },
            @{ Parent = "explorer.exe";  Children = @("mshta.exe","regsvr32.exe","rundll32.exe") }
        )
        foreach ($p in $procs) {
            if ($selfPids.Contains($p.ProcessId)) { continue }
            $parentProc = $procMap[$p.ParentProcessId]
            if (-not $parentProc) { continue }
            foreach ($rule in $suspParentChild) {
                if ($parentProc.Name -eq $rule.Parent -and $p.Name -in $rule.Children) {
                    [void]$findings.Add(@{
                        Engine = "Behavior"; Risk = "HIGH"; Process = $p.Name
                        Finding = "Suspicious process tree: $($parentProc.Name) spawned $($p.Name)"
                        Details = [ordered]@{
                            "Child Process" = "$($p.Name) (PID: $($p.ProcessId))"
                            "Parent Process" = "$($parentProc.Name) (PID: $($parentProc.ProcessId))"
                            "Command Line" = "$($p.CommandLine)"
                            "Analysis" = "Office/system processes should not spawn scripting engines - common in malware droppers"
                        }
                    })
                }
            }
        }
    } catch {}

    # 2b. Suspicious command-line patterns
    try {
        foreach ($p in $procs) {
            if (-not $p.CommandLine) { continue }
            if ($selfPids.Contains($p.ProcessId)) { continue }
            if ($p.CommandLine -match [regex]::Escape($selfScriptPath)) { continue }
            $cmd = $p.CommandLine
            $suspPatterns = @()
            $analysis = ""

            if ($cmd -match '-[Ee]nc\s|encodedcommand|FromBase64String|Convert.*Base64') {
                $suspPatterns += "Base64/Encoded command"
                $analysis = "Encoded commands are commonly used to obfuscate malicious payloads"
            }
            if ($cmd -match 'Invoke-Expression|IEX\s*\(|\.DownloadString\(|\.DownloadFile\(|Net\.WebClient|Invoke-WebRequest.*\|') {
                $suspPatterns += "Download cradle"
                $analysis = "Pattern matches common PowerShell download-and-execute techniques"
            }
            if ($cmd -match 'Add-MpPreference.*ExclusionPath|Set-MpPreference.*DisableRealtimeMonitoring') {
                $suspPatterns += "Defender evasion"
                $analysis = "Attempting to disable or bypass Windows Defender"
            }
            if ($cmd -match '-w\s+hidden|-WindowStyle\s+[Hh]idden' -and $p.Name -match 'powershell|pwsh') {
                if ($cmd -match 'bypass|unrestricted|Net\.|WebClient|Download|Invoke-') {
                    $suspPatterns += "Hidden PowerShell with bypass"
                    $analysis = "Hidden PowerShell with execution policy bypass and network activity"
                }
            }
            if ($cmd -match 'mimikatz|rubeus|sharphound|bloodhound|lazagne|procdump.*lsass|sekurlsa') {
                $suspPatterns += "Known attack tool"
                $analysis = "Command references known offensive security / credential theft tool"
            }

            if ($suspPatterns.Count -gt 0) {
                $truncCmd = if ($cmd.Length -gt 200) { $cmd.Substring(0, 200) + "..." } else { $cmd }
                [void]$findings.Add(@{
                    Engine = "Behavior"
                    Risk = if ($suspPatterns -contains "Known attack tool" -or $suspPatterns -contains "Defender evasion") { "CRIT" } else { "HIGH" }
                    Process = $p.Name
                    Finding = "Suspicious command: $($suspPatterns -join ', ')"
                    Details = [ordered]@{
                        "Process" = "$($p.Name) (PID: $($p.ProcessId))"
                        "Pattern" = ($suspPatterns -join ", ")
                        "Command Line" = $truncCmd
                        "Path" = "$($p.ExecutablePath)"
                        "Analysis" = $analysis
                    }
                })
            }
        }
    } catch {}

    # 2c. Unsigned executables in suspicious locations
    try {
        foreach ($p in $procs) {
            if (-not $p.ExecutablePath) { continue }
            if ($selfPids.Contains($p.ProcessId)) { continue }
            $exePath = $p.ExecutablePath
            if ($exePath -notmatch '\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\|\\ProgramData\\[^\\]+\.exe$|\\Users\\Public\\') { continue }
            try {
                $sig = Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    [void]$findings.Add(@{
                        Engine = "Behavior"; Risk = "MED"; Process = $p.Name
                        Finding = "Unsigned executable in suspicious location"
                        Details = [ordered]@{
                            "Process" = "$($p.Name) (PID: $($p.ProcessId))"
                            "Path" = $exePath; "Signature" = "$($sig.Status)"
                            "Analysis" = "Unsigned executables running from temp/download folders may indicate malware"
                        }
                    })
                }
            } catch {}
        }
    } catch {}

    # 2d. High-entropy executable names (randomized names)
    try {
        foreach ($p in $procs) {
            if (-not $p.Name) { continue }
            if ($selfPids.Contains($p.ProcessId)) { continue }
            $name = [System.IO.Path]::GetFileNameWithoutExtension($p.Name)
            if ($name.Length -lt 6) { continue }
            $consonants = ($name.ToLower().ToCharArray() | Where-Object { $_ -match '[bcdfghjklmnpqrstvwxyz]' }).Count
            $ratio = $consonants / $name.Length
            $hasDigitMix = $name -match '[a-zA-Z].*\d.*[a-zA-Z]|\d.*[a-zA-Z].*\d'
            if (($ratio -gt 0.75 -and $name.Length -gt 7) -or ($hasDigitMix -and $name.Length -gt 10 -and $ratio -gt 0.5)) {
                if ($name -match '^(svchost|csrss|conhost|dllhost|taskhostw?|sihost|RuntimeBroker|SearchHost|SecurityHealth|msedgewebview|WindowsTerminal)') { continue }
                if ($p.ExecutablePath -and $p.ExecutablePath -match '\\(Windows|Program Files|Microsoft)\\') { continue }
                [void]$findings.Add(@{
                    Engine = "Heuristic"; Risk = "MED"; Process = $p.Name
                    Finding = "Process name appears randomized (possible malware)"
                    Details = [ordered]@{
                        "Process" = "$($p.Name) (PID: $($p.ProcessId))"
                        "Path" = "$($p.ExecutablePath)"
                        "Name Entropy" = "Consonant ratio: $([math]::Round($ratio, 2)), Length: $($name.Length)"
                        "Analysis" = "Malware often uses random-looking process names to avoid detection"
                    }
                })
            }
        }
    } catch {}

    # 2e. Processes with no executable on disk (fileless/deleted)
    try {
        foreach ($p in $procs) {
            if (-not $p.ExecutablePath) { continue }
            if ($selfPids.Contains($p.ProcessId)) { continue }
            if (-not (Test-Path $p.ExecutablePath)) {
                [void]$findings.Add(@{
                    Engine = "Heuristic"; Risk = "HIGH"; Process = $p.Name
                    Finding = "Running process has no file on disk (fileless/deleted)"
                    Details = [ordered]@{
                        "Process" = "$($p.Name) (PID: $($p.ProcessId))"
                        "Expected Path" = "$($p.ExecutablePath)"
                        "Analysis" = "Executable was deleted after launch or running from memory only - strong indicator of malware"
                    }
                })
            }
        }
    } catch {}

    # 2f. Masquerading detection (system process names from wrong locations)
    try {
        $sysProcs = @{
            "svchost.exe"  = "C:\Windows\System32\svchost.exe"
            "csrss.exe"    = "C:\Windows\System32\csrss.exe"
            "lsass.exe"    = "C:\Windows\System32\lsass.exe"
            "services.exe" = "C:\Windows\System32\services.exe"
            "smss.exe"     = "C:\Windows\System32\smss.exe"
            "wininit.exe"  = "C:\Windows\System32\wininit.exe"
            "winlogon.exe" = "C:\Windows\System32\winlogon.exe"
            "explorer.exe" = "C:\Windows\explorer.exe"
        }
        foreach ($p in $procs) {
            if ($selfPids.Contains($p.ProcessId)) { continue }
            if ($sysProcs.ContainsKey($p.Name.ToLower()) -and $p.ExecutablePath) {
                $expected = $sysProcs[$p.Name.ToLower()]
                if ($p.ExecutablePath -ne $expected -and $p.ExecutablePath -ne $expected.Replace("System32","SysWOW64")) {
                    [void]$findings.Add(@{
                        Engine = "Heuristic"; Risk = "CRIT"; Process = $p.Name
                        Finding = "Process masquerading: $($p.Name) running from wrong location"
                        Details = [ordered]@{
                            "Process" = "$($p.Name) (PID: $($p.ProcessId))"
                            "Actual Path" = "$($p.ExecutablePath)"
                            "Expected Path" = $expected
                            "Analysis" = "System process running from non-standard location is a strong indicator of malware masquerading"
                        }
                    })
                }
            }
        }
    } catch {}

    # ── Add findings to UI ──
    foreach ($f in $findings) {
        Add-AiThreat -Engine $f.Engine -Risk $f.Risk -ProcessName $f.Process -Finding $f.Finding -Details $f.Details
    }

    $script:AiLastScanTime = Get-Date
    $statusText = "Last scan: $(Get-Date -Format 'HH:mm:ss') | Engines: Behavioral Analysis"
    if ($hhAvailable) { $statusText += " + HollowsHunter" }
    $statusText += " | Findings: $($findings.Count)"

    try { if ($script:AiScanStatusLabel) { $script:AiScanStatusLabel.Text = $statusText } } catch {}
    try { if ($script:AiStatusLabel) { $script:AiStatusLabel.Text = $statusText } } catch {}

    if ($script:AiThreatCount -eq 0) {
        try { if ($script:AiCountLabel) { $script:AiCountLabel.Text = "No threats detected"; $script:AiCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 100) } } catch {}
    } else {
        try { if ($script:AiCountLabel) { $script:AiCountLabel.Text = "$($script:AiThreatCount) threat(s) detected"; $script:AiCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 90) } } catch {}
    }

    if (-not $hhAvailable) {
        try { if ($script:AiScanStatusLabel) { $script:AiScanStatusLabel.Text += "  [HollowsHunter not found - place hollows_hunter.exe in Tools\ for memory scanning]" } } catch {}
    }

    $script:AiScanRunning = $false
    try { if ($script:AiScanBtn) { $script:AiScanBtn.Enabled = $true } } catch {}
}

# ============================================================================
#  UNIFIED DASHBOARD GUI - All features in one modern tabbed window
# ============================================================================
function Show-Dashboard {
    param([string]$OpenTab = "Status")

    # If dashboard already open, bring to front, restart timers, and switch tab
    try {
        if ($script:DashboardForm -and -not $script:DashboardForm.IsDisposed) {
            $script:DashboardForm.Show()
            $script:DashboardForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            $script:DashboardForm.BringToFront()
            $script:DashboardForm.Activate()
            # Resume timers that were paused on hide
            try { if ($script:DashTimer)     { $script:DashTimer.Start() } } catch {}
            try { if ($script:PulseTimer)    { $script:PulseTimer.Start() } } catch {}
            if ($OpenTab -and $script:SwitchPageFn) {
                try { & $script:SwitchPageFn $OpenTab } catch {}
            }
            return
        }
    } catch {
        $script:DashboardForm = $null
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # --- Domain blocklists (used by PF_BlockTrackers/Malware/Telemetry) ---
    if (-not $script:TrackerDomains) {
        $script:TrackerDomains = @(
            'www.google-analytics.com','ssl.google-analytics.com','analytics.google.com',
            'www.googletagmanager.com','www.googletagservices.com','tagmanager.google.com',
            'www.googleadservices.com','pagead2.googlesyndication.com','adservice.google.com',
            'www.facebook.com/tr','pixel.facebook.com','connect.facebook.net',
            'analytics.twitter.com','t.co','static.ads-twitter.com',
            'bat.bing.com','a.clarity.ms','c.clarity.ms','c.bing.com',
            'sb.scorecardresearch.com','b.scorecardresearch.com',
            'cdn.mxpnl.com','api.mixpanel.com',
            'cdn.segment.com','api.segment.io',
            'js.hs-analytics.net','t.hubspotemail.net',
            'stats.wp.com','pixel.wp.com',
            'mc.yandex.ru','mc.yandex.com',
            'cdn.heapanalytics.com','heapanalytics.com',
            'static.hotjar.com','script.hotjar.com',
            'matomo.org','piwik.org',
            'plausible.io','app.posthog.com',
            'doubleclick.net','ad.doubleclick.net','securepubads.g.doubleclick.net'
        )
    }
    if (-not $script:MalwareDomains) {
        $script:MalwareDomains = @(
            'malware.wicar.org','malware-traffic-analysis.net',
            'xss.is','testphp.vulnweb.com',
            'amtso.org','www.amtso.org',
            'cpsc.gov','www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com',
            'sskzmv.net','zfrfrw.net','xlowfznrg.com','mmfreedeath.com',
            'sfrfrw.net','zxfrfrw.net','wifrfrw.net','rkfrfrw.net',
            'killmalware.com','zefrfrw.net','malwaredomainlist.com'
        )
    }
    if (-not $script:TelemetryDomains) {
        $script:TelemetryDomains = @(
            'vortex.data.microsoft.com','vortex-win.data.microsoft.com',
            'settings-win.data.microsoft.com','watson.telemetry.microsoft.com',
            'watson.microsoft.com','umwatsonc.events.data.microsoft.com',
            'ceuswatcab01.blob.core.windows.net','ceuswatcab02.blob.core.windows.net',
            'eaus2watcab01.blob.core.windows.net','eaus2watcab02.blob.core.windows.net',
            'weus2watcab01.blob.core.windows.net','weus2watcab02.blob.core.windows.net',
            'telemetry.microsoft.com','dc.services.visualstudio.com',
            'az667904.vo.msecnd.net','telemetry.appex.bing.net',
            'cs1.wpc.v0cdn.net','a-0001.a-msedge.net',
            'statsfe2-df.ws.microsoft.com','mtalk.google.com',
            'bingapis.com','api.cortana.ai',
            'asimov-win.settings.data.microsoft.com.akadns.net',
            'client.wns.windows.com','wdcp.microsoft.com',
            'activity.windows.com','edge.activity.windows.com',
            'nav.smartscreen.microsoft.com','ris.api.iris.microsoft.com',
            'a.config.skype.com','b.config.skype.com','config.edge.skype.com'
        )
    }

    # --- Color palette ---
    $colBg        = [System.Drawing.Color]::FromArgb(18, 18, 28)
    $colSidebar   = [System.Drawing.Color]::FromArgb(24, 24, 38)
    $colCard      = [System.Drawing.Color]::FromArgb(30, 30, 48)
    $colAccent    = [System.Drawing.Color]::FromArgb(0, 150, 255)
    $colAccentDim = [System.Drawing.Color]::FromArgb(0, 90, 160)
    $colRed       = [System.Drawing.Color]::FromArgb(220, 50, 60)
    $colGreen     = [System.Drawing.Color]::FromArgb(0, 200, 100)
    $colOrange    = [System.Drawing.Color]::FromArgb(255, 160, 40)
    $colTextMain  = [System.Drawing.Color]::White
    $colTextDim   = [System.Drawing.Color]::FromArgb(140, 140, 160)
    $colBtnHover  = [System.Drawing.Color]::FromArgb(40, 40, 65)

    # --- Main form ---
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "SecurityMonitor Dashboard"
    $form.Size = New-Object System.Drawing.Size(1050, 680)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = $colBg
    $form.ForeColor = $colTextMain
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.MinimumSize = New-Object System.Drawing.Size(1050, 680)
    $form.FormBorderStyle = "Sizable"
    $form.TopMost = $false
    # Enable double-buffering to reduce flicker
    $form.GetType().GetProperty("DoubleBuffered", [System.Reflection.BindingFlags]"Instance,NonPublic").SetValue($form, $true, $null)

    # Minimize to tray instead of closing - pause timers to save resources
    $form.Add_FormClosing({
        param($s, $e)
        $e.Cancel = $true
        $s.Hide()
        try { if ($script:DashTimer)     { $script:DashTimer.Stop() } } catch {}
        try { if ($script:PulseTimer)    { $script:PulseTimer.Stop() } } catch {}
    })

    $script:DashboardForm = $form

    # ── Sidebar (left navigation) - no Dock, manual position ──
    $sidebar = New-Object System.Windows.Forms.Panel
    $sidebar.Location = New-Object System.Drawing.Point(0, 0)
    $sidebar.Size = New-Object System.Drawing.Size(200, $form.ClientSize.Height)
    $sidebar.BackColor = $colSidebar
    $sidebar.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $form.Controls.Add($sidebar)

    # Logo / title area
    $logoLabel = New-Object System.Windows.Forms.Label
    $logoLabel.Text = "SECURITY`nMONITOR"
    $logoLabel.Location = New-Object System.Drawing.Point(0, 15)
    $logoLabel.Size = New-Object System.Drawing.Size(200, 50)
    $logoLabel.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $logoLabel.ForeColor = $colAccent
    $logoLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $sidebar.Controls.Add($logoLabel)

    $verLabel = New-Object System.Windows.Forms.Label
    $verLabel.Text = "v7.0 Dashboard"
    $verLabel.Location = New-Object System.Drawing.Point(0, 65)
    $verLabel.Size = New-Object System.Drawing.Size(200, 18)
    $verLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $verLabel.ForeColor = $colTextDim
    $verLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $sidebar.Controls.Add($verLabel)

    # Separator line
    $sidebarSep = New-Object System.Windows.Forms.Label
    $sidebarSep.Location = New-Object System.Drawing.Point(15, 90)
    $sidebarSep.Size = New-Object System.Drawing.Size(170, 1)
    $sidebarSep.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $sidebar.Controls.Add($sidebarSep)

    # ── Sidebar collapse/expand toggle (button created now, click handler added after navButtons) ──
    $script:SidebarExpanded = $true
    $script:SidebarPanel = $sidebar
    $script:LogoLabel = $logoLabel
    $script:VerLabel = $verLabel
    $script:SidebarSep = $sidebarSep
    $collapseBtn = New-Object System.Windows.Forms.Button
    $collapseBtn.Text = "<<"
    $collapseBtn.Location = New-Object System.Drawing.Point(0, ($form.ClientSize.Height - 32))
    $collapseBtn.Size = New-Object System.Drawing.Size(200, 32)
    $collapseBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $collapseBtn.FlatStyle = "Flat"
    $collapseBtn.FlatAppearance.BorderSize = 0
    $collapseBtn.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 55)
    $collapseBtn.ForeColor = $colTextDim
    $collapseBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $collapseBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $sidebar.Controls.Add($collapseBtn)

    # ── Content area (right side) - positioned to sidebar's right, resizes with form ──
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.BackColor = $colBg
    $contentPanel.Location = New-Object System.Drawing.Point($sidebar.Width, 0)
    $contentPanel.Size = New-Object System.Drawing.Size(($form.ClientSize.Width - $sidebar.Width), $form.ClientSize.Height)
    $contentPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $form.Controls.Add($contentPanel)

    # Store contentPanel in script scope for collapse/expand repositioning
    $script:ContentPanel = $contentPanel

    # Create page panels (each tab is a Panel - manual size/anchor, NOT Dock=Fill)
    $script:Pages = @{}
    $pages = $script:Pages
    $contentW = $contentPanel.Width
    $contentH = $contentPanel.Height
    foreach ($pageName in @("Status", "Alerts", "AI Threats", "Settings", "Logs", "Console")) {
        $p = New-Object System.Windows.Forms.Panel
        $p.Location = New-Object System.Drawing.Point(0, 0)
        $p.Size = New-Object System.Drawing.Size($contentW, $contentH)
        $p.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $p.BackColor = $colBg
        $p.Visible = $false
        $p.AutoScroll = $true
        $contentPanel.Controls.Add($p)
        $pages[$pageName] = $p
    }

    # Sidebar nav buttons
    $navButtons = @()
    $navItems = @(
        @{ Name = "Status";     Icon = "[S]"; Text = "  Status" },
        @{ Name = "Alerts";     Icon = "[A]"; Text = "  Alerts" },
        @{ Name = "AI Threats"; Icon = "[AI]"; Text = " AI Threats" },
        @{ Name = "Settings";   Icon = "[C]"; Text = "  Settings" },
        @{ Name = "Logs";       Icon = "[L]"; Text = "  Logs" },
        @{ Name = "Console";   Icon = "[>]"; Text = "  Console" }
    )
    $navY = 105
    foreach ($nav in $navItems) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = "$($nav.Icon) $($nav.Text)"
        $btn.Location = New-Object System.Drawing.Point(8, $navY)
        $btn.Size = New-Object System.Drawing.Size(184, 40)
        $btn.FlatStyle = "Flat"
        $btn.FlatAppearance.BorderSize = 0
        $btn.FlatAppearance.MouseOverBackColor = $colBtnHover
        $btn.BackColor = $colSidebar
        $btn.ForeColor = $colTextDim
        $btn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $btn.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btn.Tag = $nav.Name
        $sidebar.Controls.Add($btn)
        $navButtons += $btn
        $navY += 44
    }
    $script:NavButtons = $navButtons

    # ── Sidebar collapse click handler (now navButtons is populated) ──
    $collapseBtn.Add_Click({
        try {
            $formW = $script:DashboardForm.ClientSize.Width
            $formH = $script:DashboardForm.ClientSize.Height
            if ($script:SidebarExpanded) {
                $script:SidebarPanel.Width = 50
                $script:LogoLabel.Visible = $false
                $script:VerLabel.Visible = $false
                $script:SidebarSep.Visible = $false
                foreach ($nb in $script:NavButtons) {
                    $nb.Size = New-Object System.Drawing.Size(34, 34)
                    $nb.Location = New-Object System.Drawing.Point(8, $nb.Location.Y)
                    $nb.Text = $nb.Tag.Substring(0,1)
                    $nb.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
                }
                $this.Text = ">>"
                $script:SidebarExpanded = $false
                # Reposition content panel
                $script:ContentPanel.Location = New-Object System.Drawing.Point(50, 0)
                $script:ContentPanel.Size = New-Object System.Drawing.Size(($formW - 50), $formH)
            } else {
                $script:SidebarPanel.Width = 200
                $script:LogoLabel.Visible = $true
                $script:VerLabel.Visible = $true
                $script:SidebarSep.Visible = $true
                $navIdx = 0
                $navTexts = @("[S]   Status", "[A]   Alerts", "[C]   Settings", "[L]   Logs")
                foreach ($nb in $script:NavButtons) {
                    $nb.Size = New-Object System.Drawing.Size(184, 40)
                    $nb.Location = New-Object System.Drawing.Point(8, $nb.Location.Y)
                    $nb.Text = $navTexts[$navIdx]
                    $nb.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
                    $navIdx++
                }
                $this.Text = "<<"
                $script:SidebarExpanded = $true
                # Reposition content panel
                $script:ContentPanel.Location = New-Object System.Drawing.Point(200, 0)
                $script:ContentPanel.Size = New-Object System.Drawing.Size(($formW - 200), $formH)
            }
        } catch {}
    })

    # Navigation switching scriptblock (stored in script scope so closures can reach it)
    $script:CurrentPage = "Status"
    $script:SwitchPageFn = {
        param([string]$targetName)
        $script:CurrentPage = $targetName
        foreach ($pKey in $script:Pages.Keys) {
            if ($pKey -eq $targetName) {
                $script:Pages[$pKey].Visible = $true
                $script:Pages[$pKey].BringToFront()
            } else {
                $script:Pages[$pKey].Visible = $false
            }
        }
        foreach ($nb in $script:NavButtons) {
            if ($nb.Tag -eq $targetName) {
                $nb.BackColor = [System.Drawing.Color]::FromArgb(0, 90, 160)
                $nb.ForeColor = [System.Drawing.Color]::White
                $nb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            } else {
                $nb.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 38)
                $nb.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 160)
                $nb.Font = New-Object System.Drawing.Font("Segoe UI", 10)
            }
        }
    }

    # Bind each nav button - use direct event handler with sender's Tag
    foreach ($b in $navButtons) {
        $b.Add_Click({
            try { & $script:SwitchPageFn $this.Tag } catch {}
        })
    }

    # Reposition visible nav buttons (collapses gaps when a button is hidden)
    $script:RepositionNavButtons = {
        $y = 105
        foreach ($nb in $script:NavButtons) {
            if ($nb.Visible) {
                $nb.Location = New-Object System.Drawing.Point(8, $y)
                $y += 44
            }
        }
    }

    # AI Threats tab always visible (scan is on-demand from the tab itself)
    $script:AiFeatureEnabled = $true
    & $script:RepositionNavButtons

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 1: STATUS (live overview)
    # ═══════════════════════════════════════════════════════════════
    $statusPage = $pages["Status"]

    $statusTitle = New-Object System.Windows.Forms.Label
    $statusTitle.Text = "Live Monitoring Status"
    $statusTitle.Location = New-Object System.Drawing.Point(25, 18)
    $statusTitle.Size = New-Object System.Drawing.Size(500, 32)
    $statusTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $statusTitle.ForeColor = $colAccent
    $statusPage.Controls.Add($statusTitle)

    # Pulsing status indicator
    $script:StatusBright = $true
    $statusDot = New-Object System.Windows.Forms.Panel
    $statusDot.Location = New-Object System.Drawing.Point(540, 24)
    $statusDot.Size = New-Object System.Drawing.Size(12, 12)
    $statusDot.BackColor = $colGreen
    $statusDot.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $statusPage.Controls.Add($statusDot)
    $script:StatusDotPanel = $statusDot

    $statusText = New-Object System.Windows.Forms.Label
    $statusText.Text = "MONITORING ACTIVE"
    $statusText.Location = New-Object System.Drawing.Point(558, 20)
    $statusText.Size = New-Object System.Drawing.Size(230, 24)
    $statusText.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $statusText.ForeColor = $colGreen
    $statusText.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $statusText.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $statusPage.Controls.Add($statusText)

    # Pulse timer for the dot
    $script:PulseTimer = New-Object System.Windows.Forms.Timer
    $script:PulseTimer.Interval = 800
    $script:PulseTimer.Add_Tick({
        try {
            if ($script:StatusBright) {
                $script:StatusDotPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 100, 50)
            } else {
                $script:StatusDotPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 200, 100)
            }
            $script:StatusBright = -not $script:StatusBright
        } catch {}
    })
    $script:PulseTimer.Start()

    # Stat cards with accent bar and icon
    function New-StatCard {
        param($parent, $x, $y, $label, $valueVar, $accentColor, $icon, [scriptblock]$onClick = $null)
        $card = New-Object System.Windows.Forms.Panel
        $card.Location = New-Object System.Drawing.Point($x, $y)
        $card.Size = New-Object System.Drawing.Size(185, 90)
        $card.BackColor = $colCard
        $card.Cursor = [System.Windows.Forms.Cursors]::Hand
        $card.Tag = "card"
        $parent.Controls.Add($card)

        # Left accent bar
        $accent = New-Object System.Windows.Forms.Panel
        $accent.Location = New-Object System.Drawing.Point(0, 0)
        $accent.Size = New-Object System.Drawing.Size(3, 90)
        $accent.BackColor = $accentColor
        $card.Controls.Add($accent)

        # Icon
        $iconLbl = New-Object System.Windows.Forms.Label
        $iconLbl.Text = $icon
        $iconLbl.Location = New-Object System.Drawing.Point(10, 28)
        $iconLbl.Size = New-Object System.Drawing.Size(36, 36)
        $iconLbl.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 18)
        $iconLbl.ForeColor = $accentColor
        $card.Controls.Add($iconLbl)

        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $label.ToUpper()
        $lbl.Location = New-Object System.Drawing.Point(48, 8)
        $lbl.Size = New-Object System.Drawing.Size(130, 18)
        $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 7.5, [System.Drawing.FontStyle]::Bold)
        $lbl.ForeColor = $colTextDim
        $card.Controls.Add($lbl)

        $val = New-Object System.Windows.Forms.Label
        $val.Text = "0"
        $val.Name = $valueVar
        $val.Location = New-Object System.Drawing.Point(48, 28)
        $val.Size = New-Object System.Drawing.Size(130, 50)
        $val.Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold)
        $val.ForeColor = $colTextMain
        $card.Controls.Add($val)

        # Hover effect
        $hoverEnter = { $this.BackColor = [System.Drawing.Color]::FromArgb(42, 42, 62) }
        $hoverLeave = { $this.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 48) }
        $card.Add_MouseEnter($hoverEnter)
        $card.Add_MouseLeave($hoverLeave)
        foreach ($c in $card.Controls) { $c.Add_MouseEnter({ $this.Parent.BackColor = [System.Drawing.Color]::FromArgb(42, 42, 62) }); $c.Add_MouseLeave({ $this.Parent.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 48) }) }

        # Click handler - propagate to all children
        if ($onClick) {
            $card.Add_Click($onClick)
            foreach ($c in $card.Controls) { $c.Add_Click($onClick) }
        }

        return $val
    }

    $script:LblAlerts      = New-StatCard $statusPage 25  65  "Total Alerts"       "valAlerts"   $colRed    "$([char]0x26A0)" -onClick { try { & $script:SwitchPageFn "Alerts" } catch {} }
    $script:LblConnections = New-StatCard $statusPage 220 65  "Connections"        "valConns"    $colAccent "$([char]0x21C4)" -onClick {
        try {
            $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.|::1|::$)' } |
                Select-Object -First 30 |
                ForEach-Object {
                    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                    "$($proc):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
                }
            $text = if ($conns) { $conns -join "`n" } else { "No active external connections." }
            [System.Windows.Forms.MessageBox]::Show($text, "Active Connections ($($conns.Count))", "OK", "Information")
        } catch {}
    }
    $script:LblProcesses   = New-StatCard $statusPage 415 65  "Processes"          "valProcs"    $colGreen  "$([char]0x2699)" -onClick {
        try {
            $procs = $script:KnownProcesses.Keys | Sort-Object | Select-Object -First 40
            $text = if ($procs) { $procs -join "`n" } else { "No monitored processes yet." }
            [System.Windows.Forms.MessageBox]::Show($text, "Monitored Processes ($($procs.Count))", "OK", "Information")
        } catch {}
    }
    $script:LblUptime      = New-StatCard $statusPage 610 65  "Uptime"             "valUptime"   $colOrange "$([char]0x23F1)"
    $script:LblUptime.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)

    # Computer info (expanded with scan count, start time, clickable log dir)
    $infoBox = New-Object System.Windows.Forms.Panel
    $infoBox.Location = New-Object System.Drawing.Point(25, 170)
    $infoBox.Size = New-Object System.Drawing.Size(770, 75)
    $infoBox.BackColor = $colCard
    $infoBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $statusPage.Controls.Add($infoBox)

    $infoItems = @(
        @{ L = "Computer";   V = $env:COMPUTERNAME; X = 15 },
        @{ L = "User";       V = $env:USERNAME;     X = 155 },
        @{ L = "Interval";   V = "${IntervalSeconds}s"; X = 290 },
        @{ L = "Started";    V = $script:StartTime.ToString("HH:mm:ss"); X = 390 },
        @{ L = "Scans";      V = "0";               X = 500 }
    )
    foreach ($ii in $infoItems) {
        $il = New-Object System.Windows.Forms.Label
        $il.Text = $ii.L
        $il.Location = New-Object System.Drawing.Point($ii.X, 10)
        $il.Size = New-Object System.Drawing.Size(120, 18)
        $il.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $il.ForeColor = $colTextDim
        $infoBox.Controls.Add($il)

        $iv = New-Object System.Windows.Forms.Label
        $iv.Text = $ii.V
        $iv.Location = New-Object System.Drawing.Point($ii.X, 30)
        $iv.Size = New-Object System.Drawing.Size(120, 30)
        $iv.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
        $iv.ForeColor = $colTextMain
        if ($ii.L -eq "Scans") { $iv.Name = "scanCountLabel" ; $script:ScanCountLabel = $iv }
        $infoBox.Controls.Add($iv)
    }

    # Clickable log directory link
    $logDirLabel = New-Object System.Windows.Forms.Label
    $logDirLabel.Text = "Log Dir"
    $logDirLabel.Location = New-Object System.Drawing.Point(600, 10)
    $logDirLabel.Size = New-Object System.Drawing.Size(160, 18)
    $logDirLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $logDirLabel.ForeColor = $colTextDim
    $infoBox.Controls.Add($logDirLabel)

    $logDirLink = New-Object System.Windows.Forms.LinkLabel
    $logDirLink.Text = $LogDir
    $logDirLink.Location = New-Object System.Drawing.Point(600, 30)
    $logDirLink.Size = New-Object System.Drawing.Size(160, 30)
    $logDirLink.Font = New-Object System.Drawing.Font("Consolas", 8.5, [System.Drawing.FontStyle]::Bold)
    $logDirLink.LinkColor = $colAccent
    $logDirLink.ActiveLinkColor = [System.Drawing.Color]::White
    $logDirLink.VisitedLinkColor = $colAccent
    $capturedLogDir = $LogDir
    $logDirLink.Add_LinkClicked({ Start-Process explorer.exe $capturedLogDir })
    $infoBox.Controls.Add($logDirLink)

    # ── Security Posture Panel ──
    $secPosturePanel = New-Object System.Windows.Forms.Panel
    $secPosturePanel.Location = New-Object System.Drawing.Point(25, 258)
    $secPosturePanel.Size = New-Object System.Drawing.Size(770, 52)
    $secPosturePanel.BackColor = $colCard
    $secPosturePanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $statusPage.Controls.Add($secPosturePanel)

    $spTitle = New-Object System.Windows.Forms.Label
    $spTitle.Text = "Security Posture"
    $spTitle.Location = New-Object System.Drawing.Point(12, 4)
    $spTitle.Size = New-Object System.Drawing.Size(200, 18)
    $spTitle.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
    $spTitle.ForeColor = $colAccent
    $secPosturePanel.Controls.Add($spTitle)

    # Security posture indicators
    $spItems = @(
        @{ L = "Defender"; Idx = 0 },
        @{ L = "Firewall"; Idx = 1 },
        @{ L = "UAC";      Idx = 2 },
        @{ L = "RDP";      Idx = 3 }
    )
    $script:SecPostureDots = @{}
    $script:SecPostureLabels = @{}
    foreach ($spi in $spItems) {
        $spX = 12 + $spi.Idx * [int](($secPosturePanel.Width - 24) / 4)
        $dot = New-Object System.Windows.Forms.Panel
        $dot.Location = New-Object System.Drawing.Point($spX, 28)
        $dot.Size = New-Object System.Drawing.Size(12, 12)
        $dot.Tag = "spdot_$($spi.Idx)"
        $dot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $secPosturePanel.Controls.Add($dot)
        $script:SecPostureDots[$spi.L] = $dot

        $spLbl = New-Object System.Windows.Forms.Label
        $spLbl.Text = "$($spi.L): ..."
        $spLbl.Location = New-Object System.Drawing.Point(($spX + 18), 26)
        $spLbl.Size = New-Object System.Drawing.Size(130, 16)
        $spLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
        $spLbl.ForeColor = $colTextDim
        $spLbl.Cursor = [System.Windows.Forms.Cursors]::Hand
        $spLbl.Tag = $spi.L
        $spLbl.Add_Click({
            $key = $this.Tag
            try {
                $info = switch ($key) {
                    "Defender" {
                        $d = Get-MpComputerStatus -ErrorAction SilentlyContinue
                        if ($d) { "Antivirus Enabled: $($d.AntivirusEnabled)`nReal-Time Protection: $($d.RealTimeProtectionEnabled)`nDefinition Age: $($d.AntivirusSignatureAge) day(s)`nLast Scan: $($d.FullScanEndTime)" } else { "Windows Defender status unavailable." }
                    }
                    "Firewall" {
                        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                        ($fw | ForEach-Object { "$($_.Name): $( if ($_.Enabled) {'Enabled'} else {'DISABLED'} )" }) -join "`n"
                    }
                    "UAC" {
                        $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
                        if ($uac -eq 1) { "UAC is Enabled" } else { "UAC is DISABLED - security risk!" }
                    }
                    "RDP" {
                        $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
                        if ($rdp -eq 1) { "RDP is Disabled (secure)" } else { "RDP is ENABLED - connections allowed" }
                    }
                }
                [System.Windows.Forms.MessageBox]::Show($info, "$key Details", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Could not retrieve $key status.", "$key", "OK", "Warning") }
        })
        $secPosturePanel.Controls.Add($spLbl)
        $script:SecPostureLabels[$spi.L] = $spLbl
    }

    # Resize handler for security posture indicators
    $secPosturePanel.Add_Resize({
        try {
            $pw = $this.ClientSize.Width
            $idx = 0
            $dots = @($this.Controls | Where-Object { $_.Tag -match "^spdot_" } | Sort-Object { [int]($_.Tag -replace 'spdot_','') })
            $labels = @($this.Controls | Where-Object { $_ -is [System.Windows.Forms.Label] -and $_.Cursor -eq [System.Windows.Forms.Cursors]::Hand } | Sort-Object { $_.Location.X })
            $slotW = [int](($pw - 24) / 4)
            for ($i = 0; $i -lt $dots.Count -and $i -lt $labels.Count; $i++) {
                $x = 12 + $i * $slotW
                $dots[$i].Location = New-Object System.Drawing.Point($x, 28)
                $labels[$i].Location = New-Object System.Drawing.Point(($x + 18), 26)
            }
        } catch {}
    })

    # ── Network Activity Panel ──
    $netPanel = New-Object System.Windows.Forms.Panel
    $netPanel.Location = New-Object System.Drawing.Point(25, 318)
    $netPanel.Size = New-Object System.Drawing.Size(770, 60)
    $netPanel.BackColor = $colCard
    $netPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $statusPage.Controls.Add($netPanel)

    $netTitle = New-Object System.Windows.Forms.Label
    $netTitle.Text = "Network Activity"
    $netTitle.Location = New-Object System.Drawing.Point(12, 4)
    $netTitle.Size = New-Object System.Drawing.Size(200, 18)
    $netTitle.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
    $netTitle.ForeColor = $colAccent
    $netPanel.Controls.Add($netTitle)

    $script:NetActivityLabel = New-Object System.Windows.Forms.Label
    $script:NetActivityLabel.Text = "Gathering network data..."
    $script:NetActivityLabel.Location = New-Object System.Drawing.Point(12, 24)
    $script:NetActivityLabel.Size = New-Object System.Drawing.Size(600, 30)
    $script:NetActivityLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $script:NetActivityLabel.ForeColor = $colTextMain
    $netPanel.Controls.Add($script:NetActivityLabel)

    $viewAllConns = New-Object System.Windows.Forms.LinkLabel
    $viewAllConns.Text = "View All Connections"
    $viewAllConns.Location = New-Object System.Drawing.Point(640, 24)
    $viewAllConns.Size = New-Object System.Drawing.Size(120, 18)
    $viewAllConns.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $viewAllConns.LinkColor = $colAccent
    $viewAllConns.ActiveLinkColor = [System.Drawing.Color]::White
    $viewAllConns.VisitedLinkColor = $colAccent
    $viewAllConns.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $viewAllConns.Add_LinkClicked({
        try {
            $allConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.|::1|::$)' } |
                ForEach-Object {
                    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                    "$($proc):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
                }
            $text = if ($allConns) { $allConns -join "`n" } else { "No active external connections." }
            [System.Windows.Forms.MessageBox]::Show($text, "All Connections ($($allConns.Count))", "OK", "Information")
        } catch {}
    })
    $netPanel.Controls.Add($viewAllConns)

    # ── AI Threat Detection Panel (Status Page) ──
    $aiPanel = New-Object System.Windows.Forms.Panel
    $aiPanel.Location = New-Object System.Drawing.Point(25, 385)
    $aiPanel.Size = New-Object System.Drawing.Size(770, 65)
    $aiPanel.BackColor = $colCard
    $aiPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $statusPage.Controls.Add($aiPanel)

    $aiIcon = New-Object System.Windows.Forms.Label
    $aiIcon.Text = "$([char]0x2699)"
    $aiIcon.Location = New-Object System.Drawing.Point(12, 8)
    $aiIcon.Size = New-Object System.Drawing.Size(32, 32)
    $aiIcon.Font = New-Object System.Drawing.Font("Segoe UI Symbol", 16)
    $aiIcon.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 255)
    $aiPanel.Controls.Add($aiIcon)

    $aiTitle = New-Object System.Windows.Forms.Label
    $aiTitle.Text = "AI Threat Detection"
    $aiTitle.Location = New-Object System.Drawing.Point(48, 6)
    $aiTitle.Size = New-Object System.Drawing.Size(200, 20)
    $aiTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $aiTitle.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 255)
    $aiPanel.Controls.Add($aiTitle)

    $script:AiStatusLabel = New-Object System.Windows.Forms.Label
    $script:AiStatusLabel.Text = "Initializing..."
    $script:AiStatusLabel.Location = New-Object System.Drawing.Point(48, 28)
    $script:AiStatusLabel.Size = New-Object System.Drawing.Size(500, 16)
    $script:AiStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $script:AiStatusLabel.ForeColor = $colTextDim
    $aiPanel.Controls.Add($script:AiStatusLabel)

    $script:AiCountLabel = New-Object System.Windows.Forms.Label
    $script:AiCountLabel.Text = "0"
    $script:AiCountLabel.Location = New-Object System.Drawing.Point(48, 44)
    $script:AiCountLabel.Size = New-Object System.Drawing.Size(300, 16)
    $script:AiCountLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
    $script:AiCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 100)
    $aiPanel.Controls.Add($script:AiCountLabel)

    $aiViewLink = New-Object System.Windows.Forms.LinkLabel
    $aiViewLink.Text = "View Details >>"
    $aiViewLink.Location = New-Object System.Drawing.Point(640, 8)
    $aiViewLink.Size = New-Object System.Drawing.Size(120, 18)
    $aiViewLink.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $aiViewLink.LinkColor = [System.Drawing.Color]::FromArgb(180, 120, 255)
    $aiViewLink.ActiveLinkColor = [System.Drawing.Color]::White
    $aiViewLink.VisitedLinkColor = [System.Drawing.Color]::FromArgb(180, 120, 255)
    $aiViewLink.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $aiViewLink.Add_LinkClicked({ try { & $script:SwitchPageFn "AI Threats" } catch {} })
    $aiPanel.Controls.Add($aiViewLink)

    $script:AiScanBtn = New-Object System.Windows.Forms.Button
    $script:AiScanBtn.Text = "Scan Now"
    $script:AiScanBtn.Location = New-Object System.Drawing.Point(640, 32)
    $script:AiScanBtn.Size = New-Object System.Drawing.Size(120, 26)
    $script:AiScanBtn.FlatStyle = "Flat"
    $script:AiScanBtn.BackColor = [System.Drawing.Color]::FromArgb(100, 60, 180)
    $script:AiScanBtn.ForeColor = [System.Drawing.Color]::White
    $script:AiScanBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
    $script:AiScanBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $script:AiScanBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $script:AiScanBtn.Add_Click({ try { Start-AiThreatScan } catch {} })
    $aiPanel.Controls.Add($script:AiScanBtn)
    $script:AiStatusPanel = $aiPanel
    $aiPanel.Visible = $true

    # ── Modern ListView styling helper ──
    # Applies dark OwnerDraw theme with custom header, row highlights, no grid lines
    $script:ColCard = $colCard
    $script:ColBg = $colBg
    $script:ColAccent = $colAccent
    $script:ColTextMain = $colTextMain
    $script:ColTextDim = $colTextDim

    function Style-ListView {
        param([System.Windows.Forms.ListView]$lv)
        $lv.View = "Details"
        $lv.FullRowSelect = $true
        $lv.GridLines = $false
        $lv.BorderStyle = "None"
        $lv.BackColor = $colCard
        $lv.ForeColor = $colTextMain
        $lv.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $lv.OwnerDraw = $true
        $lv.HeaderStyle = "Nonclickable"

        # Force row height to 28px using an empty ImageList trick
        $imgList = New-Object System.Windows.Forms.ImageList
        $imgList.ImageSize = New-Object System.Drawing.Size(1, 28)
        $lv.SmallImageList = $imgList

        # Draw column headers
        $lv.Add_DrawColumnHeader({
            param($s, $e)
            $headerBg = [System.Drawing.Color]::FromArgb(22, 22, 36)
            $headerFg = [System.Drawing.Color]::FromArgb(100, 160, 255)
            $brush = New-Object System.Drawing.SolidBrush($headerBg)
            $e.Graphics.FillRectangle($brush, $e.Bounds)
            $brush.Dispose()
            # Bottom accent line
            $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 100, 200), 2)
            $e.Graphics.DrawLine($pen, $e.Bounds.Left, ($e.Bounds.Bottom - 1), $e.Bounds.Right, ($e.Bounds.Bottom - 1))
            $pen.Dispose()
            $textBrush = New-Object System.Drawing.SolidBrush($headerFg)
            $headerFont = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)
            $rect = New-Object System.Drawing.RectangleF(($e.Bounds.X + 8), ($e.Bounds.Y + 4), $e.Bounds.Width, $e.Bounds.Height)
            $e.Graphics.DrawString($e.Header.Text, $headerFont, $textBrush, $rect)
            $headerFont.Dispose()
            $textBrush.Dispose()
        })

        # Draw items (rows)
        $lv.Add_DrawItem({
            param($s, $e)
            $e.DrawDefault = $false
        })

        # Draw sub-items (cells)
        $lv.Add_DrawSubItem({
            param($s, $e)
            try {
                $isSelected = ($e.ItemState -band [System.Windows.Forms.ListViewItemStates]::Selected)
                $isEven = ($e.ItemIndex % 2 -eq 0)

                # Background
                if ($isSelected) {
                    $bgColor = [System.Drawing.Color]::FromArgb(20, 60, 110)
                } elseif ($isEven) {
                    $bgColor = [System.Drawing.Color]::FromArgb(26, 26, 42)
                } else {
                    $bgColor = [System.Drawing.Color]::FromArgb(32, 32, 50)
                }
                $bgBrush = New-Object System.Drawing.SolidBrush($bgColor)
                $e.Graphics.FillRectangle($bgBrush, $e.Bounds)
                $bgBrush.Dispose()

                # Severity accent bar on first column (3px left stripe)
                if ($e.ColumnIndex -eq 0) {
                    $accentColor = $e.Item.ForeColor
                    $accentBrush = New-Object System.Drawing.SolidBrush($accentColor)
                    $e.Graphics.FillRectangle($accentBrush, $e.Bounds.X, $e.Bounds.Y, 3, $e.Bounds.Height)
                    $accentBrush.Dispose()
                }

                # Text color per column: 0=Time, 1=Severity, 2=Category, 3=Title, 4=Message
                if ($isSelected) {
                    $txtColor = [System.Drawing.Color]::White
                } else {
                    if ($e.ColumnIndex -eq 0) {
                        # Time column - soft white
                        $txtColor = [System.Drawing.Color]::FromArgb(180, 180, 200)
                    } elseif ($e.ColumnIndex -eq 1) {
                        # Severity - use item ForeColor (severity-coded)
                        $txtColor = $e.Item.ForeColor
                    } elseif ($e.ColumnIndex -eq 2) {
                        # Category - accent colored
                        $txtColor = $e.Item.ForeColor
                    } elseif ($e.ColumnIndex -eq 3) {
                        # Title - bright white
                        $txtColor = [System.Drawing.Color]::FromArgb(240, 240, 250)
                    } else {
                        # Message - dimmed
                        $txtColor = [System.Drawing.Color]::FromArgb(155, 155, 175)
                    }
                }
                $txtBrush = New-Object System.Drawing.SolidBrush($txtColor)
                $cellFont = $e.Item.Font
                if ($e.ColumnIndex -eq 0) {
                    $cellFont = New-Object System.Drawing.Font("Consolas", 8.5)
                } elseif ($e.ColumnIndex -eq 1) {
                    $cellFont = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
                }
                $textRect = New-Object System.Drawing.RectangleF(($e.Bounds.X + 8), $e.Bounds.Y, ($e.Bounds.Width - 10), $e.Bounds.Height)
                $sf = New-Object System.Drawing.StringFormat
                $sf.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap
                $sf.Trimming = [System.Drawing.StringTrimming]::EllipsisCharacter
                $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
                $text = if ($e.SubItem) { $e.SubItem.Text } else { "" }
                $e.Graphics.DrawString($text, $cellFont, $txtBrush, $textRect, $sf)
                $sf.Dispose()
                $txtBrush.Dispose()
                if ($e.ColumnIndex -in @(0, 1)) { $cellFont.Dispose() }

                # Subtle separator line between rows
                $sepPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 40, 60), 1)
                $e.Graphics.DrawLine($sepPen, $e.Bounds.Left, ($e.Bounds.Bottom - 1), $e.Bounds.Right, ($e.Bounds.Bottom - 1))
                $sepPen.Dispose()
            } catch {
                $e.DrawDefault = $true
            }
        })
    }

    # ── Auto-resize ListView columns proportionally ──
    # Column proportions: Time=14%, Severity=8%, Category=13%, Title=26%, Message=39%
    $script:LvColProportions = @(0.14, 0.08, 0.13, 0.26, 0.39)
    function Resize-ListViewColumns {
        param([System.Windows.Forms.ListView]$lv)
        $w = $lv.ClientSize.Width - 2
        if ($w -lt 200) { return }
        $props = $script:LvColProportions
        for ($i = 0; $i -lt $lv.Columns.Count -and $i -lt $props.Count; $i++) {
            $lv.Columns[$i].Width = [Math]::Max(40, [int]($w * $props[$i]))
        }
    }

    # ── System Health Gauges ──
    $healthLabel = New-Object System.Windows.Forms.Label
    $healthLabel.Text = "System Health"
    $healthLabel.Location = New-Object System.Drawing.Point(25, 462)
    $healthLabel.Size = New-Object System.Drawing.Size(200, 22)
    $healthLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $healthLabel.ForeColor = $colAccent
    $statusPage.Controls.Add($healthLabel)

    function New-GaugeBar {
        param($parent, $x, $y, $label, $barName)
        $gp = New-Object System.Windows.Forms.Panel
        $gp.Location = New-Object System.Drawing.Point($x, $y)
        $gp.Size = New-Object System.Drawing.Size(240, 44)
        $gp.BackColor = $colCard
        $gp.Tag = "gauge"
        $parent.Controls.Add($gp)

        $gl = New-Object System.Windows.Forms.Label
        $gl.Text = $label
        $gl.Location = New-Object System.Drawing.Point(10, 4)
        $gl.Size = New-Object System.Drawing.Size(60, 16)
        $gl.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $gl.ForeColor = $colTextDim
        $gp.Controls.Add($gl)

        $gv = New-Object System.Windows.Forms.Label
        $gv.Name = "${barName}_val"
        $gv.Text = "0%"
        $gv.Location = New-Object System.Drawing.Point(180, 4)
        $gv.Size = New-Object System.Drawing.Size(55, 16)
        $gv.Font = New-Object System.Drawing.Font("Consolas", 8.5, [System.Drawing.FontStyle]::Bold)
        $gv.ForeColor = $colTextMain
        $gv.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
        $gp.Controls.Add($gv)

        # Progress bar background
        $barBg = New-Object System.Windows.Forms.Panel
        $barBg.Location = New-Object System.Drawing.Point(10, 24)
        $barBg.Size = New-Object System.Drawing.Size(220, 10)
        $barBg.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 35)
        $gp.Controls.Add($barBg)

        # Progress bar fill
        $barFill = New-Object System.Windows.Forms.Panel
        $barFill.Name = $barName
        $barFill.Location = New-Object System.Drawing.Point(0, 0)
        $barFill.Size = New-Object System.Drawing.Size(0, 10)
        $barFill.BackColor = $colGreen
        $barBg.Controls.Add($barFill)

        return @{ Fill = $barFill; Label = $gv }
    }

    $script:CpuGauge  = New-GaugeBar $statusPage 25  487 "CPU"  "cpuBar"
    $script:RamGauge  = New-GaugeBar $statusPage 275 487 "RAM"  "ramBar"
    $script:DiskGauge = New-GaugeBar $statusPage 525 487 "DISK" "diskBar"

    # Recent alerts preview on status page (Enhancement 4: "View All >>" link)
    $recentLabel = New-Object System.Windows.Forms.Label
    $recentLabel.Text = "Recent Alerts"
    $recentLabel.Location = New-Object System.Drawing.Point(25, 542)
    $recentLabel.Size = New-Object System.Drawing.Size(300, 24)
    $recentLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $recentLabel.ForeColor = $colOrange
    $statusPage.Controls.Add($recentLabel)

    # "View All >>" link next to Recent Alerts title
    $viewAllLink = New-Object System.Windows.Forms.LinkLabel
    $viewAllLink.Text = "View All >>"
    $viewAllLink.Location = New-Object System.Drawing.Point(700, 546)
    $viewAllLink.Size = New-Object System.Drawing.Size(90, 18)
    $viewAllLink.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $viewAllLink.LinkColor = $colAccent
    $viewAllLink.ActiveLinkColor = [System.Drawing.Color]::White
    $viewAllLink.VisitedLinkColor = $colAccent
    $viewAllLink.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $viewAllLink.Add_LinkClicked({ try { & $script:SwitchPageFn "Alerts" } catch {} })
    $statusPage.Controls.Add($viewAllLink)

    $script:RecentList = New-Object System.Windows.Forms.ListView
    $recentList = $script:RecentList
    $recentList.Name = "recentList"
    $recentList.Location = New-Object System.Drawing.Point(25, 570)
    $recentList.Size = New-Object System.Drawing.Size(770, 170)
    $recentList.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    Style-ListView $recentList
    [void]$recentList.Columns.Add("Time", 110)
    [void]$recentList.Columns.Add("Severity", 65)
    [void]$recentList.Columns.Add("Category", 100)
    [void]$recentList.Columns.Add("Title", 185)
    [void]$recentList.Columns.Add("Message", 290)
    $recentList.Add_Resize({ try { Resize-ListViewColumns $this } catch {} })
    $recentList.Add_DoubleClick({
        try {
            $sel = $this.SelectedItems
            if ($sel.Count -gt 0) {
                $idx = $sel[0].Tag
                $ad = $script:AlertHistory[$idx]
                Show-AlertDetail -AlertData $ad -ParentForm $script:DashboardForm
            }
        } catch {}
    })
    $statusPage.Controls.Add($recentList)

    # ── Status page resize handler: redistribute stat cards, gauge bars, and security posture indicators ──
    $statusPage.Add_Resize({
        try {
            $pw = $this.ClientSize.Width
            $pad = 25
            $gap = 10

            # Redistribute stat cards (4 cards, Tag="card")
            $cards = @($this.Controls | Where-Object { $_.Tag -eq "card" } | Sort-Object { $_.Location.X })
            if ($cards.Count -eq 4) {
                $cardW = [Math]::Max(120, [int](($pw - 2 * $pad - 3 * $gap) / 4))
                for ($i = 0; $i -lt 4; $i++) {
                    $cards[$i].Location = New-Object System.Drawing.Point(($pad + $i * ($cardW + $gap)), $cards[$i].Location.Y)
                    $cards[$i].Size = New-Object System.Drawing.Size($cardW, $cards[$i].Height)
                    # Resize accent bar height
                    foreach ($c in $cards[$i].Controls) {
                        if ($c -is [System.Windows.Forms.Panel] -and $c.Width -le 5) {
                            $c.Size = New-Object System.Drawing.Size($c.Width, $cards[$i].Height)
                        }
                    }
                }
            }

            # Redistribute gauge bars (3 bars, Tag="gauge")
            $gauges = @($this.Controls | Where-Object { $_.Tag -eq "gauge" } | Sort-Object { $_.Location.X })
            if ($gauges.Count -eq 3) {
                $gaugeW = [Math]::Max(150, [int](($pw - 2 * $pad - 2 * $gap) / 3))
                for ($i = 0; $i -lt 3; $i++) {
                    $gauges[$i].Location = New-Object System.Drawing.Point(($pad + $i * ($gaugeW + $gap)), $gauges[$i].Location.Y)
                    $gauges[$i].Size = New-Object System.Drawing.Size($gaugeW, $gauges[$i].Height)
                    # Resize progress bar background inside gauge
                    foreach ($c in $gauges[$i].Controls) {
                        if ($c -is [System.Windows.Forms.Panel] -and $c.Location.Y -ge 20) {
                            $c.Size = New-Object System.Drawing.Size(($gaugeW - 20), $c.Height)
                        }
                        # Reposition percentage label
                        if ($c -is [System.Windows.Forms.Label] -and $c.Name -match "_val$") {
                            $c.Location = New-Object System.Drawing.Point(($gaugeW - 60), $c.Location.Y)
                        }
                    }
                }
            }
        } catch {}
    })

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 2: ALERTS (full history + detail panel)
    # ═══════════════════════════════════════════════════════════════
  try {
    $alertsPage = $pages["Alerts"]

    $alertsTitle = New-Object System.Windows.Forms.Label
    $alertsTitle.Text = "Alert History"
    $alertsTitle.Location = New-Object System.Drawing.Point(25, 18)
    $alertsTitle.Size = New-Object System.Drawing.Size(300, 32)
    $alertsTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $alertsTitle.ForeColor = $colRed
    $alertsPage.Controls.Add($alertsTitle)

    $alertCountLabel = New-Object System.Windows.Forms.Label
    $alertCountLabel.Name = "alertCountLabel"
    $alertCountLabel.Text = "0 alerts"
    $alertCountLabel.Location = New-Object System.Drawing.Point(540, 22)
    $alertCountLabel.Size = New-Object System.Drawing.Size(250, 24)
    $alertCountLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $alertCountLabel.ForeColor = $colTextDim
    $alertCountLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $alertCountLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $alertsPage.Controls.Add($alertCountLabel)

    # ── Search/Filter bar ──
    $filterPanel = New-Object System.Windows.Forms.Panel
    $filterPanel.Location = New-Object System.Drawing.Point(25, 52)
    $filterPanel.Size = New-Object System.Drawing.Size(770, 36)
    $filterPanel.BackColor = [System.Drawing.Color]::FromArgb(22, 22, 36)
    $filterPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $alertsPage.Controls.Add($filterPanel)

    $script:SearchBox = New-Object System.Windows.Forms.TextBox
    $script:SearchBox.Location = New-Object System.Drawing.Point(8, 6)
    $script:SearchBox.Size = New-Object System.Drawing.Size(220, 24)
    $script:SearchBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $script:SearchBox.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 55)
    $script:SearchBox.ForeColor = $colTextMain
    $script:SearchBox.BorderStyle = "FixedSingle"
    $script:SearchBox.Text = ""
    $filterPanel.Controls.Add($script:SearchBox)

    $searchPlaceholder = New-Object System.Windows.Forms.Label
    $searchPlaceholder.Text = "Search alerts..."
    $searchPlaceholder.Location = New-Object System.Drawing.Point(12, 9)
    $searchPlaceholder.Size = New-Object System.Drawing.Size(150, 18)
    $searchPlaceholder.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
    $searchPlaceholder.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 100)
    $searchPlaceholder.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 55)
    $filterPanel.Controls.Add($searchPlaceholder)
    $searchPlaceholder.BringToFront()
    $script:SearchBox.Add_TextChanged({
        $searchPlaceholder.Visible = ($this.Text.Length -eq 0)
        & $script:ApplyFilterFn
    })
    $script:SearchBox.Add_GotFocus({ $searchPlaceholder.Visible = $false })
    $script:SearchBox.Add_LostFocus({ $searchPlaceholder.Visible = ($script:SearchBox.Text.Length -eq 0) })

    $sevFilterLabel = New-Object System.Windows.Forms.Label
    $sevFilterLabel.Text = "Severity:"
    $sevFilterLabel.Location = New-Object System.Drawing.Point(240, 9)
    $sevFilterLabel.Size = New-Object System.Drawing.Size(55, 18)
    $sevFilterLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $sevFilterLabel.ForeColor = $colTextDim
    $filterPanel.Controls.Add($sevFilterLabel)

    $script:SevFilter = New-Object System.Windows.Forms.ComboBox
    $script:SevFilter.Location = New-Object System.Drawing.Point(295, 5)
    $script:SevFilter.Size = New-Object System.Drawing.Size(80, 24)
    $script:SevFilter.DropDownStyle = "DropDownList"
    $script:SevFilter.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $script:SevFilter.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 55)
    $script:SevFilter.ForeColor = $colTextMain
    $script:SevFilter.FlatStyle = "Flat"
    [void]$script:SevFilter.Items.AddRange(@("All", "CRIT", "HIGH", "MED", "LOW", "INFO"))
    $script:SevFilter.SelectedIndex = 0
    $script:SevFilter.Add_SelectedIndexChanged({ & $script:ApplyFilterFn })
    $filterPanel.Controls.Add($script:SevFilter)

    $catFilterLabel = New-Object System.Windows.Forms.Label
    $catFilterLabel.Text = "Category:"
    $catFilterLabel.Location = New-Object System.Drawing.Point(385, 9)
    $catFilterLabel.Size = New-Object System.Drawing.Size(58, 18)
    $catFilterLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $catFilterLabel.ForeColor = $colTextDim
    $filterPanel.Controls.Add($catFilterLabel)

    $script:CatFilter = New-Object System.Windows.Forms.ComboBox
    $script:CatFilter.Location = New-Object System.Drawing.Point(443, 5)
    $script:CatFilter.Size = New-Object System.Drawing.Size(110, 24)
    $script:CatFilter.DropDownStyle = "DropDownList"
    $script:CatFilter.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $script:CatFilter.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 55)
    $script:CatFilter.ForeColor = $colTextMain
    $script:CatFilter.FlatStyle = "Flat"
    [void]$script:CatFilter.Items.AddRange(@("All", "Connection", "Process", "Firmware", "Driver", "Service", "Registry", "Registry Tampering", "Security", "Listener", "Hosts", "RDP"))
    $script:CatFilter.SelectedIndex = 0
    $script:CatFilter.Add_SelectedIndexChanged({ & $script:ApplyFilterFn })
    $filterPanel.Controls.Add($script:CatFilter)

    # Export button
    $exportBtn = New-Object System.Windows.Forms.Button
    $exportBtn.Text = "Export"
    $exportBtn.Location = New-Object System.Drawing.Point(570, 4)
    $exportBtn.Size = New-Object System.Drawing.Size(70, 26)
    $exportBtn.FlatStyle = "Flat"
    $exportBtn.FlatAppearance.BorderSize = 1
    $exportBtn.FlatAppearance.BorderColor = $colAccent
    $exportBtn.BackColor = [System.Drawing.Color]::FromArgb(22, 22, 36)
    $exportBtn.ForeColor = $colAccent
    $exportBtn.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $exportBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $exportBtn.Add_Click({
        try {
            $sfd = New-Object System.Windows.Forms.SaveFileDialog
            $sfd.Filter = "CSV (*.csv)|*.csv|JSON (*.json)|*.json"
            $sfd.FileName = "SecurityMonitor_Alerts_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            if ($sfd.ShowDialog() -eq "OK") {
                $data = $script:AlertHistory
                if ($sfd.FileName -match '\.json$') {
                    $data | ConvertTo-Json -Depth 5 | Set-Content -Path $sfd.FileName -Encoding UTF8
                } else {
                    $lines = @("Timestamp,Severity,Category,Title,Message,RemoteIP")
                    foreach ($a in $data) {
                        $lines += "`"$($a.Timestamp)`",`"$($a.Severity)`",`"$($a.Category)`",`"$($a.Title -replace '"','""')`",`"$($a.Message -replace '"','""')`",`"$($a.RemoteIP)`""
                    }
                    $lines | Set-Content -Path $sfd.FileName -Encoding UTF8
                }
                [System.Windows.Forms.MessageBox]::Show("Exported $($data.Count) alerts to:`n$($sfd.FileName)", "Export Complete", "OK", "Information")
            }
        } catch {}
    })
    $filterPanel.Controls.Add($exportBtn)

    # Filter logic
    $script:ApplyFilterFn = {
        try {
            if (-not $script:AlertListView -or -not $script:AlertCountLabel) { return }
            $keyword = $script:SearchBox.Text.Trim().ToLower()
            $sevSel = $script:SevFilter.SelectedItem
            $catSel = $script:CatFilter.SelectedItem
            $script:AlertListView.Items.Clear()
            $total = $script:AlertHistory.Count
            $shown = 0
            for ($i = $total - 1; $i -ge 0; $i--) {
                $a = $script:AlertHistory[$i]
                if ($sevSel -ne "All" -and $a.Severity -ne $sevSel) { continue }
                if ($catSel -ne "All" -and $a.Category -ne $catSel) { continue }
                if ($keyword.Length -gt 0) {
                    $match = ($a.Title.ToLower().Contains($keyword)) -or ($a.Message.ToLower().Contains($keyword)) -or ($a.Category.ToLower().Contains($keyword))
                    if (-not $match) { continue }
                }
                $itemColor = switch ($a.Severity) {
                    "CRIT" { [System.Drawing.Color]::FromArgb(255, 80, 90) }
                    "HIGH" { [System.Drawing.Color]::FromArgb(255, 170, 80) }
                    "MED"  { [System.Drawing.Color]::FromArgb(120, 190, 255) }
                    "LOW"  { [System.Drawing.Color]::FromArgb(160, 220, 180) }
                    default { [System.Drawing.Color]::FromArgb(140, 140, 160) }
                }
                $item = New-Object System.Windows.Forms.ListViewItem($a.Timestamp)
                [void]$item.SubItems.Add($a.Severity)
                [void]$item.SubItems.Add($a.Category)
                [void]$item.SubItems.Add($a.Title)
                [void]$item.SubItems.Add($a.Message)
                $item.Tag = $i
                $item.ForeColor = $itemColor
                [void]$script:AlertListView.Items.Add($item)
                $shown++
            }
            $script:AlertCountLabel.Text = "$shown / $total alerts"
        } catch {}
    }

    # Full alert list
    $script:AlertListView = New-Object System.Windows.Forms.ListView
    $alertListView = $script:AlertListView
    $alertListView.Name = "alertListView"
    $alertListView.Location = New-Object System.Drawing.Point(25, 92)
    $alertListView.Size = New-Object System.Drawing.Size(770, 255)
    $alertListView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    Style-ListView $alertListView
    [void]$alertListView.Columns.Add("Time", 110)
    [void]$alertListView.Columns.Add("Severity", 65)
    [void]$alertListView.Columns.Add("Category", 100)
    [void]$alertListView.Columns.Add("Title", 185)
    [void]$alertListView.Columns.Add("Message", 290)
    $alertListView.Add_Resize({ try { Resize-ListViewColumns $this } catch {} })
    $alertsPage.Controls.Add($alertListView)

    # Detail panel below the list
    $detailBox = New-Object System.Windows.Forms.Panel
    $detailBox.Name = "detailBox"
    $detailBox.Location = New-Object System.Drawing.Point(25, 358)
    $detailBox.Size = New-Object System.Drawing.Size(770, 230)
    $detailBox.BackColor = $colCard
    $detailBox.AutoScroll = $true
    $detailBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $alertsPage.Controls.Add($detailBox)

    $script:DetailTitle = New-Object System.Windows.Forms.Label
    $detailTitle = $script:DetailTitle
    $detailTitle.Name = "detailTitle"
    $detailTitle.Text = "Select an alert to view details"
    $detailTitle.Location = New-Object System.Drawing.Point(15, 10)
    $detailTitle.Size = New-Object System.Drawing.Size(550, 26)
    $detailTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $detailTitle.ForeColor = $colTextDim
    $detailBox.Controls.Add($detailTitle)

    $script:DetailContent = New-Object System.Windows.Forms.Panel
    $detailContent = $script:DetailContent
    $detailContent.Name = "detailContent"
    $detailContent.Location = New-Object System.Drawing.Point(15, 40)
    $detailContent.Size = New-Object System.Drawing.Size(730, 160)
    $detailContent.BackColor = $colCard
    $detailContent.AutoScroll = $true
    $detailContent.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $detailBox.Controls.Add($detailContent)

    # IP Lookup button (hidden until connection alert selected)
    $script:IpLookupBtn = New-Object System.Windows.Forms.Button
    $ipLookupBtn = $script:IpLookupBtn
    $ipLookupBtn.Name = "ipLookupBtn"
    $ipLookupBtn.Text = "Lookup IP on ipinfo.io"
    $ipLookupBtn.Location = New-Object System.Drawing.Point(15, 180)
    $ipLookupBtn.Size = New-Object System.Drawing.Size(280, 34)
    $ipLookupBtn.FlatStyle = "Flat"
    $ipLookupBtn.BackColor = $colAccent
    $ipLookupBtn.ForeColor = $colTextMain
    $ipLookupBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $ipLookupBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $ipLookupBtn.Visible = $false
    $ipLookupBtn.Tag = ""
    $ipLookupBtn.Add_Click({ if ($this.Tag) { Start-Process "https://ipinfo.io/$($this.Tag)" } })
    $detailBox.Controls.Add($ipLookupBtn)

    # Open log button
    $script:OpenLogBtn = New-Object System.Windows.Forms.Button
    $openLogBtn = $script:OpenLogBtn
    $openLogBtn.Text = "Open Alert Log"
    $openLogBtn.Location = New-Object System.Drawing.Point(310, 180)
    $openLogBtn.Size = New-Object System.Drawing.Size(160, 34)
    $openLogBtn.FlatStyle = "Flat"
    $openLogBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $openLogBtn.ForeColor = $colTextMain
    $openLogBtn.Visible = $false
    $openLogBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $openLogBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $openLogBtn.Tag = $AlertFile
    $openLogBtn.Add_Click({ if ($this.Tag -and (Test-Path $this.Tag)) { Start-Process notepad.exe $this.Tag } })
    $detailBox.Controls.Add($openLogBtn)

    # Open in Regedit button (hidden until registry alert selected)
    $script:RegeditBtn = New-Object System.Windows.Forms.Button
    $regeditBtn = $script:RegeditBtn
    $regeditBtn.Text = "Open in Regedit"
    $regeditBtn.Location = New-Object System.Drawing.Point(485, 180)
    $regeditBtn.Size = New-Object System.Drawing.Size(180, 34)
    $regeditBtn.FlatStyle = "Flat"
    $regeditBtn.BackColor = [System.Drawing.Color]::FromArgb(180, 100, 0)
    $regeditBtn.ForeColor = $colTextMain
    $regeditBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $regeditBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $regeditBtn.Visible = $false
    $regeditBtn.Tag = ""
    $regeditBtn.Add_Click({
        if ($this.Tag) {
            try {
                $regeditPath = $this.Tag -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value $regeditPath -ErrorAction SilentlyContinue
                Start-Process regedit.exe
            } catch {}
        }
    })
    $detailBox.Controls.Add($regeditBtn)

    # Block IP button (hidden until connection alert with IP selected)
    $script:BlockIpBtn = New-Object System.Windows.Forms.Button
    $blockIpBtn = $script:BlockIpBtn
    $blockIpBtn.Text = "Block IP (Firewall)"
    $blockIpBtn.Location = New-Object System.Drawing.Point(15, 220)
    $blockIpBtn.Size = New-Object System.Drawing.Size(280, 34)
    $blockIpBtn.FlatStyle = "Flat"
    $blockIpBtn.BackColor = [System.Drawing.Color]::FromArgb(180, 30, 30)
    $blockIpBtn.ForeColor = $colTextMain
    $blockIpBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $blockIpBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $blockIpBtn.Visible = $false
    $blockIpBtn.Tag = ""
    $blockIpBtn.Add_Click({
        if ($this.Tag) {
            $ip = $this.Tag
            $ruleName = "SecurityMonitor_Block_$ip"
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Are you sure you want to block IP address $ip ?`n`nThis will create Windows Firewall rules to block all inbound and outbound traffic from/to this IP.`n`nRule name: $ruleName`n`nA UAC prompt will appear for elevation.",
                "Block IP - Confirm",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
                try {
                    $scriptFile = Join-Path $env:TEMP "SecurityMonitor_BlockIP_$(Get-Random).ps1"
                    $resultFile = Join-Path $env:TEMP "SecurityMonitor_BlockResult_$(Get-Random).txt"

                    $fwScript = @"
try {
    `$existIn = Get-NetFirewallRule -DisplayName '${ruleName}_In' -ErrorAction SilentlyContinue
    if (`$existIn) {
        'ALREADY_BLOCKED' | Out-File -FilePath '$resultFile' -Encoding UTF8
        exit
    }
    New-NetFirewallRule -DisplayName '${ruleName}_In' -Direction Inbound -Action Block -RemoteAddress '$ip' -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName '${ruleName}_Out' -Direction Outbound -Action Block -RemoteAddress '$ip' -Profile Any -ErrorAction Stop | Out-Null
    'SUCCESS' | Out-File -FilePath '$resultFile' -Encoding UTF8
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Out-File -FilePath '$resultFile' -Encoding UTF8
}
"@
                    [System.IO.File]::WriteAllText($scriptFile, $fwScript)

                    $proc = Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $scriptFile -Verb RunAs -PassThru -ErrorAction Stop
                    $proc.WaitForExit(15000)

                    if (Test-Path $resultFile) {
                        $result = Get-Content $resultFile -Raw -ErrorAction SilentlyContinue
                        Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
                        Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue

                        if ($result -match '^SUCCESS') {
                            $this.Text = "IP Blocked"
                            $this.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                            $this.Enabled = $false
                            [System.Windows.Forms.MessageBox]::Show("IP $ip has been blocked (Admin).`n`nInbound rule: ${ruleName}_In`nOutbound rule: ${ruleName}_Out`n`nTo unblock, delete these rules in Windows Firewall.", "IP Blocked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                        } elseif ($result -match '^ALREADY_BLOCKED') {
                            $this.Text = "IP Already Blocked"
                            $this.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                            $this.Enabled = $false
                            [System.Windows.Forms.MessageBox]::Show("IP $ip is already blocked.", "Already Blocked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                        } else {
                            $errMsg = $result -replace '^ERROR:\s*', ''
                            [System.Windows.Forms.MessageBox]::Show("Failed to block IP:`n$errMsg", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                        }
                    } else {
                        Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue
                        [System.Windows.Forms.MessageBox]::Show("Operation timed out or was cancelled.", "Timeout", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    }
                } catch {
                    if ($_.Exception.Message -match 'canceled by the user|cancelled') {
                        [System.Windows.Forms.MessageBox]::Show("UAC elevation was cancelled by the user.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    } else {
                        [System.Windows.Forms.MessageBox]::Show("Failed to launch elevated process:`n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                    }
                }
            }
        }
    })
    $detailBox.Controls.Add($blockIpBtn)

    # Restore/Delete Registry button (hidden until registry alert selected)
    $script:RestoreRegBtn = New-Object System.Windows.Forms.Button
    $restoreRegBtn = $script:RestoreRegBtn
    $restoreRegBtn.Text = "Restore Registry"
    $restoreRegBtn.Location = New-Object System.Drawing.Point(15, 260)
    $restoreRegBtn.Size = New-Object System.Drawing.Size(280, 34)
    $restoreRegBtn.FlatStyle = "Flat"
    $restoreRegBtn.BackColor = [System.Drawing.Color]::FromArgb(30, 130, 60)
    $restoreRegBtn.ForeColor = $colTextMain
    $restoreRegBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $restoreRegBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $restoreRegBtn.Visible = $false
    $restoreRegBtn.Tag = $null
    $restoreRegBtn.Add_Click({
        $info = $this.Tag
        if (-not $info) { return }
        $regPath   = $info.RegPath
        $valueName = $info.ValueName
        $expected  = $info.Expected
        $action    = $info.Action  # "delete_value", "delete_key", "restore_value", "restore_snapshot"

        $descText = switch ($action) {
            "delete_key"   { "DELETE the entire registry key:`n$regPath" }
            "delete_value" { "DELETE the registry value '$valueName' from:`n$regPath" }
            "restore_value" { "RESTORE the registry value '$valueName' to '$expected' in:`n$regPath" }
            "restore_snapshot" { "RESTORE the registry key to its baseline snapshot:`n$regPath`n`nThis will remove added entries, restore removed entries, and revert modified values." }
            default { "Fix the registry at:`n$regPath" }
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to $descText`n`nThis action requires Administrator privileges.`nA UAC prompt will appear for elevation.",
            "Restore Registry - Confirm",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        try {
            # Build the PowerShell command to run elevated
            $psCmd = switch ($action) {
                "delete_key" {
                    "Remove-Item -Path '$regPath' -Recurse -Force -ErrorAction Stop"
                }
                "delete_value" {
                    "Remove-ItemProperty -Path '$regPath' -Name '$valueName' -Force -ErrorAction Stop"
                }
                "restore_value" {
                    "Set-ItemProperty -Path '$regPath' -Name '$valueName' -Value '$expected' -ErrorAction Stop"
                }
                "restore_snapshot" {
                    # For snapshot restore, serialize the snapshot to a temp file
                    $snapshot = $script:RegistrySnapshotCache[$regPath]
                    if (-not $snapshot) {
                        [System.Windows.Forms.MessageBox]::Show("No baseline snapshot available for this key.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                        return
                    }
                    $tmpFile = Join-Path $env:TEMP "SecurityMonitor_snapshot_$(Get-Random).xml"
                    $snapshot | Export-Clixml -Path $tmpFile -Force
                    @"
`$snapshot = Import-Clixml -Path '$tmpFile'
`$currentProps = Get-ItemProperty -Path '$regPath' -ErrorAction Stop
foreach (`$p in `$currentProps.PSObject.Properties) {
    if (`$p.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
        if (-not `$snapshot.ContainsKey(`$p.Name)) {
            Remove-ItemProperty -Path '$regPath' -Name `$p.Name -Force -ErrorAction SilentlyContinue
        }
    }
}
foreach (`$k in `$snapshot.Keys) {
    Set-ItemProperty -Path '$regPath' -Name `$k -Value `$snapshot[`$k] -ErrorAction SilentlyContinue
}
Remove-Item -Path '$tmpFile' -Force -ErrorAction SilentlyContinue
"@
                }
            }

            if (-not $psCmd) { return }

            # Write command to temp script file for clean elevation
            $scriptFile = Join-Path $env:TEMP "SecurityMonitor_RegFix_$(Get-Random).ps1"
            $resultFile = Join-Path $env:TEMP "SecurityMonitor_RegResult_$(Get-Random).txt"

            # Wrap command with result reporting
            $fullScript = @"
try {
    $psCmd
    'SUCCESS' | Out-File -FilePath '$resultFile' -Encoding UTF8
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Out-File -FilePath '$resultFile' -Encoding UTF8
}
"@
            [System.IO.File]::WriteAllText($scriptFile, $fullScript)

            # Launch elevated PowerShell with UAC prompt
            $proc = Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $scriptFile -Verb RunAs -PassThru -ErrorAction Stop

            # Wait for completion (with timeout)
            $proc.WaitForExit(15000)

            # Check result
            if (Test-Path $resultFile) {
                $result = Get-Content $resultFile -Raw -ErrorAction SilentlyContinue
                Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
                Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue

                if ($result -match '^SUCCESS') {
                    # Update local baseline if applicable
                    if ($action -eq "restore_snapshot") {
                        $newHash = Get-RegistryHash -KeyPath $regPath
                        if ($newHash) { $script:RegistryBaseline[$regPath] = $newHash }
                    }
                    $actionDesc = switch ($action) {
                        "delete_key"       { "Registry key deleted:`n$regPath" }
                        "delete_value"     { "Registry value '$valueName' deleted from:`n$regPath" }
                        "restore_value"    { "Registry value '$valueName' restored to '$expected' in:`n$regPath" }
                        "restore_snapshot" { "Registry key restored to baseline snapshot:`n$regPath" }
                    }
                    [System.Windows.Forms.MessageBox]::Show($actionDesc, "Registry Restored (Admin)", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    $this.Text = "Restored"
                    $this.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
                    $this.Enabled = $false
                } else {
                    $errMsg = $result -replace '^ERROR:\s*', ''
                    [System.Windows.Forms.MessageBox]::Show("Operation failed:`n$errMsg", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            } else {
                Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue
                [System.Windows.Forms.MessageBox]::Show("Operation timed out or was cancelled.", "Timeout", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        } catch {
            if ($_.Exception.Message -match 'canceled by the user|cancelled') {
                [System.Windows.Forms.MessageBox]::Show("UAC elevation was cancelled by the user.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Failed to launch elevated process:`n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })
    $detailBox.Controls.Add($restoreRegBtn)

    # Service Action button (Stop/Disable or Start/Enable)
    $script:ServiceActionBtn = New-Object System.Windows.Forms.Button
    $serviceActionBtn = $script:ServiceActionBtn
    $serviceActionBtn.Text = "Stop Service"
    $serviceActionBtn.Location = New-Object System.Drawing.Point(15, 300)
    $serviceActionBtn.Size = New-Object System.Drawing.Size(240, 34)
    $serviceActionBtn.FlatStyle = "Flat"
    $serviceActionBtn.BackColor = [System.Drawing.Color]::FromArgb(180, 100, 0)
    $serviceActionBtn.ForeColor = $colTextMain
    $serviceActionBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $serviceActionBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $serviceActionBtn.Visible = $false
    $serviceActionBtn.Tag = $null
    $serviceActionBtn.Add_Click({
        $info = $this.Tag
        if (-not $info) { return }
        $svcName = $info.ServiceName
        $action  = $info.Action  # "stop" or "start"

        $actionText = if ($action -eq "stop") { "stop and disable" } else { "start and enable" }
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Service: $svcName`n`nAre you sure you want to $actionText this service?",
            "Service Action - Confirm",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        try {
            $tmpScript = [System.IO.Path]::GetTempFileName() + ".ps1"
            $tmpResult = [System.IO.Path]::GetTempFileName()
            if ($action -eq "stop") {
                $scriptContent = @"
try {
    Stop-Service -Name '$svcName' -Force -ErrorAction Stop
    Set-Service -Name '$svcName' -StartupType Disabled -ErrorAction Stop
    'SUCCESS' | Set-Content -Path '$tmpResult' -Encoding UTF8
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Set-Content -Path '$tmpResult' -Encoding UTF8
}
"@
            } else {
                $scriptContent = @"
try {
    Set-Service -Name '$svcName' -StartupType Automatic -ErrorAction Stop
    Start-Service -Name '$svcName' -ErrorAction Stop
    'SUCCESS' | Set-Content -Path '$tmpResult' -Encoding UTF8
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Set-Content -Path '$tmpResult' -Encoding UTF8
}
"@
            }
            $scriptContent | Set-Content -Path $tmpScript -Encoding UTF8
            $p = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpScript`"" -Verb RunAs -PassThru -WindowStyle Hidden -ErrorAction Stop
            $p.WaitForExit(15000)

            if (Test-Path $tmpResult) {
                $result = (Get-Content $tmpResult -Raw).Trim()
                if ($result -eq "SUCCESS") {
                    if ($action -eq "stop") {
                        $this.Text = "Service stopped"
                        $this.BackColor = [System.Drawing.Color]::FromArgb(30, 130, 60)
                        # Switch to reverse action
                        $this.Tag = @{ ServiceName = $svcName; Action = "start" }
                        # After a short delay, offer the reverse action
                        $this.Text = "Start Service"
                        $this.BackColor = [System.Drawing.Color]::FromArgb(40, 100, 180)
                        $this.Enabled = $true
                    } else {
                        $this.Text = "Service started"
                        $this.BackColor = [System.Drawing.Color]::FromArgb(30, 130, 60)
                        $this.Tag = @{ ServiceName = $svcName; Action = "stop" }
                        $this.Text = "Stop Service"
                        $this.BackColor = [System.Drawing.Color]::FromArgb(180, 100, 0)
                        $this.Enabled = $true
                    }
                } else {
                    [System.Windows.Forms.MessageBox]::Show($result, "Service Action - Error", "OK", "Error")
                }
            } else {
                [System.Windows.Forms.MessageBox]::Show("Operation timed out.", "Service Action", "OK", "Warning")
            }
            Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
            Remove-Item $tmpResult -Force -ErrorAction SilentlyContinue
        } catch {
            if ($_.Exception.Message -match "canceled by the user") {
                [System.Windows.Forms.MessageBox]::Show("UAC elevation was cancelled.", "Service Action", "OK", "Information")
            } else {
                [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Service Action - Error", "OK", "Error")
            }
        }
    })
    $detailBox.Controls.Add($serviceActionBtn)

    # Kill Process button
    $script:KillProcessBtn = New-Object System.Windows.Forms.Button
    $killProcessBtn = $script:KillProcessBtn
    $killProcessBtn.Text = "Kill Process"
    $killProcessBtn.Location = New-Object System.Drawing.Point(15, 300)
    $killProcessBtn.Size = New-Object System.Drawing.Size(220, 34)
    $killProcessBtn.FlatStyle = "Flat"
    $killProcessBtn.BackColor = [System.Drawing.Color]::FromArgb(160, 40, 40)
    $killProcessBtn.ForeColor = $colTextMain
    $killProcessBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $killProcessBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $killProcessBtn.Visible = $false
    $killProcessBtn.Tag = $null
    $killProcessBtn.Add_Click({
        $info = $this.Tag
        if (-not $info) { return }
        $pid = $info.PID
        $procName = $info.ProcessName
        $procPath = $info.Path

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Process: $procName`nPID: $pid`nPath: $procPath`n`nAre you sure you want to kill this process?",
            "Kill Process - Confirm",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        try {
            # First try without elevation
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if (-not $proc) {
                $this.Text = "Process not running"
                $this.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
                $this.Enabled = $false
                return
            }
            $proc | Stop-Process -Force -ErrorAction Stop
            $this.Text = "Process killed"
            $this.BackColor = [System.Drawing.Color]::FromArgb(30, 130, 60)
            $this.Enabled = $false
        } catch {
            # Access denied - try with UAC elevation
            try {
                $tmpScript = [System.IO.Path]::GetTempFileName() + ".ps1"
                $tmpResult = [System.IO.Path]::GetTempFileName()
                $scriptContent = @"
try {
    Stop-Process -Id $pid -Force -ErrorAction Stop
    'SUCCESS' | Set-Content -Path '$tmpResult' -Encoding UTF8
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Set-Content -Path '$tmpResult' -Encoding UTF8
}
"@
                $scriptContent | Set-Content -Path $tmpScript -Encoding UTF8
                $p = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpScript`"" -Verb RunAs -PassThru -WindowStyle Hidden -ErrorAction Stop
                $p.WaitForExit(15000)

                if (Test-Path $tmpResult) {
                    $result = (Get-Content $tmpResult -Raw).Trim()
                    if ($result -eq "SUCCESS") {
                        $this.Text = "Process killed (elevated)"
                        $this.BackColor = [System.Drawing.Color]::FromArgb(30, 130, 60)
                        $this.Enabled = $false
                    } else {
                        [System.Windows.Forms.MessageBox]::Show($result, "Kill Process - Error", "OK", "Error")
                    }
                } else {
                    [System.Windows.Forms.MessageBox]::Show("Operation timed out.", "Kill Process", "OK", "Warning")
                }
                Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
                Remove-Item $tmpResult -Force -ErrorAction SilentlyContinue
            } catch {
                if ($_.Exception.Message -match "canceled by the user") {
                    [System.Windows.Forms.MessageBox]::Show("UAC elevation was cancelled.", "Kill Process", "OK", "Information")
                } else {
                    [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Kill Process - Error", "OK", "Error")
                }
            }
        }
    })
    $detailBox.Controls.Add($killProcessBtn)

    # Click on alert row → populate detail panel with auto-sizing
    $alertListView.Add_SelectedIndexChanged({
        try {
            $sel = $this.SelectedItems
            if ($sel.Count -eq 0) { return }
            $idx = $sel[0].Tag
            if ($idx -ge $script:AlertHistory.Count) { return }
            $ad = $script:AlertHistory[$idx]

            $script:DetailTitle.Text = "$($ad.Title)"
            if ($ad.Severity -ne "INFO") {
                $script:DetailTitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 50, 60)
            } else {
                $script:DetailTitle.ForeColor = [System.Drawing.Color]::FromArgb(100, 160, 255)
            }

            $script:DetailContent.SuspendLayout()
            $script:DetailContent.Controls.Clear()
            $dy = 0
            $contentWidth = $script:DetailContent.Width - 20
            $valWidth = [Math]::Max(200, $contentWidth - 155)
            $valFont = New-Object System.Drawing.Font("Consolas", 9)
            $g = $script:DetailContent.CreateGraphics()

            foreach ($key in $ad.Details.Keys) {
                $valText = "$($ad.Details[$key])"

                # Measure text height for auto-wrap
                $measuredSize = $g.MeasureString($valText, $valFont, $valWidth)
                $rowH = [Math]::Max(22, [Math]::Ceiling($measuredSize.Height) + 4)

                $kl = New-Object System.Windows.Forms.Label
                $kl.Text = "${key}:"
                $kl.Location = New-Object System.Drawing.Point(0, $dy)
                $kl.Size = New-Object System.Drawing.Size(148, $rowH)
                $kl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                $kl.ForeColor = [System.Drawing.Color]::FromArgb(100, 160, 255)
                $script:DetailContent.Controls.Add($kl)

                $vl = New-Object System.Windows.Forms.Label
                $vl.Text = $valText
                $vl.Location = New-Object System.Drawing.Point(152, $dy)
                $vl.Size = New-Object System.Drawing.Size($valWidth, $rowH)
                $vl.Font = $valFont
                $vl.ForeColor = [System.Drawing.Color]::White
                $script:DetailContent.Controls.Add($vl)

                $dy += ($rowH + 4)
            }
            $g.Dispose()

            $script:DetailContent.ResumeLayout($true)

            # Auto-resize DetailContent panel to fit all rows
            $script:DetailContent.Height = [Math]::Max(80, $dy + 5)

            # Reposition buttons below content - all left-aligned in rows
            $btnY = $script:DetailContent.Bottom + 12
            $btnX = 15

            # Hide all action buttons first, then selectively show
            $script:IpLookupBtn.Visible = $false
            $script:BlockIpBtn.Visible = $false
            $script:RegeditBtn.Visible = $false
            $script:RestoreRegBtn.Visible = $false
            $script:ServiceActionBtn.Visible = $false
            $script:KillProcessBtn.Visible = $false

            # Row 1: OpenLog is always shown + context buttons
            $script:OpenLogBtn.Location = New-Object System.Drawing.Point($btnX, $btnY)
            $script:OpenLogBtn.Visible = $true
            $nextX = $btnX + $script:OpenLogBtn.Width + 10

            # Show/hide IP lookup button
            if ($ad.RemoteIP) {
                $script:IpLookupBtn.Text = "Lookup $($ad.RemoteIP)"
                $script:IpLookupBtn.Tag = "$($ad.RemoteIP)"
                $script:IpLookupBtn.Location = New-Object System.Drawing.Point($nextX, $btnY)
                $script:IpLookupBtn.Visible = $true
                $nextX += $script:IpLookupBtn.Width + 10
            }

            # Show Regedit button on same row if registry alert
            $regPath = $ad.Details["Registry Path"]
            if ($regPath) {
                $script:RegeditBtn.Tag = $regPath
                $script:RegeditBtn.Location = New-Object System.Drawing.Point($nextX, $btnY)
                $script:RegeditBtn.Visible = $true
            }

            # Row 2: action buttons (Block IP / Restore Registry)
            $btnRow2Y = $btnY + 42

            if ($ad.RemoteIP) {
                $script:BlockIpBtn.Tag = "$($ad.RemoteIP)"
                $script:BlockIpBtn.Location = New-Object System.Drawing.Point($btnX, $btnRow2Y)
                $script:BlockIpBtn.Text = "Block IP (Firewall)"
                $script:BlockIpBtn.BackColor = [System.Drawing.Color]::FromArgb(180, 30, 30)
                $script:BlockIpBtn.Enabled = $true
                $script:BlockIpBtn.Visible = $true
            }

            if ($regPath) {

                # Determine restore action based on alert type
                $valueName = $ad.Details["Value Name"]
                $expected  = $ad.Details["Expected Value"]
                if (-not $expected) { $expected = $ad.Details["Expected"] }
                $actionType = $null
                $btnText = "Restore Registry"

                if ($ad.Details["Action"] -match "should NOT exist" -or $ad.Details["Suggestion"] -match "not normally present|should NOT exist" -or $ad.Details["Threat"] -match "should NOT exist") {
                    # Key itself shouldn't exist → delete key
                    $actionType = "delete_key"
                    $btnText = "Delete Registry Key"
                } elseif ($ad.Details["Added Entries"]) {
                    # Watch-Registry change with before/after → restore snapshot
                    $actionType = "restore_snapshot"
                    $btnText = "Restore to Baseline"
                } elseif ($valueName -and $expected) {
                    # Tampering alert with known expected value → restore value
                    $actionType = "restore_value"
                    $btnText = "Restore to '$expected'"
                } elseif ($valueName -and ($ad.Category -match "Tamper" -or $ad.Title -match "REGISTRY CHANGE")) {
                    # Tampering alert where value shouldn't exist → delete value
                    $badIf = $ad.Details["Current Value"]
                    if ($ad.Details["Action"] -match "should NOT exist" -or $ad.Details["Suggestion"] -match "not normally present" -or $ad.Details["Info"] -match "IFEO|redirect|COM redirect") {
                        $actionType = "delete_value"
                        $btnText = "Delete '$valueName'"
                    } elseif ($expected) {
                        $actionType = "restore_value"
                        $btnText = "Restore '$valueName'"
                    } else {
                        $actionType = "delete_value"
                        $btnText = "Delete '$valueName'"
                    }
                } elseif ($ad.Details["Modified Entries"] -or $ad.Details["Removed Entries"]) {
                    $actionType = "restore_snapshot"
                    $btnText = "Restore to Baseline"
                }

                if ($actionType) {
                    $script:RestoreRegBtn.Tag = @{
                        RegPath   = $regPath
                        ValueName = $valueName
                        Expected  = $expected
                        Action    = $actionType
                    }
                    $script:RestoreRegBtn.Text = $btnText
                    $script:RestoreRegBtn.BackColor = [System.Drawing.Color]::FromArgb(30, 130, 60)
                    $script:RestoreRegBtn.Enabled = $true
                    $restoreX = if ($ad.RemoteIP) { $btnX + $script:BlockIpBtn.Width + 10 } else { $btnX }
                    $script:RestoreRegBtn.Location = New-Object System.Drawing.Point($restoreX, $btnRow2Y)
                    $script:RestoreRegBtn.Visible = $true
                } else {
                    $script:RestoreRegBtn.Visible = $false
                }
            }

            # Show Service Action button if alert has Service Name
            $svcName = $ad.Details["Service Name"]
            if ($svcName -and $ad.Category -eq "Service") {
                $svcStatus = $ad.Details["Status"]
                if ($svcStatus -eq "Running") {
                    $script:ServiceActionBtn.Text = "Stop Service: $svcName"
                    $script:ServiceActionBtn.BackColor = [System.Drawing.Color]::FromArgb(180, 100, 0)
                    $script:ServiceActionBtn.Tag = @{ ServiceName = $svcName; Action = "stop" }
                } else {
                    $script:ServiceActionBtn.Text = "Start Service: $svcName"
                    $script:ServiceActionBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 100, 180)
                    $script:ServiceActionBtn.Tag = @{ ServiceName = $svcName; Action = "start" }
                }
                $script:ServiceActionBtn.Enabled = $true
                $svcX = $btnX
                if ($ad.RemoteIP) { $svcX = $btnX + $script:BlockIpBtn.Width + 10 }
                if ($script:RestoreRegBtn.Visible) { $svcX = $script:RestoreRegBtn.Right + 10 }
                $script:ServiceActionBtn.Location = New-Object System.Drawing.Point($svcX, $btnRow2Y)
                $script:ServiceActionBtn.Visible = $true
            }

            # Show Kill Process button if alert has PID
            $alertPid = $ad.Details["PID"]
            if ($alertPid) {
                $script:KillProcessBtn.Tag = @{
                    PID         = [int]$alertPid
                    ProcessName = $ad.Details["Process Name"]
                    Path        = $ad.Details["Path"]
                }
                $script:KillProcessBtn.Text = "Kill Process (PID: $alertPid)"
                $script:KillProcessBtn.BackColor = [System.Drawing.Color]::FromArgb(160, 40, 40)
                $script:KillProcessBtn.Enabled = $true
                # Position: Row 2, after other visible buttons
                $killX = $btnX
                if ($ad.RemoteIP) { $killX = $btnX + $script:BlockIpBtn.Width + 10 }
                if ($script:RestoreRegBtn.Visible) { $killX = $script:RestoreRegBtn.Right + 10 }
                if ($script:ServiceActionBtn.Visible) { $killX = $script:ServiceActionBtn.Right + 10 }
                $script:KillProcessBtn.Location = New-Object System.Drawing.Point($killX, $btnRow2Y)
                $script:KillProcessBtn.Visible = $true
            }

            # Bring all visible buttons to front
            $script:OpenLogBtn.BringToFront()
            $script:IpLookupBtn.BringToFront()
            $script:RegeditBtn.BringToFront()
            $script:BlockIpBtn.BringToFront()
            $script:RestoreRegBtn.BringToFront()
            $script:ServiceActionBtn.BringToFront()
            $script:KillProcessBtn.BringToFront()
        } catch {}
    })

    # Track how many alerts we've already rendered
    $script:RenderedAlertCount = 0

    # Store alertCountLabel in script scope for timer access
    $script:AlertCountLabel = $alertCountLabel

    # Incremental refresh - only add NEW alerts since last render (script scope for timer access)
    $script:UpdateAlertsListFn = {
        try {
            $total = $script:AlertHistory.Count
            if ($total -eq $script:RenderedAlertCount) { return }

            $script:AlertListView.BeginUpdate()
            $script:RecentList.BeginUpdate()
            for ($i = $script:RenderedAlertCount; $i -lt $total; $i++) {
                $a = $script:AlertHistory[$i]
                $itemColor = switch ($a.Severity) {
                    "CRIT" { [System.Drawing.Color]::FromArgb(255, 80, 90) }
                    "HIGH" { [System.Drawing.Color]::FromArgb(255, 170, 80) }
                    "MED"  { [System.Drawing.Color]::FromArgb(120, 190, 255) }
                    "LOW"  { [System.Drawing.Color]::FromArgb(160, 220, 180) }
                    default { [System.Drawing.Color]::FromArgb(140, 140, 160) }
                }

                $item = New-Object System.Windows.Forms.ListViewItem($a.Timestamp)
                [void]$item.SubItems.Add($a.Severity)
                [void]$item.SubItems.Add($a.Category)
                [void]$item.SubItems.Add($a.Title)
                [void]$item.SubItems.Add($a.Message)
                $item.Tag = $i
                $item.ForeColor = $itemColor
                [void]$script:AlertListView.Items.Insert(0, $item)

                $r = New-Object System.Windows.Forms.ListViewItem($a.Timestamp)
                [void]$r.SubItems.Add($a.Severity)
                [void]$r.SubItems.Add($a.Category)
                [void]$r.SubItems.Add($a.Title)
                [void]$r.SubItems.Add($a.Message)
                $r.Tag = $i
                $r.ForeColor = $itemColor
                [void]$script:RecentList.Items.Insert(0, $r)
                while ($script:RecentList.Items.Count -gt 10) {
                    $script:RecentList.Items.RemoveAt($script:RecentList.Items.Count - 1)
                }
            }
            $script:AlertListView.EndUpdate()
            $script:RecentList.EndUpdate()
            $script:RenderedAlertCount = $total
            $script:AlertCountLabel.Text = "$total alerts"
            $script:LblAlerts.Text = "$($script:AlertCount)"
        } catch {}
    }

  } catch { Write-Console "Alerts page error: $_" "ERROR" }

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 2.5: AI THREATS (behavioral + memory analysis)
    # ═══════════════════════════════════════════════════════════════
  try {
    $aiPage = $pages["AI Threats"]

    $aiPageTitle = New-Object System.Windows.Forms.Label
    $aiPageTitle.Text = "AI Threat Detection"
    $aiPageTitle.Location = New-Object System.Drawing.Point(25, 18)
    $aiPageTitle.Size = New-Object System.Drawing.Size(400, 32)
    $aiPageTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $aiPageTitle.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 255)
    $aiPage.Controls.Add($aiPageTitle)

    $aiPageDesc = New-Object System.Windows.Forms.Label
    $aiPageDesc.Text = "Local behavioral analysis, memory injection scanning, and process anomaly detection"
    $aiPageDesc.Location = New-Object System.Drawing.Point(25, 52)
    $aiPageDesc.Size = New-Object System.Drawing.Size(700, 20)
    $aiPageDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $aiPageDesc.ForeColor = $colTextDim
    $aiPageDesc.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $aiPage.Controls.Add($aiPageDesc)

    # Scan controls panel
    $aiControlPanel = New-Object System.Windows.Forms.Panel
    $aiControlPanel.Location = New-Object System.Drawing.Point(25, 78)
    $aiControlPanel.Size = New-Object System.Drawing.Size(770, 42)
    $aiControlPanel.BackColor = $colCard
    $aiControlPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $aiPage.Controls.Add($aiControlPanel)

    $script:AiScanStatusLabel = New-Object System.Windows.Forms.Label
    $script:AiScanStatusLabel.Text = "Ready to scan"
    $script:AiScanStatusLabel.Location = New-Object System.Drawing.Point(15, 11)
    $script:AiScanStatusLabel.Size = New-Object System.Drawing.Size(400, 20)
    $script:AiScanStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $script:AiScanStatusLabel.ForeColor = $colTextDim
    $aiControlPanel.Controls.Add($script:AiScanStatusLabel)

    $aiPageScanBtn = New-Object System.Windows.Forms.Button
    $aiPageScanBtn.Text = "Run Full Scan"
    $aiPageScanBtn.Location = New-Object System.Drawing.Point(550, 6)
    $aiPageScanBtn.Size = New-Object System.Drawing.Size(100, 30)
    $aiPageScanBtn.FlatStyle = "Flat"
    $aiPageScanBtn.BackColor = [System.Drawing.Color]::FromArgb(100, 60, 180)
    $aiPageScanBtn.ForeColor = [System.Drawing.Color]::White
    $aiPageScanBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $aiPageScanBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $aiPageScanBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $aiPageScanBtn.Add_Click({ try { Start-AiThreatScan } catch {} })
    $aiControlPanel.Controls.Add($aiPageScanBtn)

    $aiClearBtn = New-Object System.Windows.Forms.Button
    $aiClearBtn.Text = "Clear"
    $aiClearBtn.Location = New-Object System.Drawing.Point(660, 6)
    $aiClearBtn.Size = New-Object System.Drawing.Size(100, 30)
    $aiClearBtn.FlatStyle = "Flat"
    $aiClearBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $aiClearBtn.ForeColor = $colTextMain
    $aiClearBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $aiClearBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $aiClearBtn.Add_Click({
        try {
            $script:AiThreatHistory.Clear()
            $script:AiThreatCount = 0
            $script:AiThreatListView.Items.Clear()
            $script:AiThreatDetailContent.Controls.Clear()
            $script:AiThreatDetailTitle.Text = "Select a finding to view details"
            $script:AiThreatDetailTitle.ForeColor = $script:ColTextDim
        } catch {}
    })
    $aiControlPanel.Controls.Add($aiClearBtn)

    # AI Threat ListView
    $script:AiThreatListView = New-Object System.Windows.Forms.ListView
    $aiThreatLv = $script:AiThreatListView
    $aiThreatLv.Name = "aiThreatListView"
    $aiThreatLv.Location = New-Object System.Drawing.Point(25, 128)
    $aiThreatLv.Size = New-Object System.Drawing.Size(770, 260)
    $aiThreatLv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    Style-ListView $aiThreatLv
    [void]$aiThreatLv.Columns.Add("Time", 110)
    [void]$aiThreatLv.Columns.Add("Risk", 55)
    [void]$aiThreatLv.Columns.Add("Engine", 95)
    [void]$aiThreatLv.Columns.Add("Process", 140)
    [void]$aiThreatLv.Columns.Add("Finding", 350)
    $aiThreatLv.Add_Resize({
        try {
            $w = $this.ClientSize.Width - 2
            if ($w -lt 200) { return }
            $this.Columns[0].Width = [Math]::Max(40, [int]($w * 0.14))
            $this.Columns[1].Width = [Math]::Max(40, [int]($w * 0.07))
            $this.Columns[2].Width = [Math]::Max(40, [int]($w * 0.12))
            $this.Columns[3].Width = [Math]::Max(40, [int]($w * 0.19))
            $this.Columns[4].Width = [Math]::Max(40, [int]($w * 0.48))
        } catch {}
    })
    $aiPage.Controls.Add($aiThreatLv)

    # AI Threat Detail Panel
    $aiDetailBox = New-Object System.Windows.Forms.Panel
    $aiDetailBox.Location = New-Object System.Drawing.Point(25, 398)
    $aiDetailBox.Size = New-Object System.Drawing.Size(770, 200)
    $aiDetailBox.BackColor = $colCard
    $aiDetailBox.AutoScroll = $true
    $aiDetailBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $aiPage.Controls.Add($aiDetailBox)

    $script:AiThreatDetailTitle = New-Object System.Windows.Forms.Label
    $script:AiThreatDetailTitle.Text = "Select a finding to view details"
    $script:AiThreatDetailTitle.Location = New-Object System.Drawing.Point(15, 10)
    $script:AiThreatDetailTitle.Size = New-Object System.Drawing.Size(550, 26)
    $script:AiThreatDetailTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $script:AiThreatDetailTitle.ForeColor = $colTextDim
    $aiDetailBox.Controls.Add($script:AiThreatDetailTitle)

    $script:AiThreatDetailContent = New-Object System.Windows.Forms.Panel
    $script:AiThreatDetailContent.Location = New-Object System.Drawing.Point(15, 40)
    $script:AiThreatDetailContent.Size = New-Object System.Drawing.Size(730, 140)
    $script:AiThreatDetailContent.BackColor = $colCard
    $script:AiThreatDetailContent.AutoScroll = $true
    $script:AiThreatDetailContent.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $aiDetailBox.Controls.Add($script:AiThreatDetailContent)

    # Kill Process button for AI Threats
    $script:AiKillBtn = New-Object System.Windows.Forms.Button
    $script:AiKillBtn.Text = "Kill Process"
    $script:AiKillBtn.Size = New-Object System.Drawing.Size(200, 34)
    $script:AiKillBtn.FlatStyle = "Flat"
    $script:AiKillBtn.BackColor = [System.Drawing.Color]::FromArgb(180, 30, 30)
    $script:AiKillBtn.ForeColor = [System.Drawing.Color]::White
    $script:AiKillBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $script:AiKillBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $script:AiKillBtn.Visible = $false
    $script:AiKillBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $script:AiKillBtn.Add_Click({
        try {
            $info = $this.Tag
            if (-not $info) { return }
            $pid = $info.PID
            $procName = $info.ProcessName

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Process: $procName`nPID: $pid`n`nAre you sure you want to kill this process?",
                "Kill Process - Confirm",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            try {
                Stop-Process -Id $pid -Force -ErrorAction Stop
                [System.Windows.Forms.MessageBox]::Show("Process $procName (PID: $pid) terminated.", "Success", "OK", "Information")
                $this.Enabled = $false
                $this.Text = "Process Killed"
            } catch {
                # Try with UAC elevation
                $tmpScript = Join-Path $env:TEMP "kill_proc_$pid.ps1"
                "Stop-Process -Id $pid -Force" | Set-Content $tmpScript -Encoding UTF8
                try {
                    Start-Process powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File', $tmpScript) -Verb RunAs -Wait
                    [System.Windows.Forms.MessageBox]::Show("Process $procName (PID: $pid) terminated (elevated).", "Success", "OK", "Information")
                    $this.Enabled = $false
                    $this.Text = "Process Killed"
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Failed to kill process: $_", "Error", "OK", "Error")
                }
                try { Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue } catch {}
            }
        } catch {}
    })
    $aiDetailBox.Controls.Add($script:AiKillBtn)

    # Selection handler
    $aiThreatLv.Add_SelectedIndexChanged({
        try {
            $sel = $this.SelectedItems
            if ($sel.Count -eq 0) { return }
            $idx = $sel[0].Tag
            if ($idx -ge $script:AiThreatHistory.Count) { return }
            $td = $script:AiThreatHistory[$idx]

            $script:AiThreatDetailTitle.Text = $td.Finding
            $riskColor = switch ($td.Risk) {
                "CRIT" { [System.Drawing.Color]::FromArgb(255, 60, 60) }
                "HIGH" { [System.Drawing.Color]::FromArgb(255, 170, 80) }
                "MED"  { [System.Drawing.Color]::FromArgb(120, 190, 255) }
                default { [System.Drawing.Color]::FromArgb(140, 140, 160) }
            }
            $script:AiThreatDetailTitle.ForeColor = $riskColor

            $script:AiThreatDetailContent.Controls.Clear()
            $dy = 0
            foreach ($key in $td.Details.Keys) {
                $kl = New-Object System.Windows.Forms.Label
                $kl.Text = "${key}:"
                $kl.Location = New-Object System.Drawing.Point(0, $dy)
                $kl.Size = New-Object System.Drawing.Size(130, 20)
                $kl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                $kl.ForeColor = $script:ColAccent
                $script:AiThreatDetailContent.Controls.Add($kl)

                $vl = New-Object System.Windows.Forms.Label
                $vl.Text = "$($td.Details[$key])"
                $vl.Location = New-Object System.Drawing.Point(135, $dy)
                $vl.Size = New-Object System.Drawing.Size(580, 20)
                $vl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $vl.ForeColor = $script:ColTextMain
                $vl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
                $script:AiThreatDetailContent.Controls.Add($vl)
                $dy += 22
            }

            # Show Kill button if finding has PID
            $script:AiKillBtn.Visible = $false
            $pidStr = $td.Details["PID"]
            if (-not $pidStr) {
                # Extract PID from "ProcessName (PID: 1234)" format
                $procField = $td.Details["Process"]
                if ($procField -and $procField -match 'PID:\s*(\d+)') { $pidStr = $Matches[1] }
                $childField = $td.Details["Child Process"]
                if (-not $pidStr -and $childField -and $childField -match 'PID:\s*(\d+)') { $pidStr = $Matches[1] }
            }
            if ($pidStr) {
                $pidInt = [int]$pidStr
                $pName = $td.ProcessName
                if (-not $pName) { $pName = $td.Details["Process"] }
                $script:AiKillBtn.Tag = @{ PID = $pidInt; ProcessName = $pName }
                $script:AiKillBtn.Text = "Kill Process (PID: $pidInt)"
                $script:AiKillBtn.Enabled = $true
                $script:AiKillBtn.Location = New-Object System.Drawing.Point(15, ($dy + 48))
                $script:AiKillBtn.Visible = $true
                $script:AiKillBtn.BringToFront()
            }
        } catch {}
    })

  } catch { Write-Console "AI Threats page error: $_" "ERROR" }

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 3: SETTINGS (notification preferences - live edit)
    # ═══════════════════════════════════════════════════════════════
  try {
    $settingsPage = $pages["Settings"]

    $settingsTitle = New-Object System.Windows.Forms.Label
    $settingsTitle.Text = "Notification Settings"
    $settingsTitle.Location = New-Object System.Drawing.Point(25, 18)
    $settingsTitle.Size = New-Object System.Drawing.Size(400, 32)
    $settingsTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $settingsTitle.ForeColor = $colAccent
    $settingsPage.Controls.Add($settingsTitle)

    $settingsDesc = New-Object System.Windows.Forms.Label
    $settingsDesc.Text = "Enable or disable notification categories. Changes are saved instantly."
    $settingsDesc.Location = New-Object System.Drawing.Point(25, 52)
    $settingsDesc.Size = New-Object System.Drawing.Size(700, 22)
    $settingsDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $settingsDesc.ForeColor = $colTextDim
    $settingsPage.Controls.Add($settingsDesc)

    $options = @(
        @{ Key = "Firmware";   Label = "Firmware Integrity Changes";   Desc = "Driver/firmware file hash modifications, deletions, new files (.sys, .efi, .rom, .bin)";     Icon = "[FW]" },
        @{ Key = "Driver";     Label = "Driver Changes";               Desc = "New drivers loaded or existing drivers removed from the system";                              Icon = "[DR]" },
        @{ Key = "Service";    Label = "New Services";                 Desc = "Newly installed or registered Windows services";                                              Icon = "[SV]" },
        @{ Key = "Connection"; Label = "Unknown Network Connections";  Desc = "Outbound connections from unrecognized/unwhitelisted processes";                               Icon = "[CN]" },
        @{ Key = "Process";    Label = "Unsigned Processes";           Desc = "New processes running without a valid digital signature";                                      Icon = "[PR]" },
        @{ Key = "Listener";   Label = "New Listening Ports";          Desc = "New ports opened for incoming connections by non-system processes";                            Icon = "[LP]" },
        @{ Key = "Registry";   Label = "Registry Startup Key Changes"; Desc = "Modifications to Run/RunOnce registry keys used for persistence";                             Icon = "[RG]" },
        @{ Key = "Security";   Label = "Security Events";             Desc = "Remote logons, failed login attempts, new user accounts, new services in Event Log";           Icon = "[SE]" },
        @{ Key = "RDP";        Label = "Remote Desktop (RDP) Status"; Desc = "Alert when Remote Desktop is enabled on this machine";                                        Icon = "[RD]" },
        @{ Key = "Hosts";      Label = "Hosts File Modifications";    Desc = "Changes to the hosts file that could redirect DNS queries";                                   Icon = "[HF]" }
    )

    $script:SettingsCheckboxes = @{}
    $settingsCheckboxes = $script:SettingsCheckboxes
    $sy = 85
    foreach ($opt in $options) {
        $card = New-Object System.Windows.Forms.Panel
        $card.Location = New-Object System.Drawing.Point(25, $sy)
        $card.Size = New-Object System.Drawing.Size(770, 48)
        $card.BackColor = $colCard
        $card.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $settingsPage.Controls.Add($card)

        $iconLbl = New-Object System.Windows.Forms.Label
        $iconLbl.Text = $opt.Icon
        $iconLbl.Location = New-Object System.Drawing.Point(10, 5)
        $iconLbl.Size = New-Object System.Drawing.Size(40, 20)
        $iconLbl.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
        $iconLbl.ForeColor = $colAccent
        $card.Controls.Add($iconLbl)

        $cb = New-Object System.Windows.Forms.CheckBox
        $cb.Text = $opt.Label
        $cb.Location = New-Object System.Drawing.Point(55, 4)
        $cb.Size = New-Object System.Drawing.Size(350, 22)
        $cb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $cb.ForeColor = $colTextMain
        $cb.BackColor = $colCard
        # Load current config value
        $propVal = $script:NotifyConfig.PSObject.Properties[$opt.Key]
        $cb.Checked = if ($null -eq $propVal) { $true } else { $propVal.Value -eq $true }
        $card.Controls.Add($cb)
        $settingsCheckboxes[$opt.Key] = $cb

        $descLbl = New-Object System.Windows.Forms.Label
        $descLbl.Text = $opt.Desc
        $descLbl.Location = New-Object System.Drawing.Point(55, 27)
        $descLbl.Size = New-Object System.Drawing.Size(700, 17)
        $descLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $descLbl.ForeColor = $colTextDim
        $descLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $card.Controls.Add($descLbl)

        # Instant save on toggle - use Tag to store the config key
        $cb.Tag = $opt.Key
        $cb.Add_CheckedChanged({
            try {
                $senderCb = $this
                $cfgKey = $senderCb.Tag
                $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name $cfgKey -Value $senderCb.Checked -Force
                # Skip individual writes during batch operations (Select All / Deselect All)
                if (-not $script:SuppressSettingsSave) {
                    $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8
                }
            } catch {}
        })

        $sy += 52
    }

    # ── Separator: Display Settings ──
    $sy += 16
    $dispSepLine = New-Object System.Windows.Forms.Panel
    $dispSepLine.Location = New-Object System.Drawing.Point(25, $sy)
    $dispSepLine.Size = New-Object System.Drawing.Size(770, 1)
    $dispSepLine.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $dispSepLine.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($dispSepLine)
    $sy += 12

    $dispTitle = New-Object System.Windows.Forms.Label
    $dispTitle.Text = "Display Settings"
    $dispTitle.Location = New-Object System.Drawing.Point(25, $sy)
    $dispTitle.Size = New-Object System.Drawing.Size(400, 26)
    $dispTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $dispTitle.ForeColor = $colAccent
    $settingsPage.Controls.Add($dispTitle)
    $sy += 30

    # -- Detailed Threat Info toggle --
    $threatCard = New-Object System.Windows.Forms.Panel
    $threatCard.Location = New-Object System.Drawing.Point(25, $sy)
    $threatCard.Size = New-Object System.Drawing.Size(770, 48)
    $threatCard.BackColor = $colCard
    $threatCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($threatCard)

    $threatIcon = New-Object System.Windows.Forms.Label
    $threatIcon.Text = "[!]"
    $threatIcon.Location = New-Object System.Drawing.Point(10, 5)
    $threatIcon.Size = New-Object System.Drawing.Size(40, 20)
    $threatIcon.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
    $threatIcon.ForeColor = [System.Drawing.Color]::FromArgb(255, 170, 80)
    $threatCard.Controls.Add($threatIcon)

    $threatCb = New-Object System.Windows.Forms.CheckBox
    $threatCb.Location = New-Object System.Drawing.Point(8, 24)
    $threatCb.Size = New-Object System.Drawing.Size(18, 18)
    $threatCb.ForeColor = $colTextMain
    $threatCb.BackColor = $colCard
    $propThreat = $script:NotifyConfig.PSObject.Properties["ShowThreatDetails"]
    $threatCb.Checked = if ($null -eq $propThreat) { $false } else { $propThreat.Value -eq $true }
    $threatCard.Controls.Add($threatCb)

    $threatLabel = New-Object System.Windows.Forms.Label
    $threatLabel.Text = "Detailed Threat Info and Severity Levels"
    $threatLabel.Location = New-Object System.Drawing.Point(55, 5)
    $threatLabel.Size = New-Object System.Drawing.Size(500, 20)
    $threatLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $threatLabel.ForeColor = $colTextMain
    $threatCard.Controls.Add($threatLabel)

    $threatDescLbl = New-Object System.Windows.Forms.Label
    $threatDescLbl.Text = "When enabled, shows color-coded severity levels and threat/recommendation details. When off, all alerts appear neutral."
    $threatDescLbl.Location = New-Object System.Drawing.Point(55, 27)
    $threatDescLbl.Size = New-Object System.Drawing.Size(700, 17)
    $threatDescLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $threatDescLbl.ForeColor = $colTextDim
    $threatDescLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $threatCard.Controls.Add($threatDescLbl)

    $threatCb.Tag = "ShowThreatDetails"
    $threatCb.Add_CheckedChanged({
        try {
            $senderCb = $this
            $cfgKey = $senderCb.Tag
            $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name $cfgKey -Value $senderCb.Checked -Force
            if (-not $script:SuppressSettingsSave) {
                $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8
            }
        } catch {}
    })
    $sy += 52

    # -- Windows Notifications toggle --
    $toastCard = New-Object System.Windows.Forms.Panel
    $toastCard.Location = New-Object System.Drawing.Point(25, $sy)
    $toastCard.Size = New-Object System.Drawing.Size(770, 48)
    $toastCard.BackColor = $colCard
    $toastCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($toastCard)

    $toastIcon = New-Object System.Windows.Forms.Label
    $toastIcon.Text = "[N]"
    $toastIcon.Location = New-Object System.Drawing.Point(10, 5)
    $toastIcon.Size = New-Object System.Drawing.Size(40, 20)
    $toastIcon.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
    $toastIcon.ForeColor = [System.Drawing.Color]::FromArgb(120, 190, 255)
    $toastCard.Controls.Add($toastIcon)

    $toastCb = New-Object System.Windows.Forms.CheckBox
    $toastCb.Location = New-Object System.Drawing.Point(8, 24)
    $toastCb.Size = New-Object System.Drawing.Size(18, 18)
    $toastCb.ForeColor = $colTextMain
    $toastCb.BackColor = $colCard
    $propToast = $script:NotifyConfig.PSObject.Properties["EnableToastNotifications"]
    $toastCb.Checked = if ($null -eq $propToast) { $true } else { $propToast.Value -eq $true }
    $toastCard.Controls.Add($toastCb)

    $toastLabel = New-Object System.Windows.Forms.Label
    $toastLabel.Text = "Windows Desktop Notifications"
    $toastLabel.Location = New-Object System.Drawing.Point(55, 5)
    $toastLabel.Size = New-Object System.Drawing.Size(500, 20)
    $toastLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $toastLabel.ForeColor = $colTextMain
    $toastCard.Controls.Add($toastLabel)

    $toastDescLbl = New-Object System.Windows.Forms.Label
    $toastDescLbl.Text = "Show Windows toast/balloon notifications for alerts. When off, alerts are still logged and visible in the Alerts tab."
    $toastDescLbl.Location = New-Object System.Drawing.Point(55, 27)
    $toastDescLbl.Size = New-Object System.Drawing.Size(700, 17)
    $toastDescLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $toastDescLbl.ForeColor = $colTextDim
    $toastDescLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $toastCard.Controls.Add($toastDescLbl)

    $toastCb.Tag = "EnableToastNotifications"
    $toastCb.Add_CheckedChanged({
        try {
            $senderCb = $this
            $cfgKey = $senderCb.Tag
            $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name $cfgKey -Value $senderCb.Checked -Force
            if (-not $script:SuppressSettingsSave) {
                $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8
            }
        } catch {}
    })
    $sy += 52

    # AI Threat Detection — removed from settings (always available, on-demand from AI Threats tab)

    $savedLabel = New-Object System.Windows.Forms.Label
    $savedLabel.Text = "Settings are saved automatically"
    $savedLabel.Location = New-Object System.Drawing.Point(25, ($sy + 16))
    $savedLabel.Size = New-Object System.Drawing.Size(300, 20)
    $savedLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $savedLabel.ForeColor = $colGreen
    $settingsPage.Controls.Add($savedLabel)

    $sy += 52

    # ══════════════════════════════════════════════════════════════════
    #  FIREWALL & NETWORK SETTINGS SECTION
    # ══════════════════════════════════════════════════════════════════
    $sy += 8
    $fwSepLine = New-Object System.Windows.Forms.Panel
    $fwSepLine.Location = New-Object System.Drawing.Point(25, $sy)
    $fwSepLine.Size = New-Object System.Drawing.Size(770, 1)
    $fwSepLine.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $fwSepLine.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($fwSepLine)
    $sy += 12

    $fwTitle = New-Object System.Windows.Forms.Label
    $fwTitle.Text = "Firewall & Network Protection"
    $fwTitle.Location = New-Object System.Drawing.Point(25, $sy)
    $fwTitle.Size = New-Object System.Drawing.Size(400, 26)
    $fwTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $fwTitle.ForeColor = [System.Drawing.Color]::FromArgb(255, 100, 80)
    $settingsPage.Controls.Add($fwTitle)
    $sy += 30

    $fwSubtitle = New-Object System.Windows.Forms.Label
    $fwSubtitle.Text = "These settings require admin privileges. A UAC prompt will appear for each change."
    $fwSubtitle.Location = New-Object System.Drawing.Point(25, $sy)
    $fwSubtitle.Size = New-Object System.Drawing.Size(770, 18)
    $fwSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $fwSubtitle.ForeColor = $colTextDim
    $fwSubtitle.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($fwSubtitle)
    $sy += 22

    # Error label for firewall operations
    $script:FWErrorLabel = New-Object System.Windows.Forms.Label
    $script:FWErrorLabel.Text = ""
    $script:FWErrorLabel.Location = New-Object System.Drawing.Point(25, $sy)
    $script:FWErrorLabel.Size = New-Object System.Drawing.Size(770, 16)
    $script:FWErrorLabel.Font = New-Object System.Drawing.Font("Segoe UI", 7.5)
    $script:FWErrorLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 100, 80)
    $script:FWErrorLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($script:FWErrorLabel)
    $sy += 18

    # State tracking for firewall operations
    $script:FWCheckboxes = @{}
    $script:FWStatusDots = @{}
    $script:FWPendingOps = @{}
    $script:FWRetryCount = @{}
    $script:LastFWError = ""
    $script:SuppressSettingsSave = $false

    # Save-Config helper
    function Save-Config {
        try { $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8 } catch {}
    }

    # --- Elevated PowerShell helper (async — no GUI freeze) ---
    # Launches elevated PS, then polls result via 500ms timer. Calls $OnComplete scriptblock with result.
    # Check once at setup time if we are already elevated
    $script:IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Verify scripts — per-setting verification expressions run inside the elevated process
    $script:VerifyScripts = @{
        'FW_DomainProfile'  = '$p = Get-NetFirewallProfile -Name Domain -EA SilentlyContinue; $null -ne $p -and $p.Enabled -eq {0}'
        'FW_PrivateProfile' = '$p = Get-NetFirewallProfile -Name Private -EA SilentlyContinue; $null -ne $p -and $p.Enabled -eq {0}'
        'FW_PublicProfile'  = '$p = Get-NetFirewallProfile -Name Public -EA SilentlyContinue; $null -ne $p -and $p.Enabled -eq {0}'
        'FW_BlockInbound'   = '$r = Get-NetFirewallRule -DisplayName "SecurityMonitor_BlockAllInbound" -EA SilentlyContinue; ($null -ne $r) -eq {0}'
        'FW_BlockOutbound'  = '$r = Get-NetFirewallRule -DisplayName "SecurityMonitor_BlockAllOutbound" -EA SilentlyContinue; ($null -ne $r) -eq {0}'
        'FW_BlockPing'      = '$r = Get-NetFirewallRule -DisplayName "SecurityMonitor_BlockICMP" -EA SilentlyContinue; ($null -ne $r) -eq {0}'
        'FW_BlockLAN'       = '$r = Get-NetFirewallRule -DisplayName "SecurityMonitor_BlockLAN_In_192" -EA SilentlyContinue; ($null -ne $r) -eq {0}'
        'FW_BlockDevices'   = '$r = Get-NetFirewallRule -DisplayName "SecurityMonitor_BlockDev_SMB_In" -EA SilentlyContinue; ($null -ne $r) -eq {0}'
        'PF_BlockTrackers'  = '$h = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw -EA SilentlyContinue; if ({0}) {{ $h -match "SecurityMonitor-Trackers-Start" }} else {{ $h -notmatch "SecurityMonitor-Trackers-Start" }}'
        'PF_BlockMalware'   = '$h = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw -EA SilentlyContinue; if ({0}) {{ $h -match "SecurityMonitor-Malware-Start" }} else {{ $h -notmatch "SecurityMonitor-Malware-Start" }}'
        'PF_BlockTelemetry' = '$h = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw -EA SilentlyContinue; if ({0}) {{ $h -match "SecurityMonitor-Telemetry-Start" }} else {{ $h -notmatch "SecurityMonitor-Telemetry-Start" }}'
        'PF_BlockDNSBypass' = '$r = Get-NetFirewallRule -DisplayName "SecurityMonitor_DNSLock_Out" -EA SilentlyContinue; ($null -ne $r) -eq {0}'
        'DNS_DoH'           = 'if ({0}) {{ $ok = $false; foreach ($a in (Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" -and $_.Virtual -eq $false }})) {{ $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($a.InterfaceGuid)\DohInterfaceSettings\Doh"); if ($k) {{ $n = $k.GetSubKeyNames(); $k.Close(); if ($n.Count -gt 0) {{ $ok = $true; break }} }} }}; $ok }} else {{ $clean = $true; foreach ($a in (Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" -and $_.Virtual -eq $false }})) {{ $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($a.InterfaceGuid)\DohInterfaceSettings\Doh"); if ($k) {{ $n = $k.GetSubKeyNames(); $k.Close(); if ($n.Count -gt 0) {{ $clean = $false; break }} }} }}; $clean }}'
        'DNS_Provider'      = ''
    }

    # Callback data storage — eliminates need for .GetNewClosure() which breaks .NET type resolution in PS 5.1
    $script:FWCallbackData = @{}

    $script:InvokeElevatedFWAsync = {
        param([string]$ScriptContent, [string]$ActionName, [scriptblock]$OnComplete, [string]$VerifyScript = '')
        $tmpForScript = [System.IO.Path]::GetTempFileName()
        $scriptFile = $tmpForScript -replace '\.tmp$', '.ps1'
        Remove-Item $tmpForScript -Force -ErrorAction SilentlyContinue
        $resultFile = [System.IO.Path]::GetTempFileName()
        $escapedResultFile = $resultFile -replace "'", "''"
        if ($VerifyScript -ne '') {
            $wrappedScript = @"
try {
    $ScriptContent
    Start-Sleep -Milliseconds 500
    `$pass1 = & { $VerifyScript }
    Start-Sleep -Milliseconds 800
    `$pass2 = & { $VerifyScript }
    if (`$pass1 -and `$pass2) {
        'VERIFIED' | Out-File -FilePath '$escapedResultFile' -Encoding UTF8
    } else {
        'SUCCESS' | Out-File -FilePath '$escapedResultFile' -Encoding UTF8
    }
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Out-File -FilePath '$escapedResultFile' -Encoding UTF8
}
"@
        } else {
            $wrappedScript = @"
try {
    $ScriptContent
    'SUCCESS' | Out-File -FilePath '$escapedResultFile' -Encoding UTF8
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Out-File -FilePath '$escapedResultFile' -Encoding UTF8
}
"@
        }
        [System.IO.File]::WriteAllText($scriptFile, $wrappedScript)
        try {
            if ($script:IsElevated) {
                $proc = Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $scriptFile -PassThru -ErrorAction Stop
            } else {
                $proc = Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $scriptFile -Verb RunAs -PassThru -ErrorAction Stop
            }
        } catch {
            if (Test-Path $scriptFile) { Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue }
            if (Test-Path $resultFile) { Remove-Item $resultFile -Force -ErrorAction SilentlyContinue }
            Write-Console "[$ActionName] UAC cancelled or elevation failed: $($_.Exception.Message)" "ERROR"
            & $OnComplete $ActionName "ERROR: UAC cancelled or elevation failed: $($_.Exception.Message)"
            return
        }
        Write-Console "[$ActionName] Elevated script started (PID: $($proc.Id))" "DEBUG"
        # Poll timer — uses $this.Tag instead of .GetNewClosure() to avoid PS 5.1 module scope issues
        $pollTimer = New-Object System.Windows.Forms.Timer
        $pollTimer.Interval = 500
        $pollTimer.Tag = @{ Proc = $proc; ResultFile = $resultFile; ScriptFile = $scriptFile; OnComplete = $OnComplete; ActionName = $ActionName }
        $pollTimer.Add_Tick({
            $d = $this.Tag
            try {
                if ($d.Proc.HasExited) {
                    $this.Stop()
                    $this.Dispose()
                    $result = "ERROR: No result file"
                    if (Test-Path $d.ResultFile) {
                        $rawContent = Get-Content $d.ResultFile -Raw -ErrorAction SilentlyContinue
                        if ($rawContent) { $result = $rawContent.Trim() -replace '^\uFEFF', '' }
                        Remove-Item $d.ResultFile -Force -ErrorAction SilentlyContinue
                    }
                    if (Test-Path $d.ScriptFile) { Remove-Item $d.ScriptFile -Force -ErrorAction SilentlyContinue }
                    Write-Console "[$($d.ActionName)] Result: $result" $(if ($result -match '^VERIFIED') { "OK" } elseif ($result -match '^SUCCESS') { "WARN" } else { "ERROR" })
                    & $d.OnComplete $d.ActionName $result
                }
            } catch {
                $this.Stop()
                $this.Dispose()
                Write-Console "[$($d.ActionName)] Poll exception: $($_.Exception.Message)" "ERROR"
                try { & $d.OnComplete $d.ActionName "ERROR: Poll exception: $($_.Exception.Message)" } catch {}
            }
        })
        $pollTimer.Start()
    }

    # --- Firewall Profile Settings ---
    $fwProfileItems = @(
        @{ Key = "FW_DomainProfile";  Label = "Domain Firewall Profile";  Desc = "Enable Windows Firewall for domain networks"; Icon = "[FW]" }
        @{ Key = "FW_PrivateProfile"; Label = "Private Firewall Profile"; Desc = "Enable Windows Firewall for private/home networks"; Icon = "[FW]" }
        @{ Key = "FW_PublicProfile";  Label = "Public Firewall Profile";  Desc = "Enable Windows Firewall for public networks"; Icon = "[FW]" }
    )

    # --- Firewall Block Rules ---
    $fwBlockItems = @(
        @{ Key = "FW_BlockInbound";  Label = "Block All Inbound";  Desc = "Block all incoming connections except explicitly allowed"; Icon = "[BL]" }
        @{ Key = "FW_BlockOutbound"; Label = "Block All Outbound"; Desc = "Block all outgoing connections (strict mode - may break apps)"; Icon = "[BL]" }
        @{ Key = "FW_BlockPing";     Label = "Block ICMP Ping";    Desc = "Block incoming ping requests (invisible to ping scans)"; Icon = "[BL]" }
        @{ Key = "FW_BlockLAN";      Label = "Block LAN Traffic";  Desc = "Block all local network traffic (192.168.x.x, 10.x.x.x, 172.16-31.x.x) - isolates from LAN"; Icon = "[BL]" }
        @{ Key = "FW_BlockDevices";  Label = "Block Device Connections"; Desc = "Block SMB/NetBIOS/LLMNR/mDNS - prevents network device discovery and file sharing"; Icon = "[BL]" }
    )

    # --- Privacy & Filtering ---
    $fwPrivacyItems = @(
        @{ Key = "PF_BlockTrackers";  Label = "Block Trackers (Hosts)";   Desc = "Block known tracking domains via hosts file"; Icon = "[PF]" }
        @{ Key = "PF_BlockMalware";   Label = "Block Malware (Hosts)";    Desc = "Block known malware domains via hosts file"; Icon = "[PF]" }
        @{ Key = "PF_BlockTelemetry"; Label = "Block Telemetry (Hosts)";  Desc = "Block Windows and third-party telemetry domains via hosts file"; Icon = "[PF]" }
        @{ Key = "PF_BlockDNSBypass"; Label = "Prevent DNS Bypass";       Desc = "Lock port 53 - block DNS traffic except configured DNS"; Icon = "[PF]" }
    )

    $allFWItems = $fwProfileItems + $fwBlockItems + $fwPrivacyItems

    foreach ($item in $allFWItems) {
        $fwCard = New-Object System.Windows.Forms.Panel
        $fwCard.Location = New-Object System.Drawing.Point(25, $sy)
        $fwCard.Size = New-Object System.Drawing.Size(770, 48)
        $fwCard.BackColor = $colCard
        $fwCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $settingsPage.Controls.Add($fwCard)

        # Status dot (green=active, red=inactive, orange=pending, gray=unknown)
        $statusDot = New-Object System.Windows.Forms.Panel
        $statusDot.Location = New-Object System.Drawing.Point(745, 18)
        $statusDot.Size = New-Object System.Drawing.Size(12, 12)
        $statusDot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100)
        $fwCard.Controls.Add($statusDot)

        $fwIcon = New-Object System.Windows.Forms.Label
        $fwIcon.Text = $item.Icon
        $fwIcon.Location = New-Object System.Drawing.Point(10, 5)
        $fwIcon.Size = New-Object System.Drawing.Size(40, 20)
        $fwIcon.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
        $fwIcon.ForeColor = if ($item.Icon -eq '[BL]') { [System.Drawing.Color]::FromArgb(255, 100, 80) } elseif ($item.Icon -eq '[PF]') { [System.Drawing.Color]::FromArgb(180, 120, 255) } else { $colAccent }
        $fwCard.Controls.Add($fwIcon)

        $fwCb = New-Object System.Windows.Forms.CheckBox
        $fwCb.Text = $item.Label
        $fwCb.Location = New-Object System.Drawing.Point(55, 4)
        $fwCb.Size = New-Object System.Drawing.Size(350, 22)
        $fwCb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $fwCb.ForeColor = $colTextMain
        $fwCb.BackColor = $colCard
        $fwCb.Tag = $item.Key
        # Load from config (default false for all FW settings)
        $propVal = $script:NotifyConfig.PSObject.Properties[$item.Key]
        $fwCb.Checked = if ($null -eq $propVal) { $false } else { $propVal.Value -eq $true }
        $fwCard.Controls.Add($fwCb)
        $script:FWCheckboxes[$item.Key] = $fwCb
        $script:FWStatusDots[$item.Key] = $statusDot

        $fwDescLbl = New-Object System.Windows.Forms.Label
        $fwDescLbl.Text = $item.Desc
        $fwDescLbl.Location = New-Object System.Drawing.Point(55, 27)
        $fwDescLbl.Size = New-Object System.Drawing.Size(680, 17)
        $fwDescLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $fwDescLbl.ForeColor = $colTextDim
        $fwDescLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $fwCard.Controls.Add($fwDescLbl)

        # --- Checkbox event handler ---
        $fwCb.Add_CheckedChanged({
            try {
                if ($script:SuppressSettingsSave) { return }
                $cfgKey = $this.Tag
                $isChecked = $this.Checked
                $dot = $script:FWStatusDots[$cfgKey]

                # Retry guard: max 2 consecutive failures per setting
                if (-not $script:FWRetryCount.ContainsKey($cfgKey)) { $script:FWRetryCount[$cfgKey] = 0 }
                if ($script:FWRetryCount[$cfgKey] -ge 2) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Maximum retry attempts (2) reached for this setting.`nPlease restart the application or resolve the issue manually.",
                        "Retry Limit",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                    return
                }

                # Pending operation guard
                if ($script:FWPendingOps.ContainsKey($cfgKey) -and $script:FWPendingOps[$cfgKey]) { return }
                $script:FWPendingOps[$cfgKey] = $true

                # Pessimistic: revert checkbox immediately, flip only on verified success
                try {
                    $script:SuppressSettingsSave = $true
                    $this.Checked = (-not $isChecked)
                } finally { $script:SuppressSettingsSave = $false }
                # Set dot to orange (pending operation)
                if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 60) }

                # Block All Outbound special warning
                if ($cfgKey -eq 'FW_BlockOutbound' -and $isChecked) {
                    $warnResult = [System.Windows.Forms.MessageBox]::Show(
                        "WARNING: This will block ALL outgoing traffic.`n`nMost applications will stop working. Only enable this if you have explicit allow rules configured.`n`nContinue?",
                        "Block All Outbound - Confirm",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                    if ($warnResult -ne [System.Windows.Forms.DialogResult]::Yes) {
                        if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100) }
                        $script:FWPendingOps[$cfgKey] = $false
                        return
                    }
                }

                # Block LAN Traffic special warning
                if ($cfgKey -eq 'FW_BlockLAN' -and $isChecked) {
                    $warnResult = [System.Windows.Forms.MessageBox]::Show(
                        "WARNING: This will block ALL local network traffic (192.168.x.x, 10.x.x.x, 172.16-31.x.x).`n`nYou will lose access to:`n- Local file shares and printers`n- Router admin panel`n- Other LAN devices`n`nInternet access will continue to work.`n`nContinue?",
                        "Block LAN Traffic - Confirm",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                    if ($warnResult -ne [System.Windows.Forms.DialogResult]::Yes) {
                        if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100) }
                        $script:FWPendingOps[$cfgKey] = $false
                        return
                    }
                }

                # DNS mutual exclusion is handled in OnComplete callback after verified success

                # Build the elevated script content based on config key
                $elevatedScript = $null
                switch ($cfgKey) {
                    'FW_DomainProfile'  { $elevatedScript = if ($isChecked) { "Set-NetFirewallProfile -Name Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow" } else { "Set-NetFirewallProfile -Name Domain -Enabled False" } }
                    'FW_PrivateProfile' { $elevatedScript = if ($isChecked) { "Set-NetFirewallProfile -Name Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow" } else { "Set-NetFirewallProfile -Name Private -Enabled False" } }
                    'FW_PublicProfile'  { $elevatedScript = if ($isChecked) { "Set-NetFirewallProfile -Name Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow" } else { "Set-NetFirewallProfile -Name Public -Enabled False" } }
                    'FW_BlockInbound' {
                        if ($isChecked) {
                            $elevatedScript = @'
Set-NetFirewallProfile -All -DefaultInboundAction Block -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllInbound' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllInbound' -Direction Inbound -Action Block -Protocol Any -Profile Any -ErrorAction Stop | Out-Null
& "$PSScriptRoot\SmWfpEngine.ps1" -Action BlockInbound 2>&1 | Out-Null
'@
                        } else {
                            $elevatedScript = @'
Set-NetFirewallProfile -All -DefaultInboundAction Allow -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllInbound' -ErrorAction SilentlyContinue
& "$PSScriptRoot\SmWfpEngine.ps1" -Action UnblockInbound 2>&1 | Out-Null
'@
                        }
                    }
                    'FW_BlockOutbound' {
                        if ($isChecked) {
                            $elevatedScript = @'
Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllOutbound' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllOutbound' -Direction Outbound -Action Block -Protocol Any -Profile Any -ErrorAction Stop | Out-Null
& "$PSScriptRoot\SmWfpEngine.ps1" -Action BlockOutbound 2>&1 | Out-Null
'@
                        } else {
                            $elevatedScript = @'
Set-NetFirewallProfile -All -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllOutbound' -ErrorAction SilentlyContinue
& "$PSScriptRoot\SmWfpEngine.ps1" -Action UnblockOutbound 2>&1 | Out-Null
'@
                        }
                    }
                    'FW_BlockPing' {
                        if ($isChecked) {
                            $elevatedScript = @'
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_BlockICMP' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockICMP' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
'@
                        } else {
                            $elevatedScript = @'
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_BlockICMP' -ErrorAction SilentlyContinue
'@
                        }
                    }
                    'FW_BlockLAN' {
                        if ($isChecked) {
                            $elevatedScript = @'
Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_In_192' -Direction Inbound -Action Block -RemoteAddress '192.168.0.0/16' -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_Out_192' -Direction Outbound -Action Block -RemoteAddress '192.168.0.0/16' -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_In_10' -Direction Inbound -Action Block -RemoteAddress '10.0.0.0/8' -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_Out_10' -Direction Outbound -Action Block -RemoteAddress '10.0.0.0/8' -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_In_172' -Direction Inbound -Action Block -RemoteAddress '172.16.0.0/12' -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_Out_172' -Direction Outbound -Action Block -RemoteAddress '172.16.0.0/12' -Profile Any -ErrorAction SilentlyContinue | Out-Null
'@
                        } else {
                            $elevatedScript = @'
Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
'@
                        }
                    }
                    'FW_BlockDevices' {
                        if ($isChecked) {
                            $elevatedScript = @'
# Layer 1: Windows Firewall rules
Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_SMB_In' -Direction Inbound -Protocol TCP -LocalPort @(445,139) -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_SMB_Out' -Direction Outbound -Protocol TCP -RemotePort @(445,139) -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_NetBIOS_In' -Direction Inbound -Protocol UDP -LocalPort @(137,138) -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_NetBIOS_Out' -Direction Outbound -Protocol UDP -RemotePort @(137,138) -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_LLMNR_In' -Direction Inbound -Protocol UDP -LocalPort 5355 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_LLMNR_Out' -Direction Outbound -Protocol UDP -RemotePort 5355 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_mDNS_In' -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_mDNS_Out' -Direction Outbound -Protocol UDP -RemotePort 5353 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_SSDP_In' -Direction Inbound -Protocol UDP -LocalPort 1900 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_SSDP_Out' -Direction Outbound -Protocol UDP -RemotePort 1900 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_UPnP_In' -Direction Inbound -Protocol TCP -LocalPort 2869 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_UPnP_Out' -Direction Outbound -Protocol TCP -RemotePort 2869 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Layer 2: OS-level service/registry blocking (completely firewall-independent)
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -ErrorAction SilentlyContinue
}
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 0 -Type DWord -ErrorAction SilentlyContinue
Stop-Service SSDPSRV -Force -ErrorAction SilentlyContinue
Set-Service SSDPSRV -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service upnphost -Force -ErrorAction SilentlyContinue
Set-Service upnphost -StartupType Disabled -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
'@
                        } else {
                            $elevatedScript = @'
Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 0 -Type DWord -ErrorAction SilentlyContinue
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 1 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 1 -Type DWord -ErrorAction SilentlyContinue
Set-Service SSDPSRV -StartupType Manual -ErrorAction SilentlyContinue
Set-Service upnphost -StartupType Manual -ErrorAction SilentlyContinue
'@
                        }
                    }
                    'PF_BlockTrackers' {
                        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
                        if ($isChecked) {
                            $lines = @("`n# SecurityMonitor-Trackers-Start")
                            foreach ($d in $script:TrackerDomains) { $lines += "0.0.0.0 $d" }
                            $lines += "# SecurityMonitor-Trackers-End"
                            $content = $lines -join "`n"
                            $elevatedScript = @"
`$hostsFile = '$hostsPath'
`$h = Get-Content `$hostsFile -Raw -ErrorAction SilentlyContinue
if (`$h -match 'SecurityMonitor-Trackers-Start') {
    `$h = `$h -replace '(?s)\r?\n?# SecurityMonitor-Trackers-Start.*?# SecurityMonitor-Trackers-End\r?\n?', ''
    Set-Content -Path `$hostsFile -Value `$h -Encoding ASCII -NoNewline
}
Add-Content -Path `$hostsFile -Value '$($content -replace "'","''")' -Encoding ASCII
ipconfig /flushdns | Out-Null
"@
                        } else {
                            $elevatedScript = @"
`$h = Get-Content '$hostsPath' -Raw -ErrorAction Stop
if ([string]::IsNullOrEmpty(`$h)) { `$h = '' }
`$h = `$h -replace '(?s)\r?\n?# SecurityMonitor-Trackers-Start.*?# SecurityMonitor-Trackers-End\r?\n?', ''
Set-Content -Path '$hostsPath' -Value `$h -Encoding ASCII -NoNewline
ipconfig /flushdns | Out-Null
"@
                        }
                    }
                    'PF_BlockMalware' {
                        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
                        if ($isChecked) {
                            $lines = @("`n# SecurityMonitor-Malware-Start")
                            foreach ($d in $script:MalwareDomains) { $lines += "0.0.0.0 $d" }
                            $lines += "# SecurityMonitor-Malware-End"
                            $content = $lines -join "`n"
                            $elevatedScript = @"
`$hostsFile = '$hostsPath'
`$h = Get-Content `$hostsFile -Raw -ErrorAction SilentlyContinue
if (`$h -match 'SecurityMonitor-Malware-Start') {
    `$h = `$h -replace '(?s)\r?\n?# SecurityMonitor-Malware-Start.*?# SecurityMonitor-Malware-End\r?\n?', ''
    Set-Content -Path `$hostsFile -Value `$h -Encoding ASCII -NoNewline
}
Add-Content -Path `$hostsFile -Value '$($content -replace "'","''")' -Encoding ASCII
ipconfig /flushdns | Out-Null
"@
                        } else {
                            $elevatedScript = @"
`$h = Get-Content '$hostsPath' -Raw -ErrorAction Stop
if ([string]::IsNullOrEmpty(`$h)) { `$h = '' }
`$h = `$h -replace '(?s)\r?\n?# SecurityMonitor-Malware-Start.*?# SecurityMonitor-Malware-End\r?\n?', ''
Set-Content -Path '$hostsPath' -Value `$h -Encoding ASCII -NoNewline
ipconfig /flushdns | Out-Null
"@
                        }
                    }
                    'PF_BlockTelemetry' {
                        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
                        if ($isChecked) {
                            $lines = @("`n# SecurityMonitor-Telemetry-Start")
                            foreach ($d in $script:TelemetryDomains) { $lines += "0.0.0.0 $d" }
                            $lines += "# SecurityMonitor-Telemetry-End"
                            $content = $lines -join "`n"
                            $elevatedScript = @"
`$hostsFile = '$hostsPath'
`$h = Get-Content `$hostsFile -Raw -ErrorAction SilentlyContinue
if (`$h -match 'SecurityMonitor-Telemetry-Start') {
    `$h = `$h -replace '(?s)\r?\n?# SecurityMonitor-Telemetry-Start.*?# SecurityMonitor-Telemetry-End\r?\n?', ''
    Set-Content -Path `$hostsFile -Value `$h -Encoding ASCII -NoNewline
}
Add-Content -Path `$hostsFile -Value '$($content -replace "'","''")' -Encoding ASCII
ipconfig /flushdns | Out-Null
"@
                        } else {
                            $elevatedScript = @"
`$h = Get-Content '$hostsPath' -Raw -ErrorAction Stop
if ([string]::IsNullOrEmpty(`$h)) { `$h = '' }
`$h = `$h -replace '(?s)\r?\n?# SecurityMonitor-Telemetry-Start.*?# SecurityMonitor-Telemetry-End\r?\n?', ''
Set-Content -Path '$hostsPath' -Value `$h -Encoding ASCII -NoNewline
ipconfig /flushdns | Out-Null
"@
                        }
                    }
                    'PF_BlockDNSBypass' {
                        $dnsSecureCb = $script:FWCheckboxes['DNS_DoH']
                        if ($isChecked -and $dnsSecureCb -and -not $dnsSecureCb.Checked) {
                            $warnResult = [System.Windows.Forms.MessageBox]::Show(
                                "WARNING: Secure DNS (DoH) is not active. Blocking DNS bypass without DoH may break internet connectivity.`n`nContinue?",
                                "DNS Bypass Warning",
                                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                                [System.Windows.Forms.MessageBoxIcon]::Warning)
                            if ($warnResult -ne [System.Windows.Forms.DialogResult]::Yes) {
                                if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100) }
                                $script:FWPendingOps[$cfgKey] = $false
                                return
                            }
                        }
                        if ($isChecked) {
                            $elevatedScript = @'
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_TCP' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_Out' -Direction Outbound -Protocol UDP -RemotePort 53 -Action Block -Profile Any -ErrorAction Stop | Out-Null
New-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_TCP' -Direction Outbound -Protocol TCP -RemotePort 53 -Action Block -Profile Any -ErrorAction Stop | Out-Null
'@
                        } else {
                            $elevatedScript = @'
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_TCP' -ErrorAction SilentlyContinue
'@
                        }
                    }
                }

                if ($null -ne $elevatedScript) {
                    Write-Console "[$cfgKey] Toggling to $isChecked..." "INFO"
                    # Store callback data in script-scope (avoids .GetNewClosure() PS 5.1 issues)
                    $script:FWCallbackData[$cfgKey] = @{
                        Key = $cfgKey; Checked = $isChecked; Cb = $this; Dot = $dot
                        RetryCount = $script:FWRetryCount; PendingOps = $script:FWPendingOps
                        NotifyConfig = $script:NotifyConfig; SaveConfig = ${function:Save-Config}
                        ErrorLabel = $script:FWErrorLabel
                        ColorGreen = [System.Drawing.Color]::FromArgb(0, 200, 100)
                        ColorRed = [System.Drawing.Color]::FromArgb(220, 50, 60)
                        ColorOrange = [System.Drawing.Color]::FromArgb(255, 160, 40)
                        ColorError = [System.Drawing.Color]::FromArgb(255, 60, 60)
                    }

                    # Build verify expression for this key
                    $verifyExpr = ''
                    if ($script:VerifyScripts.ContainsKey($cfgKey)) {
                        $verifyExpr = $script:VerifyScripts[$cfgKey] -f $(if ($isChecked) { '$true' } else { '$false' })
                    }

                    & $script:InvokeElevatedFWAsync -ScriptContent $elevatedScript -ActionName $cfgKey -VerifyScript $verifyExpr -OnComplete {
                        param($actionName, $result)
                        $d = $script:FWCallbackData[$actionName]
                        if (-not $d) { return }
                        try {
                            if ($result -match '^VERIFIED') {
                                $d.RetryCount[$actionName] = 0
                                try { $d.Cb.Checked = $d.Checked } catch {}
                                $d.NotifyConfig | Add-Member -MemberType NoteProperty -Name $actionName -Value $d.Checked -Force
                                try { & $d.SaveConfig } catch {}
                                if ($d.Dot) {
                                    if ($d.Checked) { $d.Dot.BackColor = $d.ColorGreen } else { $d.Dot.BackColor = $d.ColorRed }
                                }
                                if ($d.ErrorLabel) { $d.ErrorLabel.Text = "" }
                                Write-Console "[$actionName] Verified and applied (checked=$($d.Checked))" "OK"
                                $d.PendingOps[$actionName] = $false
                            } elseif ($result -match '^SUCCESS') {
                                try { $d.Cb.Checked = $d.Checked } catch {}
                                $d.NotifyConfig | Add-Member -MemberType NoteProperty -Name $actionName -Value $d.Checked -Force
                                try { & $d.SaveConfig } catch {}
                                if ($d.Dot) { $d.Dot.BackColor = $d.ColorOrange }
                                if ($d.ErrorLabel) { $d.ErrorLabel.Text = "$actionName applied but verification failed" }
                                Write-Console "[$actionName] Applied but verification failed" "WARN"
                                $d.PendingOps[$actionName] = $false
                            } else {
                                $d.RetryCount[$actionName] = ($d.RetryCount[$actionName] + 1)
                                if ($d.Dot) { $d.Dot.BackColor = $d.ColorError }
                                if ($d.ErrorLabel) { $d.ErrorLabel.Text = "Failed: $actionName - $result" }
                                Write-Console "[$actionName] Failed: $result" "ERROR"
                                $d.PendingOps[$actionName] = $false
                            }
                        } catch {
                            if ($d.Dot) { $d.Dot.BackColor = $d.ColorError }
                            if ($d.ErrorLabel) { $d.ErrorLabel.Text = "Error: $actionName - $($_.Exception.Message)" }
                            Write-Console "[$actionName] Callback error: $($_.Exception.Message)" "ERROR"
                            $d.PendingOps[$actionName] = $false
                        }
                    }
                } else {
                    $script:FWPendingOps[$cfgKey] = $false
                    if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100) }
                }
            } catch {
                $script:FWPendingOps[$this.Tag] = $false
                $script:LastFWError = "$($this.Tag): $($_.Exception.Message)"
                if ($script:FWErrorLabel) { $script:FWErrorLabel.Text = $script:LastFWError }
                Write-Console "[$($this.Tag)] Handler error: $($_.Exception.Message)" "ERROR"
            }
        })

        $sy += 52
    }

    # ── DNS Settings ──
    $sy += 8
    $dnsSepLine = New-Object System.Windows.Forms.Panel
    $dnsSepLine.Location = New-Object System.Drawing.Point(25, $sy)
    $dnsSepLine.Size = New-Object System.Drawing.Size(770, 1)
    $dnsSepLine.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $dnsSepLine.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($dnsSepLine)
    $sy += 12

    $dnsTitle = New-Object System.Windows.Forms.Label
    $dnsTitle.Text = "DNS & Secure DNS"
    $dnsTitle.Location = New-Object System.Drawing.Point(25, $sy)
    $dnsTitle.Size = New-Object System.Drawing.Size(400, 26)
    $dnsTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $dnsTitle.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 255)
    $settingsPage.Controls.Add($dnsTitle)
    $sy += 30

    # DNS Provider ComboBox
    $dnsProviderCard = New-Object System.Windows.Forms.Panel
    $dnsProviderCard.Location = New-Object System.Drawing.Point(25, $sy)
    $dnsProviderCard.Size = New-Object System.Drawing.Size(770, 48)
    $dnsProviderCard.BackColor = $colCard
    $dnsProviderCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($dnsProviderCard)

    $dnsProvIcon = New-Object System.Windows.Forms.Label
    $dnsProvIcon.Text = "[DNS]"
    $dnsProvIcon.Location = New-Object System.Drawing.Point(10, 14)
    $dnsProvIcon.Size = New-Object System.Drawing.Size(45, 20)
    $dnsProvIcon.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
    $dnsProvIcon.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 255)
    $dnsProviderCard.Controls.Add($dnsProvIcon)

    $dnsProvLabel = New-Object System.Windows.Forms.Label
    $dnsProvLabel.Text = "DNS Provider:"
    $dnsProvLabel.Location = New-Object System.Drawing.Point(55, 14)
    $dnsProvLabel.Size = New-Object System.Drawing.Size(110, 20)
    $dnsProvLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $dnsProvLabel.ForeColor = $colTextMain
    $dnsProviderCard.Controls.Add($dnsProvLabel)

    $script:DnsProviderCombo = New-Object System.Windows.Forms.ComboBox
    $script:DnsProviderCombo.Location = New-Object System.Drawing.Point(170, 11)
    $script:DnsProviderCombo.Size = New-Object System.Drawing.Size(200, 26)
    $script:DnsProviderCombo.DropDownStyle = 'DropDownList'
    $script:DnsProviderCombo.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 60)
    $script:DnsProviderCombo.ForeColor = $colTextMain
    $script:DnsProviderCombo.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dnsProviderItems = @("None (System Default)", "Cloudflare (1.1.1.1)", "Quad9 (9.9.9.9)", "Google (8.8.8.8)", "OpenDNS (208.67.222.222)", "AdGuard (94.140.14.14)")
    $script:DnsProviderCombo.Items.AddRange($dnsProviderItems)
    $script:DnsProviderConfigMap = @{
        'None'      = "None (System Default)"
        'Cloudflare'= "Cloudflare (1.1.1.1)"
        'Quad9'     = "Quad9 (9.9.9.9)"
        'Google'    = "Google (8.8.8.8)"
        'OpenDNS'   = "OpenDNS (208.67.222.222)"
        'AdGuard'   = "AdGuard (94.140.14.14)"
    }
    $script:DnsProviderReverseMap = @{
        "None (System Default)"      = @{ Name = 'None';       Primary = $null; Secondary = $null; Primary6 = $null; Secondary6 = $null; DohTemplate = $null }
        "Cloudflare (1.1.1.1)"       = @{ Name = 'Cloudflare'; Primary = '1.1.1.1'; Secondary = '1.0.0.1'; Primary6 = '2606:4700:4700::1111'; Secondary6 = '2606:4700:4700::1001'; DohTemplate = 'https://cloudflare-dns.com/dns-query' }
        "Quad9 (9.9.9.9)"            = @{ Name = 'Quad9';      Primary = '9.9.9.9'; Secondary = '149.112.112.112'; Primary6 = '2620:fe::fe'; Secondary6 = '2620:fe::9'; DohTemplate = 'https://dns.quad9.net/dns-query' }
        "Google (8.8.8.8)"           = @{ Name = 'Google';      Primary = '8.8.8.8'; Secondary = '8.8.4.4'; Primary6 = '2001:4860:4860::8888'; Secondary6 = '2001:4860:4860::8844'; DohTemplate = 'https://dns.google/dns-query' }
        "OpenDNS (208.67.222.222)"   = @{ Name = 'OpenDNS';    Primary = '208.67.222.222'; Secondary = '208.67.220.220'; Primary6 = '2620:119:35::35'; Secondary6 = '2620:119:53::53'; DohTemplate = 'https://doh.opendns.com/dns-query' }
        "AdGuard (94.140.14.14)"     = @{ Name = 'AdGuard';    Primary = '94.140.14.14'; Secondary = '94.140.15.15'; Primary6 = '2a10:50c0::ad1:ff'; Secondary6 = '2a10:50c0::ad2:ff'; DohTemplate = 'https://dns.adguard-dns.com/dns-query' }
    }
    # Load current provider from config (suppress event handler during initial load)
    $currentProvider = 'None'
    $propDNS = $script:NotifyConfig.PSObject.Properties['DNS_Provider']
    if ($propDNS) { $currentProvider = $propDNS.Value }
    try {
        $script:SuppressSettingsSave = $true
        if ($script:DnsProviderConfigMap.ContainsKey($currentProvider)) {
            $script:DnsProviderCombo.SelectedItem = $script:DnsProviderConfigMap[$currentProvider]
        } else {
            $script:DnsProviderCombo.SelectedIndex = 0
        }
    } finally { $script:SuppressSettingsSave = $false }
    $script:DnsProviderCombo.Tag = $script:DnsProviderCombo.SelectedItem
    $dnsProviderCard.Controls.Add($script:DnsProviderCombo)

    # DNS Provider status dot
    $dnsProvDot = New-Object System.Windows.Forms.Panel
    $dnsProvDot.Location = New-Object System.Drawing.Point(745, 18)
    $dnsProvDot.Size = New-Object System.Drawing.Size(12, 12)
    $dnsProvDot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100)
    $dnsProviderCard.Controls.Add($dnsProvDot)
    $script:FWStatusDots['DNS_Provider'] = $dnsProvDot

    $script:DnsProviderCombo.Add_SelectedIndexChanged({
        try {
            if ($script:SuppressSettingsSave) { return }

            # Pending operation guard - prevent concurrent DNS changes
            if ($script:FWPendingOps.ContainsKey('DNS_Provider') -and $script:FWPendingOps['DNS_Provider']) { return }
            $script:FWPendingOps['DNS_Provider'] = $true
            Write-Console "[DNS_Provider] Changing to: $($script:DnsProviderCombo.SelectedItem)" "INFO"

            $previousSelectedItem = $script:DnsProviderCombo.Tag
            $selectedItem = $script:DnsProviderCombo.SelectedItem.ToString()
            $provInfo = $script:DnsProviderReverseMap[$selectedItem]
            if (-not $provInfo) { $script:FWPendingOps['DNS_Provider'] = $false; return }
            $provName = $provInfo.Name
            $dot = $script:FWStatusDots['DNS_Provider']
            if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 60) }
            # Pessimistic: revert combo immediately, restore only on verified success
            try { $script:SuppressSettingsSave = $true; $script:DnsProviderCombo.SelectedItem = $previousSelectedItem } finally { $script:SuppressSettingsSave = $false }

            if ($provName -eq 'None') {
                # Reset DNS to DHCP (both IPv4 and IPv6)
                $elevatedScript = @'
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
}
'@
            } else {
                $pri = $provInfo.Primary
                $sec = $provInfo.Secondary
                $pri6 = $provInfo.Primary6
                $sec6 = $provInfo.Secondary6
                $elevatedScript = @"
`$adapters = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' -and `$_.Virtual -eq `$false }
`$success = `$false
foreach (`$adapter in `$adapters) {
    try {
        `$allAddrs = @('$pri','$sec','$pri6','$sec6') | Where-Object { `$_ -and `$_ -ne '' }
        try {
            Set-DnsClientServerAddress -InterfaceIndex `$adapter.ifIndex -ServerAddresses `$allAddrs -ErrorAction Stop
        } catch {
            `$v4Only = @('$pri','$sec') | Where-Object { `$_ -and `$_ -ne '' }
            Set-DnsClientServerAddress -InterfaceIndex `$adapter.ifIndex -ServerAddresses `$v4Only -ErrorAction Stop
        }
        `$success = `$true
    } catch {}
}
if (-not `$success) { throw "No adapter could be configured" }
"@
            }

            $script:FWCallbackData['DNS_Provider'] = @{
                ProvName = $provName; Dot = $dot; NotifyConfig = $script:NotifyConfig
                SaveConfig = ${function:Save-Config}; ErrorLabel = $script:FWErrorLabel
                PendingOps = $script:FWPendingOps; DohCb = $script:FWCheckboxes['DNS_DoH']
                DnsCombo = $script:DnsProviderCombo; ConfigMap = $script:DnsProviderConfigMap
                ColorGreen = [System.Drawing.Color]::FromArgb(0, 200, 100)
                ColorGrey = [System.Drawing.Color]::FromArgb(80, 80, 100)
                ColorOrange = [System.Drawing.Color]::FromArgb(255, 160, 40)
                ColorError = [System.Drawing.Color]::FromArgb(255, 60, 60)
            }

            # Build verify expression for DNS_Provider (built directly to avoid -f format escaping issues)
            if ($provName -eq 'None') {
                $verifyExpr = @'
$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false } | Select-Object -First 1
if (-not $a) { $true; return }
$dns = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -EA SilentlyContinue).ServerAddresses
$known = @('1.1.1.1','9.9.9.9','8.8.8.8','208.67.222.222','94.140.14.14')
$hasKnown = $false
foreach ($k in $known) { if ($dns -contains $k) { $hasKnown = $true; break } }
-not $hasKnown
'@
            } else {
                $verifyPrimary = $provInfo.Primary
                $verifyExpr = @"
`$a = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' -and `$_.Virtual -eq `$false } | Select-Object -First 1
if (-not `$a) { `$false; return }
`$dns = (Get-DnsClientServerAddress -InterfaceIndex `$a.ifIndex -AddressFamily IPv4 -EA SilentlyContinue).ServerAddresses
`$dns -contains '$verifyPrimary'
"@
            }

            & $script:InvokeElevatedFWAsync -ScriptContent $elevatedScript -ActionName "DNS_Provider" -VerifyScript $verifyExpr -OnComplete {
                param($actionName, $result)
                $d = $script:FWCallbackData[$actionName]
                if (-not $d) { return }
                try {
                    if ($result -match '^VERIFIED') {
                        try { $d.DnsCombo.SelectedItem = $d.ConfigMap[$d.ProvName] } catch {}
                        $d.DnsCombo.Tag = $d.DnsCombo.SelectedItem
                        $d.NotifyConfig | Add-Member -MemberType NoteProperty -Name 'DNS_Provider' -Value $d.ProvName -Force
                        try { & $d.SaveConfig } catch {}
                        if ($d.Dot) {
                            if ($d.ProvName -ne 'None') { $d.Dot.BackColor = $d.ColorGreen } else { $d.Dot.BackColor = $d.ColorGrey }
                        }
                        if ($d.ErrorLabel) { $d.ErrorLabel.Text = "" }
                        if ($d.DohCb) {
                            if ($d.ProvName -eq 'None') { $d.DohCb.Checked = $false; $d.DohCb.Enabled = $false }
                            else {
                                $d.DohCb.Enabled = $true
                                # Re-apply DoH if it was active (DNS changed, DoH needs new provider IPs)
                                if ($d.DohCb.Checked) {
                                    Write-Console "[DNS_Provider] DoH is active, re-applying for new provider..." "INFO"
                                    try { $script:SuppressSettingsSave = $true; $d.DohCb.Checked = $false } finally { $script:SuppressSettingsSave = $false }
                                    $d.DohCb.Checked = $true
                                }
                            }
                        }
                        Write-Console "[DNS_Provider] Verified: $($d.ProvName)" "OK"
                    } elseif ($result -match '^SUCCESS') {
                        try { $d.DnsCombo.SelectedItem = $d.ConfigMap[$d.ProvName] } catch {}
                        $d.DnsCombo.Tag = $d.DnsCombo.SelectedItem
                        $d.NotifyConfig | Add-Member -MemberType NoteProperty -Name 'DNS_Provider' -Value $d.ProvName -Force
                        try { & $d.SaveConfig } catch {}
                        if ($d.Dot) { $d.Dot.BackColor = $d.ColorOrange }
                        if ($d.ErrorLabel) { $d.ErrorLabel.Text = "DNS applied but verification pending" }
                        if ($d.DohCb) {
                            if ($d.ProvName -eq 'None') { $d.DohCb.Checked = $false; $d.DohCb.Enabled = $false }
                            else {
                                $d.DohCb.Enabled = $true
                                if ($d.DohCb.Checked) {
                                    Write-Console "[DNS_Provider] DoH is active, re-applying for new provider..." "INFO"
                                    $d.DohCb.Checked = $false
                                    $d.DohCb.Checked = $true
                                }
                            }
                        }
                        Write-Console "[DNS_Provider] Applied but verify failed" "WARN"
                    } else {
                        if ($d.Dot) { $d.Dot.BackColor = $d.ColorError }
                        if ($d.ErrorLabel) { $d.ErrorLabel.Text = "DNS change failed: $result" }
                        Write-Console "[DNS_Provider] Failed: $result" "ERROR"
                    }
                } catch {
                    if ($d.Dot) { $d.Dot.BackColor = $d.ColorError }
                    if ($d.ErrorLabel) { $d.ErrorLabel.Text = "DNS error: $($_.Exception.Message)" }
                    Write-Console "[DNS_Provider] Callback error: $($_.Exception.Message)" "ERROR"
                }
                $d.PendingOps['DNS_Provider'] = $false
            }
        } catch {
            $script:FWPendingOps['DNS_Provider'] = $false
            if ($script:FWErrorLabel) { $script:FWErrorLabel.Text = "DNS: $($_.Exception.Message)" }
            Write-Console "[DNS_Provider] Handler error: $($_.Exception.Message)" "ERROR"
        }
    })
    $sy += 52

    # --- DNS over HTTPS (DoH) toggle ---
    $dohCard = New-Object System.Windows.Forms.Panel
    $dohCard.Location = New-Object System.Drawing.Point(25, $sy)
    $dohCard.Size = New-Object System.Drawing.Size(770, 48)
    $dohCard.BackColor = $colCard
    $dohCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($dohCard)

    $dohDot = New-Object System.Windows.Forms.Panel
    $dohDot.Location = New-Object System.Drawing.Point(745, 18)
    $dohDot.Size = New-Object System.Drawing.Size(12, 12)
    $dohDot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 100)
    $dohCard.Controls.Add($dohDot)
    $script:FWStatusDots['DNS_DoH'] = $dohDot

    $dohIcon = New-Object System.Windows.Forms.Label
    $dohIcon.Text = "[DoH]"
    $dohIcon.Location = New-Object System.Drawing.Point(10, 5)
    $dohIcon.Size = New-Object System.Drawing.Size(45, 20)
    $dohIcon.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
    $dohIcon.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 255)
    $dohCard.Controls.Add($dohIcon)

    $dohCb = New-Object System.Windows.Forms.CheckBox
    $dohCb.Text = "DNS over HTTPS (DoH)"
    $dohCb.Location = New-Object System.Drawing.Point(55, 4)
    $dohCb.Size = New-Object System.Drawing.Size(350, 22)
    $dohCb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $dohCb.ForeColor = $colTextMain
    $dohCb.BackColor = $colCard
    $dohCb.Tag = "DNS_DoH"
    $propDoH = $script:NotifyConfig.PSObject.Properties['DNS_DoH']
    $dohCb.Checked = if ($null -eq $propDoH) { $false } else { $propDoH.Value -eq $true }
    # Disable DoH checkbox if no DNS provider is selected
    if ($currentProvider -eq 'None') { $dohCb.Enabled = $false }
    $dohCard.Controls.Add($dohCb)
    $script:FWCheckboxes['DNS_DoH'] = $dohCb

    $dohDescLbl = New-Object System.Windows.Forms.Label
    $dohDescLbl.Text = "Encrypt DNS queries using HTTPS. Requires a supported DNS provider above."
    $dohDescLbl.Location = New-Object System.Drawing.Point(55, 27)
    $dohDescLbl.Size = New-Object System.Drawing.Size(680, 17)
    $dohDescLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $dohDescLbl.ForeColor = $colTextDim
    $dohDescLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $dohCard.Controls.Add($dohDescLbl)

    $dohCb.Add_CheckedChanged({
        try {
            if ($script:SuppressSettingsSave) { return }
            if ($script:FWPendingOps.ContainsKey('DNS_DoH') -and $script:FWPendingOps['DNS_DoH']) { return }

            # Guard: DoH requires a DNS provider to be selected
            $selectedDns = $script:DnsProviderCombo.SelectedItem.ToString()
            $dnsInfo = $script:DnsProviderReverseMap[$selectedDns]
            if ($this.Checked -and ($null -eq $dnsInfo -or $dnsInfo.Name -eq 'None')) {
                try { $script:SuppressSettingsSave = $true; $this.Checked = $false } finally { $script:SuppressSettingsSave = $false }
                if ($script:FWErrorLabel) { $script:FWErrorLabel.Text = "Select a DNS provider before enabling DoH" }
                return
            }

            $script:FWPendingOps['DNS_DoH'] = $true
            Write-Console "[DNS_DoH] Toggling to $($this.Checked)..." "INFO"

            $isChecked = $this.Checked
            # Pessimistic: revert checkbox immediately, flip only on verified success
            try { $script:SuppressSettingsSave = $true; $this.Checked = (-not $isChecked) } finally { $script:SuppressSettingsSave = $false }
            $dot = $script:FWStatusDots['DNS_DoH']
            if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 60) }

            if ($isChecked) {
                $dohTemplate = if ($dnsInfo -and $dnsInfo.DohTemplate) { $dnsInfo.DohTemplate } else { '' }
                $pri = if ($dnsInfo) { $dnsInfo.Primary } else { '' }
                $sec = if ($dnsInfo) { $dnsInfo.Secondary } else { '' }
                $pri6 = if ($dnsInfo) { $dnsInfo.Primary6 } else { '' }
                $sec6 = if ($dnsInfo) { $dnsInfo.Secondary6 } else { '' }
                $elevatedScript = @"
`$allServers = @('$pri','$sec','$pri6','$sec6') | Where-Object { `$_ }

# Register DoH server templates via Windows API (handles both IPv4 and IPv6)
foreach (`$srv in `$allServers) {
    try {
        `$existing = Get-DnsClientDohServerAddress -ServerAddress `$srv -ErrorAction SilentlyContinue
        if (`$existing) {
            Set-DnsClientDohServerAddress -ServerAddress `$srv -DohTemplate '$dohTemplate' -AllowFallbackToUdp `$false -AutoUpgrade `$true -ErrorAction Stop
        } else {
            Add-DnsClientDohServerAddress -ServerAddress `$srv -DohTemplate '$dohTemplate' -AllowFallbackToUdp `$false -AutoUpgrade `$true -ErrorAction Stop
        }
    } catch {}
}

`$adapters = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' -and `$_.Virtual -eq `$false }
foreach (`$adapter in `$adapters) {
    # Set DNS addresses
    try { Set-DnsClientServerAddress -InterfaceIndex `$adapter.ifIndex -ServerAddresses `$allServers -ErrorAction Stop } catch {}

    # Clean old DoH entries first, then write fresh ones for current provider only
    `$guid = `$adapter.InterfaceGuid
    `$regBase = "SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\`$guid\DohInterfaceSettings"
    `$dohKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("`$regBase\Doh", `$true)
    if (`$dohKey) {
        foreach (`$old in `$dohKey.GetSubKeyNames()) { try { `$dohKey.DeleteSubKeyTree(`$old) } catch {} }
        `$dohKey.Close()
    }

    # Write DohFlags=1 + DohTemplate for each current server IP
    `$regDoh = "`$regBase\Doh"
    foreach (`$srv in `$allServers) {
        `$subKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("`$regDoh\`$srv")
        `$subKey.SetValue('DohFlags', [long]1, [Microsoft.Win32.RegistryValueKind]::QWord)
        `$subKey.SetValue('DohTemplate', '$dohTemplate', [Microsoft.Win32.RegistryValueKind]::String)
        `$subKey.Close()
    }
}

ipconfig /flushdns | Out-Null
try { Restart-Service Dnscache -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Milliseconds 1500
"@
            } else {
                $pri = if ($dnsInfo) { $dnsInfo.Primary } else { '' }
                $sec = if ($dnsInfo) { $dnsInfo.Secondary } else { '' }
                $pri6 = if ($dnsInfo) { $dnsInfo.Primary6 } else { '' }
                $sec6 = if ($dnsInfo) { $dnsInfo.Secondary6 } else { '' }
                $elevatedScript = @"
# Remove per-adapter DoH registry (resets Windows Settings dropdown to "Off")
`$adapters = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' -and `$_.Virtual -eq `$false }
foreach (`$adapter in `$adapters) {
    `$guid = `$adapter.InterfaceGuid
    `$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\`$guid\DohInterfaceSettings"
    Remove-Item -LiteralPath `$basePath -Recurse -Force -ErrorAction SilentlyContinue
}

ipconfig /flushdns | Out-Null
try { Restart-Service Dnscache -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Milliseconds 1500
"@
            }

            $script:FWCallbackData['DNS_DoH'] = @{
                Checked = $isChecked; Dot = $dot; Cb = $this
                NotifyConfig = $script:NotifyConfig; SaveConfig = ${function:Save-Config}
                ErrorLabel = $script:FWErrorLabel; PendingOps = $script:FWPendingOps
                ColorGreen = [System.Drawing.Color]::FromArgb(0, 200, 100)
                ColorRed = [System.Drawing.Color]::FromArgb(220, 50, 60)
                ColorOrange = [System.Drawing.Color]::FromArgb(255, 160, 40)
                ColorError = [System.Drawing.Color]::FromArgb(255, 60, 60)
            }

            # Build verify expression for DNS_DoH
            $verifyExpr = $script:VerifyScripts['DNS_DoH'] -f $(if ($isChecked) { '$true' } else { '$false' })

            & $script:InvokeElevatedFWAsync -ScriptContent $elevatedScript -ActionName "DNS_DoH" -VerifyScript $verifyExpr -OnComplete {
                param($actionName, $result)
                $d = $script:FWCallbackData[$actionName]
                if (-not $d) { return }
                try {
                    if ($result -match '^VERIFIED') {
                        try { $d.Cb.Checked = $d.Checked } catch {}
                        $d.NotifyConfig | Add-Member -MemberType NoteProperty -Name 'DNS_DoH' -Value $d.Checked -Force
                        try { & $d.SaveConfig } catch {}
                        if ($d.Dot) {
                            if ($d.Checked) { $d.Dot.BackColor = $d.ColorGreen } else { $d.Dot.BackColor = $d.ColorRed }
                        }
                        if ($d.ErrorLabel) { $d.ErrorLabel.Text = "" }
                        Write-Console "[DNS_DoH] Verified (checked=$($d.Checked))" "OK"
                        $d.PendingOps['DNS_DoH'] = $false
                    } elseif ($result -match '^SUCCESS') {
                        try { $d.Cb.Checked = $d.Checked } catch {}
                        $d.NotifyConfig | Add-Member -MemberType NoteProperty -Name 'DNS_DoH' -Value $d.Checked -Force
                        try { & $d.SaveConfig } catch {}
                        if ($d.Dot) { $d.Dot.BackColor = $d.ColorOrange }
                        if ($d.ErrorLabel) { $d.ErrorLabel.Text = "DoH applied but verification failed" }
                        Write-Console "[DNS_DoH] Applied but verify failed" "WARN"
                        $d.PendingOps['DNS_DoH'] = $false
                    } else {
                        if ($d.Dot) { $d.Dot.BackColor = $d.ColorError }
                        if ($d.ErrorLabel) { $d.ErrorLabel.Text = "DoH change failed: $result" }
                        Write-Console "[DNS_DoH] Failed: $result" "ERROR"
                        $d.PendingOps['DNS_DoH'] = $false
                    }
                } catch {
                    if ($d.Dot) { $d.Dot.BackColor = $d.ColorError }
                    if ($d.ErrorLabel) { $d.ErrorLabel.Text = "DoH error: $($_.Exception.Message)" }
                    Write-Console "[DNS_DoH] Callback error: $($_.Exception.Message)" "ERROR"
                    $d.PendingOps['DNS_DoH'] = $false
                }
            }
        } catch {
            if ($dot) { $dot.BackColor = [System.Drawing.Color]::FromArgb(255, 60, 60) }
            $script:LastFWError = "DNS_DoH: $($_.Exception.Message)"
            $script:FWPendingOps['DNS_DoH'] = $false
            Write-Console "[DNS_DoH] Handler error: $($_.Exception.Message)" "ERROR"
        }
    })

    $sy += 52
    $sy += 8

    # --- Background status detection (periodic, every 15 seconds) ---
    $script:LaunchStatusJob = {
        $script:FWStatusJob = Start-Job -ScriptBlock {
            $results = @{}
            try {
                $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                foreach ($p in $profiles) {
                    switch ($p.Name) {
                        'Domain'  { $results['FW_DomainProfile']  = $p.Enabled }
                        'Private' { $results['FW_PrivateProfile'] = $p.Enabled }
                        'Public'  { $results['FW_PublicProfile']  = $p.Enabled }
                    }
                }
                $anyProfile = $profiles | Select-Object -First 1
                if ($anyProfile) {
                    $inboundRule = Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllInbound' -ErrorAction SilentlyContinue
                    $results['FW_BlockInbound']  = ($anyProfile.DefaultInboundAction -eq 'Block') -or ($null -ne $inboundRule)
                    $outboundRule = Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockAllOutbound' -ErrorAction SilentlyContinue
                    $results['FW_BlockOutbound'] = ($anyProfile.DefaultOutboundAction -eq 'Block') -or ($null -ne $outboundRule)
                }
                $icmpRule = Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockICMP' -ErrorAction SilentlyContinue
                $results['FW_BlockPing'] = ($null -ne $icmpRule)
                $lanRule = Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockLAN_In_192' -ErrorAction SilentlyContinue
                $results['FW_BlockLAN'] = ($null -ne $lanRule)
                $devRule = Get-NetFirewallRule -DisplayName 'SecurityMonitor_BlockDev_SMB_In' -ErrorAction SilentlyContinue
                $llmnrDisabled = $false
                try {
                    $llmnrReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue
                    $llmnrDisabled = ($null -ne $llmnrReg -and $llmnrReg.EnableMulticast -eq 0)
                } catch {}
                $ssdpDisabled = ((Get-Service SSDPSRV -ErrorAction SilentlyContinue).StartType -eq 'Disabled')
                $results['FW_BlockDevices'] = ($null -ne $devRule) -or $llmnrDisabled -or $ssdpDisabled
            } catch {}
            try {
                # Check per-adapter DoH flags via .NET Registry API (Get-ChildItem breaks on IPv6 colons)
                $adapterDoH = $false
                $physAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }
                foreach ($pa in $physAdapters) {
                    $regPath = "SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($pa.InterfaceGuid)\DohInterfaceSettings\Doh"
                    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath)
                    if ($regKey) {
                        $subKeys = $regKey.GetSubKeyNames()
                        $regKey.Close()
                        if ($subKeys.Count -gt 0) { $adapterDoH = $true; break }
                    }
                }
                $results['DNS_DoH'] = $adapterDoH
            } catch { $results['DNS_DoH'] = $false }
            try {
                $physicalAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }
                $dnsServers = @()
                foreach ($pa in $physicalAdapters) {
                    $dnsServers += (Get-DnsClientServerAddress -InterfaceIndex $pa.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
                    $dnsServers += (Get-DnsClientServerAddress -InterfaceIndex $pa.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
                }
                $results['DNS_Provider'] = if ($dnsServers -contains '1.1.1.1') { 'Cloudflare' }
                    elseif ($dnsServers -contains '9.9.9.9') { 'Quad9' }
                    elseif ($dnsServers -contains '8.8.8.8') { 'Google' }
                    elseif ($dnsServers -contains '208.67.222.222') { 'OpenDNS' }
                    elseif ($dnsServers -contains '94.140.14.14') { 'AdGuard' }
                    else { 'None' }
            } catch {}
            try {
                $hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw -ErrorAction SilentlyContinue
                $results['PF_BlockTrackers']  = ($hostsContent -match 'SecurityMonitor-Trackers-Start')
                $results['PF_BlockMalware']   = ($hostsContent -match 'SecurityMonitor-Malware-Start')
                $results['PF_BlockTelemetry'] = ($hostsContent -match 'SecurityMonitor-Telemetry-Start')
            } catch {}
            try {
                $dnsLock = Get-NetFirewallRule -DisplayName 'SecurityMonitor_DNSLock_Out' -ErrorAction SilentlyContinue
                $results['PF_BlockDNSBypass'] = ($null -ne $dnsLock)
            } catch {}
            return $results
        }
    }

    try {
        $script:FWStatusLastLaunch = [DateTime]::Now
        & $script:LaunchStatusJob

        $script:FWStatusTimer = New-Object System.Windows.Forms.Timer
        $script:FWStatusTimer.Interval = 500
        $script:FWStatusTimer.Add_Tick({
            try {
                if ($script:FWStatusJob -and $script:FWStatusJob.State -in @('Completed','Failed')) {
                    Write-Console "[StatusJob] Completed (state=$($script:FWStatusJob.State))" "DEBUG"
                    $statusResults = Receive-Job -Job $script:FWStatusJob -ErrorAction SilentlyContinue
                    Remove-Job -Job $script:FWStatusJob -Force -ErrorAction SilentlyContinue
                    $script:FWStatusJob = $null
                    $script:FWRetryCount = @{}
                    # Clear completed pending ops (don't replace hashtable — callbacks hold references)
                    $keysToRemove = @($script:FWPendingOps.Keys | Where-Object { -not $script:FWPendingOps[$_] })
                    foreach ($k in $keysToRemove) { $script:FWPendingOps.Remove($k) }
                    if ($statusResults -is [hashtable]) {
                        try {
                            $script:SuppressSettingsSave = $true
                            foreach ($key in $statusResults.Keys) {
                                # Skip keys with active pending operations to avoid overwriting in-flight changes
                                if ($script:FWPendingOps.ContainsKey($key) -and $script:FWPendingOps[$key]) { continue }
                                $val = $statusResults[$key]
                                if ($key -eq 'DNS_Provider') {
                                    $providerName = [string]$val
                                    $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name 'DNS_Provider' -Value $providerName -Force
                                    if ($script:DnsProviderConfigMap.ContainsKey($providerName)) {
                                        $script:DnsProviderCombo.SelectedItem = $script:DnsProviderConfigMap[$providerName]
                                    }
                                    $script:DnsProviderCombo.Tag = $script:DnsProviderCombo.SelectedItem
                                    if ($script:FWStatusDots.ContainsKey('DNS_Provider')) {
                                        $script:FWStatusDots['DNS_Provider'].BackColor = if ($providerName -ne 'None') {
                                            [System.Drawing.Color]::FromArgb(0, 200, 100)
                                        } else {
                                            [System.Drawing.Color]::FromArgb(80, 80, 100)
                                        }
                                    }
                                    if ($script:FWCheckboxes.ContainsKey('DNS_DoH')) {
                                        $dohCb = $script:FWCheckboxes['DNS_DoH']
                                        if ($providerName -eq 'None') {
                                            if ($dohCb.Checked) { $dohCb.Checked = $false }
                                            $dohCb.Enabled = $false
                                        } else {
                                            $dohCb.Enabled = $true
                                        }
                                    }
                                    continue
                                }
                                if ($script:FWCheckboxes.ContainsKey($key)) {
                                    $cb = $script:FWCheckboxes[$key]
                                    $boolVal = [bool]$val
                                    if ($cb.Checked -ne $boolVal) { $cb.Checked = $boolVal }
                                    $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name $key -Value $boolVal -Force
                                }
                                if ($script:FWStatusDots.ContainsKey($key)) {
                                    $script:FWStatusDots[$key].BackColor = if ([bool]$val) {
                                        [System.Drawing.Color]::FromArgb(0, 200, 100)
                                    } else {
                                        [System.Drawing.Color]::FromArgb(220, 50, 60)
                                    }
                                }
                            }
                        } finally { $script:SuppressSettingsSave = $false }
                        try { $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8 } catch {}
                    }
                }
                # Re-launch status job periodically (every 15 seconds)
                if (-not $script:FWStatusJob -and ([DateTime]::Now - $script:FWStatusLastLaunch).TotalSeconds -ge 15) {
                    $script:FWStatusLastLaunch = [DateTime]::Now
                    & $script:LaunchStatusJob
                }
            } catch { Write-Console "[StatusTimer] Tick error: $($_.Exception.Message)" "ERROR" }
        })
        $script:FWStatusTimer.Start()
    } catch {}

    # ── Beep on Alert toggle ──
    $sy += 8
    $beepCard = New-Object System.Windows.Forms.Panel
    $beepCard.Location = New-Object System.Drawing.Point(25, $sy)
    $beepCard.Size = New-Object System.Drawing.Size(770, 48)
    $beepCard.BackColor = $colCard
    $beepCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $settingsPage.Controls.Add($beepCard)

    $beepIcon = New-Object System.Windows.Forms.Label
    $beepIcon.Text = "[SND]"
    $beepIcon.Location = New-Object System.Drawing.Point(10, 5)
    $beepIcon.Size = New-Object System.Drawing.Size(45, 20)
    $beepIcon.Font = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
    $beepIcon.ForeColor = [System.Drawing.Color]::FromArgb(255, 220, 100)
    $beepCard.Controls.Add($beepIcon)

    $beepCb = New-Object System.Windows.Forms.CheckBox
    $beepCb.Text = "Beep on Alert"
    $beepCb.Location = New-Object System.Drawing.Point(55, 4)
    $beepCb.Size = New-Object System.Drawing.Size(350, 22)
    $beepCb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $beepCb.ForeColor = $colTextMain
    $beepCb.BackColor = $colCard
    $beepCb.Tag = "BeepOnAlert"
    $propBeep = $script:NotifyConfig.PSObject.Properties['BeepOnAlert']
    $beepCb.Checked = if ($null -eq $propBeep) { $false } else { $propBeep.Value -eq $true }
    $beepCard.Controls.Add($beepCb)

    $beepDescLbl = New-Object System.Windows.Forms.Label
    $beepDescLbl.Text = "Play a system beep sound when a new alert is detected."
    $beepDescLbl.Location = New-Object System.Drawing.Point(55, 27)
    $beepDescLbl.Size = New-Object System.Drawing.Size(680, 17)
    $beepDescLbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $beepDescLbl.ForeColor = $colTextDim
    $beepDescLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $beepCard.Controls.Add($beepDescLbl)

    $beepCb.Add_CheckedChanged({
        try {
            if ($script:SuppressSettingsSave) { return }
            $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name $this.Tag -Value $this.Checked -Force
            try { $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8 } catch {}
        } catch { $script:LastFWError = "SettingsSave(Beep): $($_.Exception.Message)" }
    })
    $sy += 52

  } catch { Write-Console "Settings page error: $_" "ERROR" }

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 4: LOGS (open/view log files)
    # ═══════════════════════════════════════════════════════════════
  try {
    $logsPage = $pages["Logs"]

    $logsTitle = New-Object System.Windows.Forms.Label
    $logsTitle.Text = "Log Files"
    $logsTitle.Location = New-Object System.Drawing.Point(25, 18)
    $logsTitle.Size = New-Object System.Drawing.Size(300, 32)
    $logsTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $logsTitle.ForeColor = $colAccent
    $logsPage.Controls.Add($logsTitle)

    $logFiles = @(
        @{ Label = "Alert Log";       File = $AlertFile;      Desc = "All security alerts generated during this session" },
        @{ Label = "Monitor Log";     File = $LogFile;        Desc = "General monitoring events and status messages" },
        @{ Label = "Connection Log";  File = $ConnectionLog;  Desc = "All network connection events (new/terminated)" },
        @{ Label = "Process Log";     File = $ProcessLog;     Desc = "Process creation and termination tracking" }
    )

    $ly = 65
    foreach ($lf in $logFiles) {
        $logCard = New-Object System.Windows.Forms.Panel
        $logCard.Location = New-Object System.Drawing.Point(25, $ly)
        $logCard.Size = New-Object System.Drawing.Size(770, 60)
        $logCard.BackColor = $colCard
        $logCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $logsPage.Controls.Add($logCard)

        $lfLabel = New-Object System.Windows.Forms.Label
        $lfLabel.Text = $lf.Label
        $lfLabel.Location = New-Object System.Drawing.Point(15, 8)
        $lfLabel.Size = New-Object System.Drawing.Size(250, 22)
        $lfLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $lfLabel.ForeColor = $colTextMain
        $logCard.Controls.Add($lfLabel)

        $lfDesc = New-Object System.Windows.Forms.Label
        $lfDesc.Text = $lf.Desc
        $lfDesc.Location = New-Object System.Drawing.Point(15, 32)
        $lfDesc.Size = New-Object System.Drawing.Size(500, 18)
        $lfDesc.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $lfDesc.ForeColor = $colTextDim
        $logCard.Controls.Add($lfDesc)

        $openBtn = New-Object System.Windows.Forms.Button
        $openBtn.Text = "Open"
        $openBtn.Location = New-Object System.Drawing.Point(($logCard.Width - 160), 12)
        $openBtn.Size = New-Object System.Drawing.Size(70, 32)
        $openBtn.FlatStyle = "Flat"
        $openBtn.BackColor = $colAccentDim
        $openBtn.ForeColor = $colTextMain
        $openBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $openBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
        $openBtn.Tag = $lf.File
        $openBtn.Add_Click({
            if ($this.Tag -and (Test-Path $this.Tag)) {
                Start-Process notepad.exe $this.Tag
            } else {
                [System.Windows.Forms.MessageBox]::Show("Log file has not been created yet.`nIt will appear after the first monitoring cycle generates data.`n`nExpected path:`n$($this.Tag)", "File Not Found", "OK", "Information")
            }
        })
        $logCard.Controls.Add($openBtn)

        $folderBtn = New-Object System.Windows.Forms.Button
        $folderBtn.Text = "Folder"
        $folderBtn.Location = New-Object System.Drawing.Point(($logCard.Width - 80), 12)
        $folderBtn.Size = New-Object System.Drawing.Size(70, 32)
        $folderBtn.FlatStyle = "Flat"
        $folderBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
        $folderBtn.ForeColor = $colTextMain
        $folderBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $folderBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
        $folderBtn.Tag = $LogDir
        $folderBtn.Add_Click({ Start-Process explorer.exe $this.Tag })
        $logCard.Controls.Add($folderBtn)

        $ly += 68
    }

    # Baselines section
    $blTitle = New-Object System.Windows.Forms.Label
    $blTitle.Text = "Baselines"
    $blTitle.Location = New-Object System.Drawing.Point(25, ($ly + 15))
    $blTitle.Size = New-Object System.Drawing.Size(300, 28)
    $blTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $blTitle.ForeColor = $colOrange
    $logsPage.Controls.Add($blTitle)
    $ly += 48

    $baselineFiles = @(
        @{ Label = "Firmware Baseline"; File = $FirmwareBaseline },
        @{ Label = "Driver Baseline";   File = $DriverBaseline },
        @{ Label = "Service Baseline";  File = $ServiceBaseline }
    )
    foreach ($bl in $baselineFiles) {
        $blCard = New-Object System.Windows.Forms.Panel
        $blCard.Location = New-Object System.Drawing.Point(25, $ly)
        $blCard.Size = New-Object System.Drawing.Size(770, 44)
        $blCard.BackColor = $colCard
        $blCard.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $logsPage.Controls.Add($blCard)

        $blLabel = New-Object System.Windows.Forms.Label
        $blLabel.Text = $bl.Label
        $blLabel.Location = New-Object System.Drawing.Point(15, 10)
        $blLabel.Size = New-Object System.Drawing.Size(250, 22)
        $blLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $blLabel.ForeColor = $colTextMain
        $blCard.Controls.Add($blLabel)

        $blOpenBtn = New-Object System.Windows.Forms.Button
        $blOpenBtn.Text = "View"
        $blOpenBtn.Location = New-Object System.Drawing.Point(690, 6)
        $blOpenBtn.Size = New-Object System.Drawing.Size(70, 30)
        $blOpenBtn.FlatStyle = "Flat"
        $blOpenBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
        $blOpenBtn.ForeColor = $colTextMain
        $blOpenBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $blOpenBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
        $blOpenBtn.Tag = $bl.File
        $blOpenBtn.Add_Click({
            if ($this.Tag -and (Test-Path $this.Tag)) {
                Start-Process notepad.exe $this.Tag
            } else {
                [System.Windows.Forms.MessageBox]::Show("Baseline file has not been created yet.`nIt will appear after the first monitoring cycle.`n`nExpected path:`n$($this.Tag)", "File Not Found", "OK", "Information")
            }
        })
        $blCard.Controls.Add($blOpenBtn)

        $ly += 50
    }
  } catch { Write-Console "Logs page error: $_" "ERROR" }

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 6: CONSOLE (live debug/error output)
    # ═══════════════════════════════════════════════════════════════
  try {
    $consolePage = $pages["Console"]

    $consoleTitle = New-Object System.Windows.Forms.Label
    $consoleTitle.Text = "Console Output"
    $consoleTitle.Location = New-Object System.Drawing.Point(25, 18)
    $consoleTitle.Size = New-Object System.Drawing.Size(400, 32)
    $consoleTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $consoleTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 220, 130)
    $consolePage.Controls.Add($consoleTitle)

    $consoleDesc = New-Object System.Windows.Forms.Label
    $consoleDesc.Text = "Live log of all operations, errors, and system events."
    $consoleDesc.Location = New-Object System.Drawing.Point(25, 50)
    $consoleDesc.Size = New-Object System.Drawing.Size(500, 20)
    $consoleDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $consoleDesc.ForeColor = $colTextDim
    $consolePage.Controls.Add($consoleDesc)

    $consoleClearBtn = New-Object System.Windows.Forms.Button
    $consoleClearBtn.Text = "Clear"
    $consoleClearBtn.Location = New-Object System.Drawing.Point(695, 16)
    $consoleClearBtn.Size = New-Object System.Drawing.Size(80, 30)
    $consoleClearBtn.FlatStyle = "Flat"
    $consoleClearBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $consoleClearBtn.ForeColor = $colTextMain
    $consoleClearBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $consoleClearBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $consolePage.Controls.Add($consoleClearBtn)

    $script:ConsoleBox = New-Object System.Windows.Forms.RichTextBox
    $script:ConsoleBox.Location = New-Object System.Drawing.Point(25, 78)
    $script:ConsoleBox.Size = New-Object System.Drawing.Size(750, 500)
    $script:ConsoleBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $script:ConsoleBox.BackColor = [System.Drawing.Color]::FromArgb(12, 12, 20)
    $script:ConsoleBox.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 220)
    $script:ConsoleBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $script:ConsoleBox.ReadOnly = $true
    $script:ConsoleBox.WordWrap = $false
    $script:ConsoleBox.ScrollBars = "Both"
    $consolePage.Controls.Add($script:ConsoleBox)

    $consoleClearBtn.Add_Click({ $script:ConsoleBox.Clear() })

  } catch { Write-Host "[!] Console page error: $_" -ForegroundColor Red }

    # ── Status updater timer ──
    # ── Cached data for dashboard (updated by background runspace, read by UI timer) ──
    $script:DashCache = [hashtable]::Synchronized(@{
        CpuLoad = 0; RamUsed = 0; DiskUsed = 0
        DefenderOn = $null; FirewallOn = $null; UacOn = $null; RdpOff = $null
        NetConns = 0; NetTopStr = "None"
        Running = $true
    })

    # Background runspace for heavy WMI/CIM queries - never blocks UI thread
    $script:DashRunspace = [runspacefactory]::CreateRunspace()
    $script:DashRunspace.ApartmentState = "STA"
    $script:DashRunspace.Open()
    $script:DashRunspace.SessionStateProxy.SetVariable("cache", $script:DashCache)
    $script:DashPowerShell = [powershell]::Create().AddScript({
        param($cache)
        while ($cache.Running) {
            try {
                # CPU
                try {
                    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
                    if ($cpu) { $cache.CpuLoad = [math]::Round(($cpu | Measure-Object -Property LoadPercentage -Average).Average, 0) }
                } catch {}
                # RAM
                try {
                    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
                    if ($os) { $cache.RamUsed = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 0) }
                } catch {}
                # Disk
                try {
                    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
                    if ($disk) { $cache.DiskUsed = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 0) }
                } catch {}
                # Security posture
                try { $def = Get-MpComputerStatus -ErrorAction SilentlyContinue; $cache.DefenderOn = ($def -and $def.AntivirusEnabled) } catch { $cache.DefenderOn = $null }
                try { $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue; $cache.FirewallOn = (($fw | Where-Object { $_.Enabled }).Count -eq $fw.Count) } catch { $cache.FirewallOn = $null }
                try { $cache.UacOn = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA -eq 1) } catch {}
                try { $cache.RdpOff = ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1) } catch {}
                # Network summary
                try {
                    $netConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                        Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.|::1|::$)' }
                    $cache.NetConns = if ($netConns) { @($netConns).Count } else { 0 }
                    $topProcs = @($netConns) | Group-Object -Property OwningProcess |
                        Sort-Object Count -Descending | Select-Object -First 5 |
                        ForEach-Object {
                            $pName = (Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName
                            if (-not $pName) { $pName = "PID:$($_.Name)" }
                            "$pName($($_.Count))"
                        }
                    $cache.NetTopStr = if ($topProcs) { ($topProcs -join "  |  ") } else { "None" }
                } catch {}
            } catch {}
            # Sleep 10 seconds between updates (doesn't block UI)
            Start-Sleep -Seconds 10
        }
    }).AddArgument($script:DashCache)
    $script:DashPowerShell.Runspace = $script:DashRunspace
    $script:DashRunspaceHandle = $script:DashPowerShell.BeginInvoke()

    # Fast UI refresh timer - only reads cached data, never calls WMI/CIM
    $script:DashTimer = New-Object System.Windows.Forms.Timer
    $script:DashTimer.Interval = 2000
    $script:DashTimer.Add_Tick({
        try {
            if (-not ($script:DashboardForm -and $script:DashboardForm.Visible -and -not $script:DashboardForm.IsDisposed)) { return }

            # Lightweight label updates
            $script:LblAlerts.Text = "$($script:AlertCount)"
            $script:LblConnections.Text = "$($script:KnownRemotes.Count)"
            $script:LblProcesses.Text = "$($script:KnownProcesses.Count)"
            $up = (Get-Date) - $script:StartTime
            $script:LblUptime.Text = "{0:D2}h {1:D2}m" -f [int]$up.TotalHours, $up.Minutes
            & $script:UpdateAlertsListFn
            try { if ($script:ScanCountLabel) { $script:ScanCountLabel.Text = "$($script:MonitorCycle)" } } catch {}

            # Apply cached gauge data (instant - no WMI)
            try {
                $maxW = 220
                $colGreen  = [System.Drawing.Color]::FromArgb(0, 200, 100)
                $colYellow = [System.Drawing.Color]::FromArgb(255, 220, 50)
                $colRed    = [System.Drawing.Color]::FromArgb(255, 60, 60)

                foreach ($gauge in @(@{G=$script:CpuGauge; V=$script:DashCache.CpuLoad}, @{G=$script:RamGauge; V=$script:DashCache.RamUsed}, @{G=$script:DiskGauge; V=$script:DashCache.DiskUsed})) {
                    $pct = [math]::Max(0, [math]::Min(100, $gauge.V))
                    $gauge.G.Label.Text = "$pct%"
                    $gauge.G.Fill.Width = [math]::Round($maxW * $pct / 100)
                    if ($pct -ge 90) { $gauge.G.Fill.BackColor = $colRed }
                    elseif ($pct -ge 70) { $gauge.G.Fill.BackColor = $colYellow }
                    else { $gauge.G.Fill.BackColor = $colGreen }
                }
            } catch {}

            # Apply cached security posture (instant - no cmdlets)
            try {
                $colGreenSp = [System.Drawing.Color]::FromArgb(0, 200, 100)
                $colRedSp   = [System.Drawing.Color]::FromArgb(255, 60, 60)
                $colGraySp  = [System.Drawing.Color]::FromArgb(80, 80, 80)

                if ($script:DashCache.DefenderOn -eq $true) {
                    $script:SecPostureDots["Defender"].BackColor = $colGreenSp
                    $script:SecPostureLabels["Defender"].Text = "Defender: ON"
                    $script:SecPostureLabels["Defender"].ForeColor = $colGreenSp
                } elseif ($script:DashCache.DefenderOn -eq $false) {
                    $script:SecPostureDots["Defender"].BackColor = $colRedSp
                    $script:SecPostureLabels["Defender"].Text = "Defender: OFF"
                    $script:SecPostureLabels["Defender"].ForeColor = $colRedSp
                } else {
                    $script:SecPostureDots["Defender"].BackColor = $colGraySp
                    $script:SecPostureLabels["Defender"].Text = "Defender: N/A"
                }

                if ($script:DashCache.FirewallOn -eq $true) {
                    $script:SecPostureDots["Firewall"].BackColor = $colGreenSp
                    $script:SecPostureLabels["Firewall"].Text = "Firewall: ON"
                    $script:SecPostureLabels["Firewall"].ForeColor = $colGreenSp
                } elseif ($script:DashCache.FirewallOn -eq $false) {
                    $script:SecPostureDots["Firewall"].BackColor = $colRedSp
                    $script:SecPostureLabels["Firewall"].Text = "Firewall: PARTIAL"
                    $script:SecPostureLabels["Firewall"].ForeColor = $colRedSp
                } else {
                    $script:SecPostureDots["Firewall"].BackColor = $colGraySp
                    $script:SecPostureLabels["Firewall"].Text = "Firewall: N/A"
                }

                if ($script:DashCache.UacOn -eq $true) {
                    $script:SecPostureDots["UAC"].BackColor = $colGreenSp
                    $script:SecPostureLabels["UAC"].Text = "UAC: Enabled"
                    $script:SecPostureLabels["UAC"].ForeColor = $colGreenSp
                } elseif ($script:DashCache.UacOn -eq $false) {
                    $script:SecPostureDots["UAC"].BackColor = $colRedSp
                    $script:SecPostureLabels["UAC"].Text = "UAC: DISABLED"
                    $script:SecPostureLabels["UAC"].ForeColor = $colRedSp
                }

                if ($script:DashCache.RdpOff -eq $true) {
                    $script:SecPostureDots["RDP"].BackColor = $colGreenSp
                    $script:SecPostureLabels["RDP"].Text = "RDP: Disabled"
                    $script:SecPostureLabels["RDP"].ForeColor = $colGreenSp
                } elseif ($script:DashCache.RdpOff -eq $false) {
                    $script:SecPostureDots["RDP"].BackColor = $colRedSp
                    $script:SecPostureLabels["RDP"].Text = "RDP: ENABLED"
                    $script:SecPostureLabels["RDP"].ForeColor = $colRedSp
                }
            } catch {}

            # Network activity from cache
            try {
                $script:NetActivityLabel.Text = "Active: $($script:DashCache.NetConns) connections   Top: $($script:DashCache.NetTopStr)"
            } catch {}

            # AI threat count update
            try {
                if ($script:AiCountLabel) {
                    $cnt = $script:AiThreatCount
                    if ($cnt -eq 0) {
                        $script:AiCountLabel.Text = "No threats detected"
                        $script:AiCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 100)
                    } else {
                        $script:AiCountLabel.Text = "$cnt threat(s) detected"
                        $script:AiCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 90)
                    }
                }
            } catch {}
        } catch {}
    })
    $script:DashTimer.Start()

    # AI scan timers - only start if AI feature is enabled
    $script:AiInitTimer = New-Object System.Windows.Forms.Timer
    $script:AiInitTimer.Interval = 5000
    $script:AiInitTimer.Add_Tick({
        $this.Stop()
        $this.Dispose()
        try { Start-AiThreatScan } catch {}
    })

    $script:AiPeriodicTimer = New-Object System.Windows.Forms.Timer
    $script:AiPeriodicTimer.Interval = 300000
    $script:AiPeriodicTimer.Add_Tick({
        try { Start-AiThreatScan } catch {}
    })

    # AI scan timers disabled — user runs scans manually via button
    # if ($script:AiFeatureEnabled) {
    #     $script:AiInitTimer.Start()
    #     $script:AiPeriodicTimer.Start()
    # }

    # Set open tab and switch page
    $script:DashboardOpenTab = $OpenTab

    # Switch page immediately (sets Visible/BringToFront)
    try { & $script:SwitchPageFn $OpenTab } catch { Write-Console "SwitchPage error: $_" "ERROR" }

    # Also switch after form is shown to ensure rendering
    $form.Add_Shown({
        try {
            & $script:SwitchPageFn $script:DashboardOpenTab
            $script:ContentPanel.Refresh()
        } catch { Write-Console "Shown SwitchPage error: $_" "ERROR" }
    })

    $form.Show()
}

# ── Alert detail popup (called from dashboard double-click) ──
function Show-AlertDetail {
    param([hashtable]$AlertData, $ParentForm)

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Alert: $($AlertData.Title)"
    $dlg.Size = New-Object System.Drawing.Size(600, 420)
    $dlg.StartPosition = "CenterParent"
    $dlg.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 38)
    $dlg.ForeColor = [System.Drawing.Color]::White
    $dlg.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $dlg.FormBorderStyle = "FixedDialog"
    $dlg.MaximizeBox = $false
    $dlg.TopMost = $true

    # Red top bar
    $bar = New-Object System.Windows.Forms.Panel
    $bar.Dock = "Top"
    $bar.Size = New-Object System.Drawing.Size(600, 5)
    $bar.BackColor = [System.Drawing.Color]::FromArgb(220, 50, 60)
    $dlg.Controls.Add($bar)

    $tl = New-Object System.Windows.Forms.Label
    $tl.Text = $AlertData.Title
    $tl.Location = New-Object System.Drawing.Point(18, 14)
    $tl.Size = New-Object System.Drawing.Size(560, 28)
    $tl.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $tl.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 80)
    $dlg.Controls.Add($tl)

    $catTime = New-Object System.Windows.Forms.Label
    $catTime.Text = "$($AlertData.Category)  |  $($AlertData.Timestamp)"
    $catTime.Location = New-Object System.Drawing.Point(18, 44)
    $catTime.Size = New-Object System.Drawing.Size(560, 20)
    $catTime.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $catTime.ForeColor = [System.Drawing.Color]::FromArgb(0, 180, 240)
    $dlg.Controls.Add($catTime)

    $dp = New-Object System.Windows.Forms.Panel
    $dp.Location = New-Object System.Drawing.Point(18, 72)
    $dp.Size = New-Object System.Drawing.Size(555, 250)
    $dp.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 46)
    $dp.AutoScroll = $true
    $dlg.Controls.Add($dp)

    $dy = 8
    foreach ($key in $AlertData.Details.Keys) {
        $kl = New-Object System.Windows.Forms.Label
        $kl.Text = "${key}:"
        $kl.Location = New-Object System.Drawing.Point(8, $dy)
        $kl.Size = New-Object System.Drawing.Size(130, 20)
        $kl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $kl.ForeColor = [System.Drawing.Color]::FromArgb(100, 160, 255)
        $dp.Controls.Add($kl)

        $vl = New-Object System.Windows.Forms.Label
        $vl.Text = "$($AlertData.Details[$key])"
        $vl.Location = New-Object System.Drawing.Point(142, $dy)
        $vl.Size = New-Object System.Drawing.Size(400, 20)
        $vl.Font = New-Object System.Drawing.Font("Consolas", 9)
        $vl.ForeColor = [System.Drawing.Color]::White
        $dp.Controls.Add($vl)
        $dy += 24
    }

    # Buttons
    if ($AlertData.RemoteIP) {
        $ib = New-Object System.Windows.Forms.Button
        $ib.Text = "Lookup $($AlertData.RemoteIP) on ipinfo.io"
        $ib.Location = New-Object System.Drawing.Point(18, 335)
        $ib.Size = New-Object System.Drawing.Size(300, 34)
        $ib.FlatStyle = "Flat"
        $ib.BackColor = [System.Drawing.Color]::FromArgb(0, 130, 200)
        $ib.ForeColor = [System.Drawing.Color]::White
        $ib.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $ib.Cursor = [System.Windows.Forms.Cursors]::Hand
        $capturedIP = $AlertData.RemoteIP
        $ib.Add_Click({ Start-Process "https://ipinfo.io/$capturedIP" })
        $dlg.Controls.Add($ib)
    }

    $cb = New-Object System.Windows.Forms.Button
    $cb.Text = "Close"
    $cb.Location = New-Object System.Drawing.Point(480, 335)
    $cb.Size = New-Object System.Drawing.Size(90, 34)
    $cb.FlatStyle = "Flat"
    $cb.BackColor = [System.Drawing.Color]::FromArgb(70, 30, 30)
    $cb.ForeColor = [System.Drawing.Color]::White
    $cb.Cursor = [System.Windows.Forms.Cursors]::Hand
    $cb.Add_Click({ $dlg.Close() })
    $dlg.Controls.Add($cb)

    $dlg.ShowDialog() | Out-Null
}

# --- SYSTEM TRAY ICON ---
$script:TrayIcon = $null
$script:LastAlertData = $null

function Initialize-TrayIcon {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $script:TrayIcon = New-Object System.Windows.Forms.NotifyIcon

    # Create a custom bright shield icon for better tray visibility
    try {
        $bmp = New-Object System.Drawing.Bitmap(32, 32)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear([System.Drawing.Color]::Transparent)
        # Shield shape
        $shieldPoints = @(
            (New-Object System.Drawing.Point(16, 2)),
            (New-Object System.Drawing.Point(28, 6)),
            (New-Object System.Drawing.Point(28, 16)),
            (New-Object System.Drawing.Point(16, 30)),
            (New-Object System.Drawing.Point(4, 16)),
            (New-Object System.Drawing.Point(4, 6))
        )
        $g.FillPolygon((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 180, 255))), $shieldPoints)
        # Inner highlight
        $innerPoints = @(
            (New-Object System.Drawing.Point(16, 6)),
            (New-Object System.Drawing.Point(24, 9)),
            (New-Object System.Drawing.Point(24, 15)),
            (New-Object System.Drawing.Point(16, 26)),
            (New-Object System.Drawing.Point(8, 15)),
            (New-Object System.Drawing.Point(8, 9))
        )
        $g.FillPolygon((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 120, 200))), $innerPoints)
        # Check mark
        $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 3)
        $g.DrawLine($pen, 10, 16, 14, 21)
        $g.DrawLine($pen, 14, 21, 22, 11)
        $pen.Dispose()
        $g.Dispose()
        $hIcon = $bmp.GetHicon()
        $script:TrayIcon.Icon = [System.Drawing.Icon]::FromHandle($hIcon)
        # Keep bitmap alive - disposing can invalidate icon handle on some .NET versions
        $script:TrayIconBmp = $bmp
    } catch {
        $script:TrayIcon.Icon = [System.Drawing.SystemIcons]::Shield
    }

    $script:TrayIcon.Text = "SecurityMonitor v7.0"
    $script:TrayIcon.Visible = $true

    # Force tray icon to appear on first run - toggle visibility after message pump starts
    $refreshTimer = New-Object System.Windows.Forms.Timer
    $refreshTimer.Interval = 500
    $refreshTimer.Add_Tick({
        $this.Stop()
        $this.Dispose()
        try {
            $script:TrayIcon.Visible = $false
            $script:TrayIcon.Visible = $true
        } catch {}
    })
    $refreshTimer.Start()

    # DOUBLE CLICK on tray icon → open Dashboard
    $script:TrayIcon.Add_MouseDoubleClick({
        param($s, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            try { Show-Dashboard } catch { Write-Console "Dashboard error: $_" "ERROR" }
        }
    })

    # RIGHT CLICK context menu
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $contextMenu.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 45)
    $contextMenu.ForeColor = [System.Drawing.Color]::White
    $contextMenu.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $contextMenu.RenderMode = "System"

    $dashItem = New-Object System.Windows.Forms.ToolStripMenuItem("Open Dashboard")
    $dashItem.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $dashItem.Add_Click({ try { Show-Dashboard } catch { Write-Console "Dashboard error: $_" "ERROR" } })
    [void]$contextMenu.Items.Add($dashItem)

    $alertsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Alerts")
    $alertsItem.Add_Click({ try { Show-Dashboard -OpenTab "Alerts" } catch {} })
    [void]$contextMenu.Items.Add($alertsItem)

    $settingsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Settings")
    $settingsItem.Add_Click({ try { Show-Dashboard -OpenTab "Settings" } catch {} })
    [void]$contextMenu.Items.Add($settingsItem)

    $logsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Logs")
    $logsItem.Add_Click({ try { Show-Dashboard -OpenTab "Logs" } catch {} })
    [void]$contextMenu.Items.Add($logsItem)

    [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("Stop Monitoring")
    $exitItem.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 80)
    $exitItem.Add_Click({
        $script:MonitoringRunning = $false
        $script:TrayIcon.Visible = $false
        $script:TrayIcon.Dispose()
        if ($script:DashboardForm -and -not $script:DashboardForm.IsDisposed) {
            $script:DashboardForm.Dispose()
        }
        [System.Windows.Forms.Application]::ExitThread()
    })
    [void]$contextMenu.Items.Add($exitItem)

    $script:TrayIcon.ContextMenuStrip = $contextMenu

    # Click on balloon tip: smart action based on alert category
    $script:TrayIcon.Add_BalloonTipClicked({
        if ($null -eq $script:LastAlertData) { return }
        $ad = $script:LastAlertData
        try {
            switch ($ad.Category) {
                "Connection" {
                    # Open IP lookup in browser
                    if ($ad.RemoteIP) {
                        Start-Process "https://ipinfo.io/$($ad.RemoteIP)"
                    }
                }
                "Process" {
                    # Open file location in Explorer
                    $path = $ad.Details["Process Path"]
                    if (-not $path) { $path = $ad.Details["Path"] }
                    if ($path -and (Test-Path $path)) {
                        Start-Process explorer.exe "/select,`"$path`""
                    } elseif ($path) {
                        $dir = Split-Path $path -Parent -ErrorAction SilentlyContinue
                        if ($dir -and (Test-Path $dir)) { Start-Process explorer.exe "`"$dir`"" }
                    }
                }
                "Registry Tampering" {
                    # Open regedit at the registry path
                    $regPath = $ad.Details["Registry Path"]
                    if ($regPath) {
                        # Convert PS registry path to regedit format
                        $regeditPath = $regPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
                        # Set regedit LastKey so it opens at the right location
                        try {
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value $regeditPath -ErrorAction SilentlyContinue
                        } catch {}
                        Start-Process regedit.exe
                    }
                }
                "Firmware" {
                    # Open firmware file location in Explorer
                    $filePath = $ad.Details["File Path"]
                    if ($filePath -and (Test-Path $filePath)) {
                        Start-Process explorer.exe "/select,`"$filePath`""
                    } elseif ($filePath) {
                        $dir = Split-Path $filePath -Parent -ErrorAction SilentlyContinue
                        if ($dir -and (Test-Path $dir)) { Start-Process explorer.exe "`"$dir`"" }
                    }
                }
                "Hosts" {
                    # Open hosts file in Notepad
                    Start-Process notepad.exe "$env:SystemRoot\System32\drivers\etc\hosts"
                }
                "RDP" {
                    # Open System Properties > Remote tab
                    Start-Process SystemPropertiesRemote.exe
                }
                "Security" {
                    # Open Event Viewer at Security log
                    Start-Process eventvwr.msc "/s"
                }
                "Listener" {
                    # Show current listening ports in a popup
                    $listeners = netstat -ano | Select-String "LISTENING" | Select-Object -First 25
                    $text = ($listeners | ForEach-Object { $_.ToString().Trim() }) -join "`n"
                    [System.Windows.Forms.MessageBox]::Show($text, "Listening Ports", "OK", "Information")
                }
                { $_ -eq "Driver" -or $_ -eq "Service" } {
                    # Open Services management console
                    Start-Process services.msc
                }
                "Registry" {
                    # Open regedit for startup key changes
                    try {
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
                    } catch {}
                    Start-Process regedit.exe
                }
                default {
                    # Fallback: open dashboard Alerts tab
                }
            }
        } catch {}
        # Always open dashboard Alerts tab
        try { Show-Dashboard -OpenTab "Alerts" } catch {}
    })
}

# --- WINDOWS TOAST NOTIFICATION ---
function Send-ToastNotification {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Severity = "Warning",
        [hashtable]$AlertData = $null
    )

    # Store for balloon click handler
    if ($AlertData) {
        $script:LastAlertData = $AlertData
    }

    # Try system tray balloon first (supports click events)
    if ($script:TrayIcon) {
        try {
            $script:TrayIcon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
            $script:TrayIcon.BalloonTipTitle = "SecurityMonitor: $Title"
            # Smart click hint based on category
            $clickHint = if ($AlertData) {
                switch ($AlertData.Category) {
                    "Connection"        { "Click to lookup IP on ipinfo.io" }
                    "Process"           { "Click to open file location" }
                    "Registry Tampering" { "Click to open Registry Editor" }
                    "Firmware"          { "Click to open file location" }
                    "Hosts"             { "Click to open hosts file" }
                    "RDP"               { "Click to open Remote Desktop settings" }
                    "Security"          { "Click to open Event Viewer" }
                    "Listener"          { "Click to view listening ports" }
                    "Driver"            { "Click to open Services" }
                    "Service"           { "Click to open Services" }
                    "Registry"          { "Click to open Registry Editor" }
                    default             { "Click to view details" }
                }
            } else { "Click to view details" }
            $script:TrayIcon.BalloonTipText = "$Message`n$clickHint"
            $script:TrayIcon.ShowBalloonTip(8000)
            return $true
        } catch {}
    }

    # Fallback: Toast notification with launch action
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        $launchUrl = ""
        if ($AlertData) {
            switch ($AlertData.Category) {
                "Connection"  { if ($AlertData.RemoteIP) { $launchUrl = "https://ipinfo.io/$($AlertData.RemoteIP)" } }
                "Hosts"       { $launchUrl = "$env:SystemRoot\System32\drivers\etc\hosts" }
                "RDP"         { $launchUrl = "ms-settings:remotedesktop" }
                "Security"    { $launchUrl = "eventvwr.msc" }
                default       { if ($AlertData.RemoteIP) { $launchUrl = "https://ipinfo.io/$($AlertData.RemoteIP)" } }
            }
        }

        $template = @"
<toast duration="long" launch="$launchUrl" activationType="protocol">
    <visual>
        <binding template="ToastGeneric">
            <text>SecurityMonitor: $Title</text>
            <text>$Message</text>
            <text placement="attribution">Security Alert - $(Get-Date -Format 'HH:mm:ss') | Click for details</text>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:Notification.Default"/>
</toast>
"@
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
        return $true
    } catch {
        return $false
    }
}

function Test-ThreatDetailsEnabled {
    $val = $script:NotifyConfig.PSObject.Properties["ShowThreatDetails"]
    if ($null -eq $val) { return $false }
    return $val.Value -eq $true
}

function Get-AlertSeverity {
    param([string]$Title, [string]$Category)
    # When threat details are disabled, always return INFO (neutral)
    if (-not (Test-ThreatDetailsEnabled)) { return "INFO" }
    if ($Category -eq "Registry Tampering") { return "CRIT" }
    if ($Title -match "FIRMWARE.*(DELETED|MODIFIED)") { return "CRIT" }
    if ($Title -match "REGISTRY CHANGE|EXECUTABLE BLOCKED|DEFENDER EXCLUSION") { return "CRIT" }
    if ($Category -eq "Connection" -or $Title -match "UNKNOWN CONNECTION") { return "HIGH" }
    if ($Category -eq "Process" -or $Title -match "UNSIGNED PROCESS") { return "HIGH" }
    if ($Title -match "REMOTE LOGON|FAILED LOGON|NEW USER") { return "HIGH" }
    if ($Category -match "Driver|Service|Security") { return "MED" }
    if ($Title -match "NEW_DRIVER|NEW_SERVICE|SECURITY EVENT") { return "MED" }
    if ($Category -match "Listener|Hosts|Registry|RDP") { return "LOW" }
    return "INFO"
}

function Send-Alert {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Category = "",
        [string]$RemoteIP = "",
        [hashtable]$ExtraDetails = @{}
    )
    # Skip entirely if category is disabled in settings
    if ($Category -ne "" -and -not (Test-NotifyEnabled -Category $Category)) {
        Write-Log "$Title - $Message [FILTERED]" -Level "ALERT"
        return
    }

    $script:AlertCount++
    Write-Log "$Title - $Message" -Level "ALERT"

    $severity = Get-AlertSeverity -Title $Title -Category $Category

    # Build alert data for GUI
    $alertData = @{
        Title     = $Title
        Message   = $Message
        Category  = $Category
        Severity  = $severity
        RemoteIP  = $RemoteIP
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Details   = @{
            "Alert Type"  = $Title
            "Description" = $Message
            "Computer"    = $env:COMPUTERNAME
            "User"        = $env:USERNAME
        }
    }
    $showThreat = Test-ThreatDetailsEnabled
    foreach ($key in $ExtraDetails.Keys) {
        # Hide threat/recommendation fields when threat details are off
        if (-not $showThreat -and $key -in @("Info","Suggestion","Threat","Action")) { continue }
        $alertData.Details[$key] = $ExtraDetails[$key]
    }
    if ($Category -eq "Connection" -and $RemoteIP) {
        $alertData.Details["Remote IP"]   = $RemoteIP
        $alertData.Details["IP Lookup"]   = "https://ipinfo.io/$RemoteIP"
    }

    [void]$script:AlertHistory.Add($alertData)

    # Cap alert history at 10000
    while ($script:AlertHistory.Count -gt 10000) {
        $script:AlertHistory.RemoveAt(0)
        $script:RenderedAlertCount = [Math]::Max(0, $script:RenderedAlertCount - 1)
    }

    # Send toast/balloon only if enabled in settings
    $toastEnabled = $script:NotifyConfig.PSObject.Properties["EnableToastNotifications"]
    $showToast = if ($null -eq $toastEnabled) { $true } else { $toastEnabled.Value -eq $true }
    if ($showToast) {
        $tipIcon = if ($severity -eq "CRIT") { "Error" } elseif ($severity -match "HIGH|MED") { "Warning" } else { "Info" }
        if ($showThreat) {
            Send-ToastNotification -Title "[$severity] $Title" -Message $Message -AlertData $alertData
        } else {
            Send-ToastNotification -Title $Title -Message $Message -AlertData $alertData
        }
    }

    if (-not $Silent) {
        if ($showThreat) {
            Write-Alert "[$severity] $Title - $Message"
        } else {
            Write-Alert "$Title - $Message"
        }
        $beepProp = $script:NotifyConfig.PSObject.Properties['BeepOnAlert']
        $beepEnabled = ($null -ne $beepProp -and $beepProp.Value -eq $true)
        if ($showThreat -and $beepEnabled) {
            try {
                if ($severity -eq "CRIT") { [System.Console]::Beep(800, 200); [System.Console]::Beep(1200, 200); [System.Console]::Beep(1600, 300) }
                elseif ($severity -eq "HIGH") { [System.Console]::Beep(1000, 300); [System.Console]::Beep(1500, 300) }
                elseif ($severity -eq "MED") { [System.Console]::Beep(1200, 200) }
            } catch {}
        }
    }
}

# --- FIRMWARE HASH BASELINE ---
function Get-FirmwareFiles {
    $paths = @()
    $fwDirs = @(
        "$env:SystemRoot\System32\drivers",
        "$env:SystemRoot\Firmware",
        "$env:SystemRoot\System32\DriverStore\FileRepository"
    )
    foreach ($dir in $fwDirs) {
        if (Test-Path $dir) {
            $paths += Get-ChildItem -Path $dir -Recurse -File -Include "*.sys","*.efi","*.rom","*.bin","*.fw","*.cap" -ErrorAction SilentlyContinue |
                      Where-Object { $_.Length -gt 0 -and $_.Length -lt 50MB } |
                      Select-Object -First 500
        }
    }
    return $paths
}

function New-FirmwareBaseline {
    Write-Status "Creating firmware baseline (this may take a few minutes)..."
    $files = Get-FirmwareFiles
    $baseline = @{}
    $count = 0
    foreach ($f in $files) {
        try {
            $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
            $baseline[$f.FullName] = @{
                Hash         = $hash
                Size         = $f.Length
                LastWrite    = $f.LastWriteTime.ToString("o")
                CreationTime = $f.CreationTime.ToString("o")
            }
            $count++
        } catch {}
    }
    $baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $FirmwareBaseline -Encoding UTF8
    Write-Ok "$count firmware/driver files saved to baseline"
    Write-Log "Firmware baseline created: $count files" -Level "INFO"
    return $baseline
}

function Compare-FirmwareBaseline {
    if (-not (Test-Path $FirmwareBaseline)) { return }
    $baseline = Get-Content $FirmwareBaseline -Raw | ConvertFrom-Json
    $changes = @()
    foreach ($prop in $baseline.PSObject.Properties) {
        $filePath = $prop.Name
        $expected = $prop.Value
        if (-not (Test-Path $filePath)) {
            $changes += @{ File = $filePath; Type = "DELETED"; Detail = "Firmware file deleted!" }
            continue
        }
        try {
            $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
            if ($currentHash -ne $expected.Hash) {
                $changes += @{
                    File   = $filePath
                    Type   = "MODIFIED"
                    Detail = "Hash changed! Previous: $($expected.Hash.Substring(0,16))... Current: $($currentHash.Substring(0,16))..."
                }
            }
        } catch {}
    }
    $currentFiles = Get-FirmwareFiles
    foreach ($f in $currentFiles) {
        if (-not $baseline.PSObject.Properties[$f.FullName]) {
            $changes += @{ File = $f.FullName; Type = "NEW"; Detail = "New firmware/driver file detected!" }
        }
    }
    return $changes
}

# --- DRIVER BASELINE ---
function New-DriverBaseline {
    Write-Status "Creating driver baseline..."
    $drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, Started, StartMode
    $driverList = [System.Collections.ArrayList]@()
    foreach ($d in $drivers) {
        [void]$driverList.Add(@{
            Name        = $d.Name
            DisplayName = $d.DisplayName
            PathName    = $d.PathName
            State       = $d.State
            Started     = $d.Started
            StartMode   = $d.StartMode
        })
    }
    $driverList | ConvertTo-Json -Depth 3 | Set-Content -Path $DriverBaseline -Encoding UTF8
    Write-Ok "$($driverList.Count) drivers saved to baseline"
    Write-Log "Driver baseline created: $($driverList.Count) drivers" -Level "INFO"
}

function Compare-DriverBaseline {
    if (-not (Test-Path $DriverBaseline)) { return }
    $baseline = Get-Content $DriverBaseline -Raw | ConvertFrom-Json
    $current = Get-CimInstance Win32_SystemDriver | Select-Object Name, State, Started
    $baseNames = $baseline | ForEach-Object { $_.Name }
    $currNames = $current | ForEach-Object { $_.Name }
    $changes = @()
    foreach ($d in $current) {
        if ($d.Name -notin $baseNames) {
            $changes += @{ Driver = $d.Name; Type = "NEW_DRIVER"; Detail = "New driver loaded: $($d.Name)" }
        }
    }
    foreach ($b in $baseline) {
        if ($b.Name -notin $currNames) {
            $changes += @{ Driver = $b.Name; Type = "REMOVED_DRIVER"; Detail = "Driver removed: $($b.Name)" }
        }
    }
    return $changes
}

# --- SERVICE BASELINE ---
function New-ServiceBaseline {
    Write-Status "Creating service baseline..."
    $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
    $svcList = [System.Collections.ArrayList]@()
    foreach ($s in $services) {
        [void]$svcList.Add(@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            Status      = $s.Status.ToString()
            StartType   = $s.StartType.ToString()
        })
    }
    $svcList | ConvertTo-Json -Depth 3 | Set-Content -Path $ServiceBaseline -Encoding UTF8
    Write-Ok "$($svcList.Count) services saved to baseline"
}

function Compare-ServiceBaseline {
    if (-not (Test-Path $ServiceBaseline)) { return }
    $baseline = Get-Content $ServiceBaseline -Raw | ConvertFrom-Json
    $current = Get-Service | Select-Object Name, DisplayName, Status, StartType
    $baseNames = $baseline | ForEach-Object { $_.Name }
    $changes = @()
    foreach ($s in $current) {
        if ($s.Name -notin $baseNames) {
            $changes += @{
                Service     = $s.Name
                Type        = "NEW_SERVICE"
                Detail      = "New service detected: $($s.DisplayName) [$($s.Status)]"
                ExtraDetails = @{
                    "Service Name"    = $s.Name
                    "Display Name"    = "$($s.DisplayName)"
                    "Status"          = "$($s.Status)"
                    "Start Type"      = "$($s.StartType)"
                }
            }
        }
    }
    return $changes
}

# --- NETWORK MONITORING ---
function Get-ConnectionSnapshot {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" } |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddr   = $_.LocalAddress
            LocalPort   = $_.LocalPort
            RemoteAddr  = $_.RemoteAddress
            RemotePort  = $_.RemotePort
            PID         = $_.OwningProcess
            ProcessName = $proc.ProcessName
            ProcessPath = $proc.Path
        }
    }
}

$script:KnownRemotes = @{}
$script:WhitelistedProcesses = @(
    "msedge", "chrome", "firefox", "steam", "steamwebhelper",
    "svchost", "OneDrive", "SearchHost", "node", "Code",
    "explorer", "RuntimeBroker", "smartscreen", "spoolsv",
    "MsMpEng", "SecurityHealthService", "MpDefenderCoreService",
    "lsass", "services", "wininit", "csrss", "winlogon",
    "dwm", "taskhostw", "sihost", "ctfmon", "conhost",
    "powershell", "WindowsTerminal", "cmd"
)

function Watch-Connections {
    $current = Get-ConnectionSnapshot
    foreach ($conn in $current) {
        $key = "$($conn.RemoteAddr):$($conn.RemotePort)|$($conn.PID)"
        if (-not $script:KnownRemotes.ContainsKey($key)) {
            $script:KnownRemotes[$key] = Get-Date
            $isKnown = $conn.ProcessName -in $script:WhitelistedProcesses
            $logEntry = "NEW CONNECTION: $($conn.ProcessName) (PID:$($conn.PID)) -> $($conn.RemoteAddr):$($conn.RemotePort) | Path: $($conn.ProcessPath)"

            Write-Log $logEntry -Level "INFO" -Target $ConnectionLog

            if (-not $isKnown) {
                Send-Alert "UNKNOWN CONNECTION" "$($conn.ProcessName) -> $($conn.RemoteAddr):$($conn.RemotePort)" -Category "Connection" -RemoteIP $conn.RemoteAddr -ExtraDetails @{
                    "Process Name" = $conn.ProcessName
                    "Process Path" = $conn.ProcessPath
                    "PID"          = "$($conn.PID)"
                    "Local Port"   = "$($conn.LocalAddr):$($conn.LocalPort)"
                    "Remote"       = "$($conn.RemoteAddr):$($conn.RemotePort)"
                }
            } else {
                Write-Warn "Known connection: $($conn.ProcessName) -> $($conn.RemoteAddr):$($conn.RemotePort)"
            }
        }
    }
    $currentKeys = $current | ForEach-Object { "$($_.RemoteAddr):$($_.RemotePort)|$($_.PID)" }
    $staleKeys = $script:KnownRemotes.Keys | Where-Object { $_ -notin $currentKeys }
    foreach ($k in $staleKeys) {
        $script:KnownRemotes.Remove($k)
    }
}

# --- PROCESS MONITORING ---
$script:KnownProcesses = @{}

function Watch-Processes {
    $current = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
    foreach ($proc in $current) {
        if (-not $script:KnownProcesses.ContainsKey($proc.Id)) {
            $script:KnownProcesses[$proc.Id] = @{
                Name = $proc.ProcessName
                Path = $proc.Path
                Time = Get-Date
            }
            $isKnown = $proc.ProcessName -in $script:WhitelistedProcesses
            $isSigned = $false
            if ($proc.Path) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                    $isSigned = $sig.Status -eq "Valid"
                } catch {}
            }

            $logEntry = "NEW PROCESS: $($proc.ProcessName) (PID:$($proc.Id)) | Path: $($proc.Path) | Signed: $isSigned"
            Write-Log $logEntry -Level "INFO" -Target $ProcessLog

            if (-not $isKnown -and $proc.Path -and -not $isSigned) {
                Send-Alert "UNSIGNED PROCESS" "$($proc.ProcessName) (PID:$($proc.Id)) - $($proc.Path)" -Category "Process" -ExtraDetails @{
                    "Process Name" = $proc.ProcessName
                    "PID"          = "$($proc.Id)"
                    "Path"         = "$($proc.Path)"
                    "Signed"       = "No"
                }
            }
        }
    }
    $currentPids = $current | ForEach-Object { $_.Id }
    $stalePids = $script:KnownProcesses.Keys | Where-Object { $_ -notin $currentPids }
    foreach ($p in $stalePids) {
        $info = $script:KnownProcesses[$p]
        Write-Log "PROCESS TERMINATED: $($info.Name) (PID:$p)" -Level "INFO" -Target $ProcessLog
        $script:KnownProcesses.Remove($p)
    }
}

# --- LISTENING PORT MONITORING ---
$script:KnownListeners = @{}

function Watch-Listeners {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                 Where-Object { $_.LocalAddress -notmatch "^(127\.|::1)" }
    foreach ($l in $listeners) {
        $key = "$($l.LocalAddress):$($l.LocalPort)"
        if (-not $script:KnownListeners.ContainsKey($key)) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $script:KnownListeners[$key] = $proc.ProcessName
            $logEntry = "NEW LISTENING PORT: $key | Process: $($proc.ProcessName) (PID:$($l.OwningProcess)) | Path: $($proc.Path)"
            Write-Log $logEntry -Level "INFO"

            $isSystem = $proc.ProcessName -in @("svchost","lsass","services","wininit","spoolsv","System","steam")
            if (-not $isSystem) {
                Send-Alert "NEW LISTENING PORT" "$key - $($proc.ProcessName)" -Category "Listener" -ExtraDetails @{
                    "Listening On" = $key
                    "Process"      = $proc.ProcessName
                    "PID"          = "$($l.OwningProcess)"
                    "Path"         = "$($proc.Path)"
                }
            }
        }
    }
}

# --- SECURITY EVENT MONITORING ---
$script:LastEventTime = Get-Date

function Watch-SecurityEvents {
    $dangerousEventIds = @(
        4624, 4625, 4648, 4672, 4688, 4697, 4720, 4732, 7045
    )
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            StartTime = $script:LastEventTime
            Id        = $dangerousEventIds
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($evt in $events) {
            $logEntry = "SECURITY EVENT [ID:$($evt.Id)] $($evt.TimeCreated) - $($evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length)))"
            Write-Log $logEntry -Level "WARN"

            if ($evt.Id -eq 4624 -and $evt.Message -match "Logon Type:\s+(3|10)") {
                Send-Alert "REMOTE LOGON DETECTED" "Logon Type: $($Matches[1]) - $($evt.TimeCreated)" -Category "Security"
            }
            if ($evt.Id -eq 4625) {
                Send-Alert "FAILED LOGON ATTEMPT" "$($evt.TimeCreated)" -Category "Security"
            }
            if ($evt.Id -eq 4720) {
                Send-Alert "NEW USER ACCOUNT CREATED" "$($evt.TimeCreated)" -Category "Security"
            }
            if ($evt.Id -eq 4697 -or $evt.Id -eq 7045) {
                Send-Alert "NEW SERVICE INSTALLED" "$($evt.TimeCreated)" -Category "Security"
            }
        }
        $script:LastEventTime = Get-Date
    } catch {}
}

# --- REGISTRY MONITORING ---
$script:RegistryBaseline = @{}
$script:RegistrySnapshotCache = @{}

function Get-RegistryHash {
    param([string]$KeyPath)
    try {
        $values = Get-ItemProperty -Path $KeyPath -ErrorAction SilentlyContinue
        if ($null -eq $values) { return $null }
        $json = $values | ConvertTo-Json -Depth 2 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash($bytes)
        return [BitConverter]::ToString($hashBytes) -replace '-',''
    } catch { return $null }
}

function New-RegistryBaseline {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    )
    foreach ($key in $keys) {
        $hash = Get-RegistryHash -KeyPath $key
        if ($hash) {
            $script:RegistryBaseline[$key] = $hash
            # Cache current values for before/after comparison
            $vals = @{}
            try {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                        $vals[$p.Name] = "$($p.Value)"
                    }
                }
            } catch {}
            $script:RegistrySnapshotCache[$key] = $vals
        }
    }
    Write-Ok "Registry baseline created ($($keys.Count) keys)"
}

function Watch-Registry {
    # Uses pre-cached registry data from background runspace when available
    $cachedRegKeys = $script:MonitorCache.RegistryKeys
    $criticalKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $criticalKeys) {
        # Use cached values if available, otherwise fall back to direct read
        $afterValues = @{}
        $cachedEntry = $cachedRegKeys | Where-Object { $_.Key -eq $key } | Select-Object -First 1
        if ($cachedEntry -and $cachedEntry.Values) {
            $afterValues = $cachedEntry.Values
        } else {
            try {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                        $afterValues[$p.Name] = "$($p.Value)"
                    }
                }
            } catch {}
        }

        # Compute hash from values
        $json = ($afterValues.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "|"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-',''

        if ($hash -and $script:RegistryBaseline.ContainsKey($key) -and $script:RegistryBaseline[$key] -ne $hash) {
            $beforeSnapshot = $script:RegistrySnapshotCache[$key]

            # Determine what changed
            $added = @(); $removed = @(); $modified = @()
            if ($beforeSnapshot) {
                foreach ($k in $afterValues.Keys) {
                    if (-not $beforeSnapshot.ContainsKey($k)) { $added += "$k = $($afterValues[$k])" }
                    elseif ($beforeSnapshot[$k] -ne $afterValues[$k]) { $modified += "$k`: $($beforeSnapshot[$k]) -> $($afterValues[$k])" }
                }
                foreach ($k in $beforeSnapshot.Keys) {
                    if (-not $afterValues.ContainsKey($k)) { $removed += "$k = $($beforeSnapshot[$k])" }
                }
            }

            $changeDesc = @()
            if ($added.Count -gt 0)    { $changeDesc += "ADDED: $($added -join '; ')" }
            if ($removed.Count -gt 0)  { $changeDesc += "REMOVED: $($removed -join '; ')" }
            if ($modified.Count -gt 0) { $changeDesc += "MODIFIED: $($modified -join '; ')" }
            $changeText = if ($changeDesc.Count -gt 0) { $changeDesc -join "`n" } else { "Hash changed (details unavailable)" }

            $details = @{
                "Registry Path" = $key
                "Change Details" = $changeText
                "Before Hash" = $script:RegistryBaseline[$key].Substring(0, 16) + "..."
                "After Hash"  = $hash.Substring(0, 16) + "..."
            }
            if ($added.Count -gt 0)    { $details["Added Entries"] = $added -join "`n" }
            if ($removed.Count -gt 0)  { $details["Removed Entries"] = $removed -join "`n" }
            if ($modified.Count -gt 0) { $details["Modified Entries"] = $modified -join "`n" }

            # List current values
            $currentVals = ($afterValues.GetEnumerator() | ForEach-Object { "$($_.Key) = $($_.Value)" }) -join "`n"
            if ($currentVals) { $details["Current Values"] = $currentVals }

            Send-Alert "REGISTRY CHANGED" "Key: $key" -Category "Registry" -ExtraDetails $details
            Write-Log "Registry change: $key | Old: $($script:RegistryBaseline[$key].Substring(0,16))... New: $($hash.Substring(0,16))..." -Level "ALERT"
            $script:RegistryBaseline[$key] = $hash
            $script:RegistrySnapshotCache[$key] = $afterValues
        }
    }

    try {
        $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections).fDenyTSConnections
        if ($rdp -eq 0) {
            Send-Alert "RDP ENABLED" "Remote Desktop connection is enabled!" -Category "RDP"
        }
    } catch {}
}

# --- HOSTS FILE MONITORING ---
$script:HostsHash = $null

function Watch-HostsFile {
    try {
        # Use cached hash from background runspace if available
        $hash = $script:MonitorCache.HostsHash
        if (-not $hash) {
            $hash = (Get-FileHash -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
        if (-not $hash) { return }
        if ($null -eq $script:HostsHash) {
            $script:HostsHash = $hash
        } elseif ($script:HostsHash -ne $hash) {
            Send-Alert "HOSTS FILE MODIFIED" "DNS redirection may have changed!" -Category "Hosts"
            $script:HostsHash = $hash
        }
    } catch {}
}

# --- ANTI-TAMPERING REGISTRY MONITORING ---
# Detects registry keys that hackers use to disable security tools, PowerShell, Defender, etc.
function Watch-RegistryTampering {
    # Build lookup from background cache for instant registry reads
    $tamperCache = @{}
    $cachedTamper = $script:MonitorCache.RegistryTamper
    if ($cachedTamper) {
        foreach ($entry in $cachedTamper) {
            $tamperCache["$($entry.Path)|$($entry.Name)"] = $entry
        }
    }

    # Helper: get registry value from cache or direct read (fallback)
    $getRegVal = {
        param($path, $name)
        $cacheKey = "$path|$name"
        if ($tamperCache.ContainsKey($cacheKey)) {
            $e = $tamperCache[$cacheKey]
            return @{ Exists = $e.Exists; Value = $e.Value }
        }
        # Fallback to direct read if not in cache
        $exists = Test-Path $path
        $val = $null
        if ($exists -and $name -ne "(KeyExists)") {
            $val = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
        }
        return @{ Exists = $exists; Value = $val }
    }

    $tamperChecks = @(
        # IFEO debugger redirects
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on PowerShell" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell_ise.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on PowerShell ISE" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Task Manager" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Registry Editor" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Defender engine" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MpCmdRun.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Defender CLI" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cmd.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Command Prompt" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mmc.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Management Console" },

        # Windows Defender disabling
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; BadIf = "1"; Desc = "Windows Defender AntiSpyware disabled via policy" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; BadIf = "1"; Desc = "Windows Defender AntiVirus disabled via policy" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; BadIf = "1"; Desc = "Defender real-time protection disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; BadIf = "1"; Desc = "Defender behavior monitoring disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; BadIf = "1"; Desc = "Defender on-access protection disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; BadIf = "1"; Desc = "Defender download scanning disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; BadIf = "1"; Desc = "Defender scan-on-RT-enable disabled" },

        # UAC bypass / disable
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; BadIf = "0"; Desc = "UAC (User Account Control) disabled" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; BadIf = "0"; Desc = "UAC admin consent prompt disabled" },

        # UAC bypass via COM hijacking
        @{ Path = "HKCU:\Software\Classes\ms-settings\shell\open\command"; Name = "(Default)"; BadIf = "exists"; Desc = "ms-settings COM redirect present" },
        @{ Path = "HKCU:\Software\Classes\mscfile\shell\open\command"; Name = "(Default)"; BadIf = "exists"; Desc = "mscfile COM redirect present" },

        # Disable Task Manager and system tools
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; BadIf = "1"; Desc = "Task Manager disabled via policy" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; BadIf = "1"; Desc = "Registry Editor disabled via policy" },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Name = "DisableCMD"; BadIf = "1"; Desc = "Command Prompt disabled via policy" },

        # PowerShell execution and logging
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; BadIf = "0"; Desc = "PowerShell Script Block logging disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; BadIf = "0"; Desc = "PowerShell module logging disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableTranscripting"; BadIf = "0"; Desc = "PowerShell transcription disabled" },

        # AMSI (Antimalware Scan Interface) disable
        @{ Path = "HKCU:\Software\Microsoft\Windows Script\Settings"; Name = "AmsiEnable"; BadIf = "0"; Desc = "AMSI (Antimalware Scan Interface) disabled" },

        # Firewall disable
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall disabled (Standard profile)" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall disabled (Domain profile)" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall disabled (Public profile)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall service disabled (Standard)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall service disabled (Public)" },

        # Event Log tampering
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name = "Enabled"; BadIf = "0"; Desc = "Security Event Log disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name = "Enabled"; BadIf = "0"; Desc = "System Event Log disabled" },

        # Notification suppression
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "EnableBalloonTips"; BadIf = "0"; Desc = "Balloon notifications disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoTrayItemsDisplay"; BadIf = "1"; Desc = "System tray icons hidden" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "HideSCAHealth"; BadIf = "1"; Desc = "Security Center icon hidden" },

        # Executable blocklist
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisallowRun"; BadIf = "1"; Desc = "Executable blocklist active" },

        # Security service tampering
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"; Name = "Start"; BadIf = "4"; Desc = "Windows Defender service disabled" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc"; Name = "Start"; BadIf = "4"; Desc = "Security Center service disabled" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc"; Name = "Start"; BadIf = "4"; Desc = "Firewall service disabled" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"; Name = "Start"; BadIf = "4"; Desc = "Event Log service disabled" },

        # Winlogon persistence
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "Shell"; BadIf = "notexplorer"; Desc = "Winlogon Shell value differs from default" },

        # MiniNt key
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt"; Name = "(KeyExists)"; BadIf = "exists"; Desc = "MiniNt key present (affects security event logging)" },

        # Security Center notification suppression
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Security Center"; Name = "AntiVirusDisableNotify"; BadIf = "1"; Desc = "AntiVirus disable notifications suppressed" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Security Center"; Name = "FirewallDisableNotify"; BadIf = "1"; Desc = "Firewall disable notifications suppressed" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Security Center"; Name = "UpdatesDisableNotify"; BadIf = "1"; Desc = "Update disable notifications suppressed" },

        # Windows Script Host disable
        @{ Path = "HKLM:\Software\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; BadIf = "0"; Desc = "Windows Script Host disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; BadIf = "0"; Desc = "Windows Script Host disabled (user)" },

        # ═══ PowerShell Execution Policy ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; Name = "ExecutionPolicy"; BadIf = "Restricted"; Desc = "PowerShell ExecutionPolicy set to Restricted" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; Name = "ExecutionPolicy"; BadIf = "Restricted"; Desc = "PowerShell ExecutionPolicy Restricted (user level)" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Name = "EnableScripts"; BadIf = "0"; Desc = "PowerShell scripts disabled via Group Policy" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Name = "ExecutionPolicy"; BadIf = "Restricted"; Desc = "PowerShell ExecutionPolicy Restricted via GPO" },

        # ═══ PowerShell Constrained Language Mode ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; Name = "__PSLockdownPolicy"; BadIf = "4"; Desc = "PowerShell Constrained Language Mode active (limits .NET access)" },

        # ═══ IFEO settings ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecurityMonitor.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on SecurityMonitor" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\pwsh.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on PowerShell 7 (pwsh.exe)" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wscript.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on WScript" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cscript.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on CScript" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\eventvwr.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Event Viewer" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msconfig.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on MSConfig" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\perfmon.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Performance Monitor" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Process Explorer" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp64.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Process Explorer 64" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\autoruns.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Autoruns" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\autoruns64.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger set on Autoruns64" },

        # ═══ Software Restriction Policies ═══
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"; Name = "DefaultLevel"; BadIf = "0"; Desc = "Software Restriction Policy: default disallowed" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"; Name = "TransparentEnabled"; BadIf = "0"; Desc = "SRP transparency disabled (limits DLL loading)" },

        # ═══ AppLocker ═══
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script"; Name = "EnforcementMode"; BadIf = "1"; Desc = "AppLocker script rules in enforce mode" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe"; Name = "EnforcementMode"; BadIf = "1"; Desc = "AppLocker executable rules in enforce mode" },

        # ═══ WMI/CIM services ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt"; Name = "Start"; BadIf = "4"; Desc = "WMI Service disabled (affects system monitoring)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc"; Name = "Start"; BadIf = "4"; Desc = "IP Helper Service disabled (affects network monitoring)" },

        # ═══ Windows Notification settings ═══
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"; Name = "ToastEnabled"; BadIf = "0"; Desc = "Toast notifications disabled" },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; BadIf = "1"; Desc = "Notification Center disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; BadIf = "1"; Desc = "Notification Center disabled (machine policy)" },

        # ═══ Remote access settings ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "fDenyTSConnections"; BadIf = "0"; Desc = "Remote Desktop enabled at service level" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name = "UserAuthentication"; BadIf = "0"; Desc = "RDP Network Level Authentication disabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fAllowUnsolicited"; BadIf = "1"; Desc = "Unsolicited Remote Assistance allowed" },

        # ═══ Scheduled Tasks ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"; Name = "(KeyExists)"; BadIf = "checkchildren"; Desc = "Scheduled task tree check" },

        # ═══ Windows Update settings ═══
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; BadIf = "1"; Desc = "Windows Auto-Update disabled via policy" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"; Name = "Start"; BadIf = "4"; Desc = "Windows Update Service disabled" },

        # ═══ Credential settings ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; BadIf = "1"; Desc = "WDigest cleartext password storage enabled" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableRestrictedAdmin"; BadIf = "0"; Desc = "Restricted Admin mode setting changed" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; BadIf = "0"; Desc = "LSA Protection (PPL) disabled" },

        # ═══ Network security settings ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; BadIf = "1"; Desc = "SMBv1 protocol enabled (legacy protocol)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RequireSecuritySignature"; BadIf = "0"; Desc = "SMB signing not required" },

        # ═══ Startup settings ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "Userinit"; BadIf = "notdefault"; Desc = "Winlogon Userinit value differs from default" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "AppInit_DLLs"; BadIf = "exists_nonempty"; Desc = "AppInit_DLLs value is set" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "LoadAppInit_DLLs"; BadIf = "1"; Desc = "AppInit_DLLs loading enabled" },

        # ═══ Audit policy settings ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name = "ProcessCreationIncludeCmdLine_Enabled"; BadIf = "0"; Desc = "Process command-line auditing disabled" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Name = "MaxSize"; BadIf = "toosmall"; Desc = "Security event log size check" }
    )

    foreach ($check in $tamperChecks) {
        try {
            # Special case: check if key itself exists
            if ($check.Name -eq "(KeyExists)") {
                $regInfo = & $getRegVal $check.Path "(KeyExists)"
                if ($regInfo.Exists) {
                    $alertKey = "TAMPER:$($check.Path)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY CHANGE" $check.Desc -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path" = $check.Path
                            "Info"          = $check.Desc
                            "Suggestion"    = "Review whether this key should exist"
                        }
                    }
                }
                continue
            }

            # Special case: Winlogon Shell check
            if ($check.BadIf -eq "notexplorer") {
                $val = (& $getRegVal $check.Path $check.Name).Value
                if ($val -and $val -ne "explorer.exe") {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY CHANGE" "$($check.Desc) - Current: $val" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Value Name"     = $check.Name
                            "Current Value"  = "$val"
                            "Expected Value" = "explorer.exe"
                            "Info"           = $check.Desc
                        }
                    }
                }
                continue
            }

            # Special case: Winlogon Userinit check
            if ($check.BadIf -eq "notdefault") {
                $val = (& $getRegVal $check.Path $check.Name).Value
                $defaultUserinit = "C:\Windows\system32\userinit.exe,"
                if ($val -and $val -ne $defaultUserinit -and $val -ne "C:\Windows\system32\userinit.exe") {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY CHANGE" "$($check.Desc) - Current: $val" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Value Name"     = $check.Name
                            "Current Value"  = "$val"
                            "Expected"       = $defaultUserinit
                            "Info"           = "Startup program differs from default"
                        }
                    }
                }
                continue
            }

            # Special case: AppInit_DLLs non-empty check
            if ($check.BadIf -eq "exists_nonempty") {
                $val = (& $getRegVal $check.Path $check.Name).Value
                if ($val -and "$val".Trim().Length -gt 0) {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY CHANGE" "$($check.Desc) - DLLs: $val" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Loaded DLLs"    = "$val"
                            "Info"           = "DLL loading configured via AppInit_DLLs"
                            "Suggestion"     = "You can clear AppInit_DLLs and set LoadAppInit_DLLs to 0"
                        }
                    }
                }
                continue
            }

            # Special case: Event log size check
            if ($check.BadIf -eq "toosmall") {
                $val = (& $getRegVal $check.Path $check.Name).Value
                if ($val -and [int]$val -lt 1048576) {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY CHANGE" "Security event log size: $([math]::Round($val/1024))KB" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Current Size"   = "$([math]::Round($val/1024))KB"
                            "Recommended Min." = "1024KB (1MB)"
                            "Info"           = "Small log size causes older entries to be overwritten faster"
                        }
                    }
                }
                continue
            }

            # Special case: Skip scheduled task tree check (handled separately below)
            if ($check.BadIf -eq "checkchildren") { continue }

            $regInfo = & $getRegVal $check.Path $check.Name
            if (-not $regInfo.Exists) { continue }
            $val = $regInfo.Value
            if ($null -eq $val) { continue }

            $isBad = $false
            if ($check.BadIf -eq "exists") {
                $isBad = $true
            } elseif ("$val" -eq "$($check.BadIf)") {
                $isBad = $true
            }

            if ($isBad) {
                $alertKey = "TAMPER:$($check.Path)\$($check.Name)=$val"
                if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                    $script:TamperAlerted[$alertKey] = $true
                    $extraInfo = @{
                        "Registry Path"  = $check.Path
                        "Value Name"     = $check.Name
                        "Current Value"  = "$val"
                        "Info"           = $check.Desc
                    }
                    if ($check.BadIf -eq "exists") {
                        $extraInfo["Suggestion"] = "This value is not normally present - you can delete it if needed"
                    } else {
                        # Value exists but has wrong value - provide safe default for restore
                        $safeDefaults = @{
                            "0" = "1"   # If bad=0, safe=1 (enable features)
                            "1" = "0"   # If bad=1, safe=0 (disable bad policies)
                            "4" = "2"   # If bad=4 (disabled service), safe=2 (auto start)
                        }
                        $safeVal = $safeDefaults[$check.BadIf]
                        if ($safeVal) {
                            $extraInfo["Expected Value"] = $safeVal
                            $extraInfo["Suggestion"] = "You can restore to default value ('$safeVal')"
                        } else {
                            $extraInfo["Suggestion"] = "Review this setting and correct if needed"
                        }
                    }
                    Send-Alert "REGISTRY CHANGE" $check.Desc -Category "Registry Tampering" -ExtraDetails $extraInfo
                }
            }
        } catch {}
    }

    # Check DisallowRun list for blocked security executables
    try {
        $disallowPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
        if (Test-Path $disallowPath) {
            $props = Get-ItemProperty -Path $disallowPath -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match "^\d+$" -and $p.Value -match "(?i)(powershell|cmd|regedit|taskmgr|mmc|eventvwr|msconfig|perfmon|procexp|autoruns|wireshark)") {
                    $alertKey = "TAMPER:DisallowRun:$($p.Value)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "EXECUTABLE BLOCKED" "In DisallowRun list: $($p.Value)" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"   = $disallowPath
                            "Blocked Exe"     = $p.Value
                            "Info"            = "Blocked via DisallowRun policy"
                            "Suggestion"      = "You can remove this entry if needed"
                        }
                    }
                }
            }
        }
    } catch {}

    # Check Defender exclusions for suspicious entries
    try {
        $exclPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes"
        )
        foreach ($ep in $exclPaths) {
            if (Test-Path $ep) {
                $props = Get-ItemProperty -Path $ep -ErrorAction SilentlyContinue
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                        $alertKey = "TAMPER:Exclusion:$ep\$($p.Name)"
                        if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                            $script:TamperAlerted[$alertKey] = $true
                            Send-Alert "DEFENDER EXCLUSION" "Exclusion entry: $($p.Name)" -Category "Registry Tampering" -ExtraDetails @{
                                "Registry Path"    = $ep
                                "Excluded Target"  = $p.Name
                                "Info"             = "Item excluded from Defender scanning"
                                "Suggestion"       = "Verify this exclusion was added intentionally"
                            }
                        }
                    }
                }
            }
        }
    } catch {}

    # ═══ Check for suspicious scheduled tasks targeting PowerShell/SecurityMonitor ═══
    try {
        $suspiciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.State -ne "Disabled" -and $_.Actions
        } | ForEach-Object {
            $task = $_
            foreach ($action in $task.Actions) {
                if ($action.Execute -match '(?i)(powershell|pwsh|cmd|wscript|cscript)' -and
                    $action.Arguments -match '(?i)(kill|stop|taskkill|SecurityMonitor|Remove-Item|del\s|erase)') {
                    [PSCustomObject]@{
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                        Execute  = $action.Execute
                        Args     = $action.Arguments
                    }
                }
            }
        }
        foreach ($st in $suspiciousTasks) {
            $alertKey = "TAMPER:Task:$($st.TaskPath)$($st.TaskName)"
            if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                $script:TamperAlerted[$alertKey] = $true
                Send-Alert "SUSPICIOUS SCHEDULED TASK" "Task '$($st.TaskName)' may target SecurityMonitor" -Category "Registry Tampering" -ExtraDetails @{
                    "Task Name" = $st.TaskName
                    "Task Path" = $st.TaskPath
                    "Command"   = "$($st.Execute) $($st.Args)"
                    "Threat"    = "Scheduled task may kill/disable SecurityMonitor"
                    "Action"    = "Disable-ScheduledTask -TaskName '$($st.TaskName)' -TaskPath '$($st.TaskPath)'"
                }
            }
        }
    } catch {}

    # ═══ Check Run/RunOnce for anti-SecurityMonitor entries ═══
    try {
        $runPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($rp in $runPaths) {
            if (-not (Test-Path $rp)) { continue }
            $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                    if ($p.Value -match '(?i)(taskkill.*powershell|stop.*SecurityMonitor|del.*SecurityMonitor|Remove-Item.*SecurityMonitor|kill.*powershell)') {
                        $alertKey = "TAMPER:Run:$rp\$($p.Name)"
                        if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                            $script:TamperAlerted[$alertKey] = $true
                            Send-Alert "ANTI-MONITOR STARTUP ENTRY" "Run key '$($p.Name)' targets SecurityMonitor" -Category "Registry Tampering" -ExtraDetails @{
                                "Registry Path" = $rp
                                "Entry Name"    = $p.Name
                                "Command"       = "$($p.Value)"
                                "Threat"        = "Startup entry designed to kill SecurityMonitor on boot"
                                "Action"        = "Remove-ItemProperty -Path '$rp' -Name '$($p.Name)'"
                            }
                        }
                    }
                }
            }
        }
    } catch {}
}

$script:TamperAlerted = @{}

# --- MAIN LOOP ---
function Start-Monitoring {
    $banner = @"

  ======================================================
    SECURITY MONITORING SYSTEM v7.1
    Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Computer: $env:COMPUTERNAME
    User: $env:USERNAME
    Scan Interval: $IntervalSeconds seconds
    Log Directory: $LogDir
  ======================================================

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Console "SecurityMonitor v7.0 starting..." "OK"
    Write-Log "=== MONITORING STARTED === Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"

    # ── Acquire a system-wide mutex so Launcher.ps1 can detect us ──
    $script:AppMutex = $null
    try {
        $createdNew = $false
        $script:AppMutex = [System.Threading.Mutex]::new($true, "Global\SecurityMonitor_Running", [ref]$createdNew)
        if (-not $createdNew) {
            Write-Warn "Another SecurityMonitor instance is already running - exiting."
            try { $script:AppMutex.ReleaseMutex() } catch {}
            $script:AppMutex.Dispose()
            $script:AppMutex = $null
            return
        }
        Write-Ok "Instance mutex acquired"
    } catch {
        Write-Warn "Could not create mutex: $($_.Exception.Message)"
    }

    # Initialize system tray icon FIRST - must happen before Application.Run()
    Initialize-TrayIcon
    Write-Ok "System tray icon initialized (click notifications for details)"

    $script:MonitorCycle = 0
    $script:FwCheckInterval = 30
    $script:MonitoringRunning = $true

    # ── Deferred init timer: runs heavy baseline work AFTER message pump starts ──
    # This ensures the tray icon is visible immediately on first run.
    $initTimer = New-Object System.Windows.Forms.Timer
    $initTimer.Interval = 200
    $initTimer.Add_Tick({
        $initTimer.Stop()
        $initTimer.Dispose()

        try {
            # Create baselines (heavy I/O - runs inside message loop now)
            $fwBaseline = $null
            if (Test-Path $FirmwareBaseline) {
                Write-Ok "Existing firmware baseline loaded"
                $fwBaseline = Get-Content $FirmwareBaseline -Raw | ConvertFrom-Json
            } else {
                $fwBaseline = New-FirmwareBaseline
            }

            if (-not (Test-Path $DriverBaseline)) {
                New-DriverBaseline
            } else {
                Write-Ok "Existing driver baseline loaded"
            }

            if (-not (Test-Path $ServiceBaseline)) {
                New-ServiceBaseline
            } else {
                Write-Ok "Existing service baseline loaded"
            }

            New-RegistryBaseline

            # Record existing processes
            Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } | ForEach-Object {
                $script:KnownProcesses[$_.Id] = @{ Name = $_.ProcessName; Path = $_.Path; Time = Get-Date }
            }

            # Record existing connections
            Get-ConnectionSnapshot | ForEach-Object {
                $key = "$($_.RemoteAddr):$($_.RemotePort)|$($_.PID)"
                $script:KnownRemotes[$key] = Get-Date
            }

            # Record existing listeners
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -notmatch "^(127\.|::1)" } | ForEach-Object {
                $key = "$($_.LocalAddress):$($_.LocalPort)"
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                $script:KnownListeners[$key] = $proc.ProcessName
            }

            # Initial hosts file hash
            try {
                $script:HostsHash = (Get-FileHash "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256).Hash
            } catch {}

            Write-Host ""
            Write-Ok "Monitoring active. Press Ctrl+C to stop."
            Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray

            # ── Background I/O runspace: does ALL heavy cmdlet calls off-UI-thread ──
            $script:MonitorCache.Running = $true
            $script:MonIORunspace = [runspacefactory]::CreateRunspace()
            $script:MonIORunspace.ApartmentState = "STA"
            $script:MonIORunspace.Open()
            $script:MonIORunspace.SessionStateProxy.SetVariable("cache", $script:MonitorCache)
            $script:MonIORunspace.SessionStateProxy.SetVariable("interval", $IntervalSeconds)
            $script:MonIOPS = [powershell]::Create().AddScript({
                param($cache, $interval)
                while ($cache.Running) {
                    try {
                        # Network connections (was ~340ms)
                        try {
                            $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                                Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" } |
                                ForEach-Object {
                                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                                    @{
                                        LocalAddr = $_.LocalAddress; LocalPort = $_.LocalPort
                                        RemoteAddr = $_.RemoteAddress; RemotePort = $_.RemotePort
                                        PID = $_.OwningProcess
                                        ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                                        ProcessPath = if ($proc) { "$($proc.Path)" } else { "" }
                                    }
                                }
                            $cache.Connections = @($conns)
                        } catch {}

                        # Listeners (was ~150ms)
                        try {
                            $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                                Where-Object { $_.LocalAddress -notmatch "^(127\.|::1)" } |
                                ForEach-Object {
                                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                                    @{
                                        LocalAddr = $_.LocalAddress; LocalPort = $_.LocalPort
                                        PID = $_.OwningProcess
                                        ProcessName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                                    }
                                }
                            $cache.Listeners = @($listeners)
                        } catch {}

                        # Processes (was ~5ms but Get-AuthenticodeSignature can be slow)
                        try {
                            $procs = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } |
                                ForEach-Object {
                                    @{ Id = $_.Id; Name = $_.ProcessName; Path = "$($_.Path)" }
                                }
                            $cache.Processes = @($procs)
                        } catch {}

                        # Registry tampering pre-read (was ~1100ms - the MAIN offender)
                        try {
                            $tamperResults = @()
                            $regPaths = @(
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell_ise.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MpCmdRun.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cmd.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mmc.exe", "Debugger"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin"),
                                @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
                                @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"),
                                @("HKCU:\Software\Microsoft\Windows Script\Settings", "AmsiEnable"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile", "EnableFirewall"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall"),
                                @("HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall"),
                                @("HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend", "Start"),
                                @("HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc", "Start"),
                                @("HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc", "Start"),
                                @("HKLM:\SYSTEM\CurrentControlSet\Services\EventLog", "Start"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
                                @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
                                @("HKLM:\SOFTWARE\Microsoft\Security Center", "AntiVirusDisableNotify"),
                                @("HKLM:\SOFTWARE\Microsoft\Security Center", "FirewallDisableNotify"),
                                @("HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "__PSLockdownPolicy"),
                                @("HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications", "ToastEnabled"),
                                @("HKCU:\Software\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter")
                            )
                            foreach ($rp in $regPaths) {
                                try {
                                    $pathExists = Test-Path $rp[0]
                                    $val = $null
                                    if ($pathExists -and $rp[1]) {
                                        $val = (Get-ItemProperty -Path $rp[0] -Name $rp[1] -ErrorAction SilentlyContinue).$($rp[1])
                                    }
                                    $tamperResults += @{ Path = $rp[0]; Name = $rp[1]; Exists = $pathExists; Value = $val }
                                } catch {
                                    $tamperResults += @{ Path = $rp[0]; Name = $rp[1]; Exists = $false; Value = $null }
                                }
                            }
                            # Also check special keys
                            $tamperResults += @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt"; Name = "(KeyExists)"; Exists = (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt"); Value = $null }
                            $cache.RegistryTamper = $tamperResults
                        } catch {}

                        # Critical registry keys hash check
                        try {
                            $regKeyData = @()
                            foreach ($key in @(
                                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                            )) {
                                $vals = @{}
                                try {
                                    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                                    if ($props) {
                                        foreach ($p in $props.PSObject.Properties) {
                                            if ($p.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                                                $vals[$p.Name] = "$($p.Value)"
                                            }
                                        }
                                    }
                                } catch {}
                                $regKeyData += @{ Key = $key; Values = $vals }
                            }
                            $cache.RegistryKeys = $regKeyData
                        } catch {}

                        # Hosts file hash
                        try {
                            $cache.HostsHash = (Get-FileHash "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        } catch {}

                        $cache.Cycle++
                        $cache.Ready = $true
                    } catch {}
                    Start-Sleep -Seconds $interval
                }
            }).AddArgument($script:MonitorCache).AddArgument($IntervalSeconds)
            $script:MonIOPS.Runspace = $script:MonIORunspace
            $script:MonIOHandle = $script:MonIOPS.BeginInvoke()

            # ── UI Monitor Timer: reads from cache (instant), processes results, sends alerts ──
            $script:LastMonCycle = 0
            $script:MonitorTimer = New-Object System.Windows.Forms.Timer
            $script:MonitorTimer.Interval = 2000
            $script:MonitorTimer.Add_Tick({
                try {
                    if (-not $script:MonitorCache.Ready) { return }
                    if ($script:MonitorCache.Cycle -eq $script:LastMonCycle) { return }
                    $script:LastMonCycle = $script:MonitorCache.Cycle
                    $script:MonitorCycle++
                    $ts = Get-Date -Format "HH:mm:ss"

                    # Process cached connections (no I/O here - just comparisons)
                    $cachedConns = $script:MonitorCache.Connections
                    if ($cachedConns) {
                        foreach ($conn in $cachedConns) {
                            $key = "$($conn.RemoteAddr):$($conn.RemotePort)|$($conn.PID)"
                            if (-not $script:KnownRemotes.ContainsKey($key)) {
                                $script:KnownRemotes[$key] = Get-Date
                                $isKnown = $conn.ProcessName -in $script:WhitelistedProcesses
                                Write-Log "NEW CONNECTION: $($conn.ProcessName) (PID:$($conn.PID)) -> $($conn.RemoteAddr):$($conn.RemotePort)" -Level "INFO" -Target $ConnectionLog
                                if (-not $isKnown) {
                                    Send-Alert "UNKNOWN CONNECTION" "$($conn.ProcessName) -> $($conn.RemoteAddr):$($conn.RemotePort)" -Category "Connection" -RemoteIP $conn.RemoteAddr -ExtraDetails @{
                                        "Process Name" = $conn.ProcessName; "Process Path" = $conn.ProcessPath
                                        "PID" = "$($conn.PID)"; "Remote" = "$($conn.RemoteAddr):$($conn.RemotePort)"
                                    }
                                }
                            }
                        }
                        $currentKeys = $cachedConns | ForEach-Object { "$($_.RemoteAddr):$($_.RemotePort)|$($_.PID)" }
                        $staleKeys = @($script:KnownRemotes.Keys) | Where-Object { $_ -notin $currentKeys }
                        foreach ($k in $staleKeys) { $script:KnownRemotes.Remove($k) }
                    }

                    # Process cached listeners
                    $cachedListeners = $script:MonitorCache.Listeners
                    if ($cachedListeners) {
                        foreach ($l in $cachedListeners) {
                            $key = "$($l.LocalAddr):$($l.LocalPort)"
                            if (-not $script:KnownListeners.ContainsKey($key)) {
                                $script:KnownListeners[$key] = $l.ProcessName
                                if ($l.ProcessName -notin $script:WhitelistedProcesses) {
                                    Send-Alert "NEW LISTENER" "$($l.ProcessName) on port $($l.LocalPort)" -Category "Listener" -ExtraDetails @{
                                        "Process" = $l.ProcessName; "Port" = "$($l.LocalAddr):$($l.LocalPort)"
                                    }
                                }
                            }
                        }
                    }

                    # Process cached processes
                    $cachedProcs = $script:MonitorCache.Processes
                    if ($cachedProcs) {
                        foreach ($proc in $cachedProcs) {
                            if (-not $script:KnownProcesses.ContainsKey($proc.Id)) {
                                $script:KnownProcesses[$proc.Id] = @{ Name = $proc.Name; Path = $proc.Path; Time = Get-Date }
                                $isKnown = $proc.Name -in $script:WhitelistedProcesses
                                Write-Log "NEW PROCESS: $($proc.Name) (PID:$($proc.Id)) | Path: $($proc.Path)" -Level "INFO" -Target $ProcessLog
                                if (-not $isKnown -and $proc.Path) {
                                    Send-Alert "NEW PROCESS" "$($proc.Name) (PID:$($proc.Id))" -Category "Process" -ExtraDetails @{
                                        "Process Name" = $proc.Name; "PID" = "$($proc.Id)"; "Path" = $proc.Path
                                    }
                                }
                            }
                        }
                        $currentPids = $cachedProcs | ForEach-Object { $_.Id }
                        $stalePids = @($script:KnownProcesses.Keys) | Where-Object { $_ -notin $currentPids }
                        foreach ($p in $stalePids) { $script:KnownProcesses.Remove($p) }
                    }

                    # Process cached registry tampering (was 1100ms, now instant)
                    Watch-RegistryTampering
                    Watch-Registry
                    Watch-HostsFile
                    Watch-SecurityEvents

                    # Firmware/driver/service checks on longer interval
                    if ($script:MonitorCycle % $script:FwCheckInterval -eq 0) {
                        $fwChanges = Compare-FirmwareBaseline
                        if ($fwChanges -and $fwChanges.Count -gt 0) {
                            foreach ($change in $fwChanges) {
                                Send-Alert "FIRMWARE $($change.Type)" "$($change.File) - $($change.Detail)" -Category "Firmware" -ExtraDetails @{
                                    "File Path" = $change.File; "Change Type" = $change.Type; "Detail" = $change.Detail
                                }
                            }
                        }
                        $drvChanges = Compare-DriverBaseline
                        if ($drvChanges) { foreach ($c in $drvChanges) { Send-Alert $c.Type $c.Detail -Category "Driver" } }
                        $svcChanges = Compare-ServiceBaseline
                        if ($svcChanges) { foreach ($c in $svcChanges) { Send-Alert $c.Type $c.Detail -Category "Service" -ExtraDetails $c.ExtraDetails } }
                    }

                    if ($script:MonitorCycle % 6 -eq 0) {
                        $uptime = (Get-Date) - $script:StartTime
                        $uptimeStr = "{0:D2}h {1:D2}m {2:D2}s" -f $uptime.Hours, $uptime.Minutes, $uptime.Seconds
                        Write-Host "[$ts] Uptime: $uptimeStr | Alerts: $($script:AlertCount) | Connections: $($script:KnownRemotes.Count) | Processes: $($script:KnownProcesses.Count)" -ForegroundColor DarkGray
                    }
                } catch {
                    Write-Warn "Monitor tick error: $($_.Exception.Message)"
                } finally {
                    if ($script:MonitoringRunning) { $script:MonitorTimer.Start() }
                }
            })
            $script:MonitorTimer.Start()
        } catch {
            Write-Warn "Init error: $($_.Exception.Message)"
        }
    })
    $initTimer.Start()

    # ── Signal file watcher: Launcher.ps1 drops a file to ask us to open the dashboard ──
    $script:SignalTimer = New-Object System.Windows.Forms.Timer
    $script:SignalTimer.Interval = 1000
    $script:SignalTimer.Add_Tick({
        try {
            $sigFile = Join-Path $env:TEMP "SecurityMonitor_OpenDashboard.signal"
            if (Test-Path $sigFile) {
                Remove-Item $sigFile -Force -ErrorAction SilentlyContinue
                try { Show-Dashboard } catch {}
            }
        } catch {}
    })
    $script:SignalTimer.Start()

    # Auto-open dashboard on first launch (skip in silent/tray-only mode)
    if (-not $Silent) {
        try { Show-Dashboard } catch { Write-Console "Auto-open dashboard error: $_" "ERROR" }
    }

    # Run the Windows Forms message loop (keeps UI responsive)
    [System.Windows.Forms.Application]::Run()
}

# --- START ---
try {
    Start-Monitoring
} catch {
    Write-Log "ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Alert "Monitoring error: $($_.Exception.Message)"
} finally {
    $script:MonitoringRunning = $false
    # Clean up tray icon
    if ($script:TrayIcon) {
        try { $script:TrayIcon.Visible = $false; $script:TrayIcon.Dispose() } catch {}
    }
    # Clean up dashboard
    if ($script:DashboardForm -and -not $script:DashboardForm.IsDisposed) {
        try { $script:DashboardForm.Dispose() } catch {}
    }
    # Clean up timers
    if ($script:SignalTimer) { try { $script:SignalTimer.Stop(); $script:SignalTimer.Dispose() } catch {} }
    if ($script:MonitorTimer) { try { $script:MonitorTimer.Stop(); $script:MonitorTimer.Dispose() } catch {} }
    # Stop background monitor I/O runspace
    if ($script:MonitorCache) { try { $script:MonitorCache.Running = $false } catch {} }
    if ($script:MonIOPS) { try { $script:MonIOPS.Stop(); $script:MonIOPS.Dispose() } catch {} }
    if ($script:MonIORunspace) { try { $script:MonIORunspace.Close(); $script:MonIORunspace.Dispose() } catch {} }
    if ($script:PulseTimer) { try { $script:PulseTimer.Stop(); $script:PulseTimer.Dispose() } catch {} }
    # Stop background runspace for dashboard data
    if ($script:DashCache) { try { $script:DashCache.Running = $false } catch {} }
    if ($script:DashPowerShell) { try { $script:DashPowerShell.Stop(); $script:DashPowerShell.Dispose() } catch {} }
    if ($script:DashRunspace) { try { $script:DashRunspace.Close(); $script:DashRunspace.Dispose() } catch {} }
    if ($script:DashTimer) { try { $script:DashTimer.Stop(); $script:DashTimer.Dispose() } catch {} }
    # Release instance mutex
    if ($script:AppMutex) {
        try { $script:AppMutex.ReleaseMutex() } catch {}
        try { $script:AppMutex.Dispose() } catch {}
    }
    Write-Log "=== MONITORING STOPPED === Total alerts: $script:AlertCount" -Level "INFO"
    Write-Host "`nMonitoring stopped. Total alerts: $script:AlertCount" -ForegroundColor Yellow
    Write-Host "Log files: $LogDir" -ForegroundColor Cyan
    Write-Console "Monitoring stopped. Total alerts: $script:AlertCount" "WARN"
}
