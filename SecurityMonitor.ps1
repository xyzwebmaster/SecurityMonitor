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
    3.0.0
#>

param(
    [int]$IntervalSeconds = 10,
    [string]$LogDir = "$PSScriptRoot\Logs",
    [string]$BaselineDir = "$PSScriptRoot\Baselines",
    [switch]$Silent
)

# --- NOTIFICATION PREFERENCES GUI ---
$ConfigFile = Join-Path $PSScriptRoot "notification_config.json"

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
    $saveBtn.Text = "Save && Start Monitoring"
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
        return $config
    } else {
        # User closed the window - enable everything by default
        $config = @{}
        foreach ($opt in $options) { $config[$opt.Key] = $true }
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

# --- CONFIGURATION ---
$ErrorActionPreference = "SilentlyContinue"
$script:StartTime = Get-Date
$script:AlertCount = 0

# Color-coded output functions
function Write-Status  { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok      { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Alert   { param($Msg) Write-Host "[!] ALERT: $Msg" -ForegroundColor Red }
function Write-Warn    { param($Msg) Write-Host "[~] $Msg" -ForegroundColor Yellow }

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

# --- WINDOWS TOAST NOTIFICATION ---
function Send-ToastNotification {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Severity = "Warning"
    )
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        $template = @"
<toast duration="long">
    <visual>
        <binding template="ToastGeneric">
            <text>SecurityMonitor: $Title</text>
            <text>$Message</text>
            <text placement="attribution">Security Alert - $(Get-Date -Format 'HH:mm:ss')</text>
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
        try {
            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
            $balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon = [System.Drawing.SystemIcons]::Warning
            $balloon.BalloonTipIcon = "Warning"
            $balloon.BalloonTipTitle = "SecurityMonitor: $Title"
            $balloon.BalloonTipText = $Message
            $balloon.Visible = $true
            $balloon.ShowBalloonTip(5000)
            Start-Sleep -Milliseconds 100
            return $true
        } catch {
            return $false
        }
    }
}

function Send-Alert {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Category = ""
    )
    $script:AlertCount++
    Write-Log "$Title - $Message" -Level "ALERT"

    # Only send toast notification if this category is enabled in user preferences
    $shouldNotify = $true
    if ($Category -ne "" -and -not (Test-NotifyEnabled -Category $Category)) {
        $shouldNotify = $false
    }

    if ($shouldNotify) {
        Send-ToastNotification -Title $Title -Message $Message
    }

    if (-not $Silent) {
        Write-Alert "$Title - $Message"
        if ($shouldNotify) {
            try { [System.Console]::Beep(1000, 300); [System.Console]::Beep(1500, 300) } catch {}
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
    $current = Get-Service | Select-Object Name, Status, StartType
    $baseNames = $baseline | ForEach-Object { $_.Name }
    $changes = @()
    foreach ($s in $current) {
        if ($s.Name -notin $baseNames) {
            $changes += @{ Service = $s.Name; Type = "NEW_SERVICE"; Detail = "New service detected: $($s.Name) [$($s.Status)]" }
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
                Send-Alert "UNKNOWN CONNECTION" "$($conn.ProcessName) -> $($conn.RemoteAddr):$($conn.RemotePort)" -Category "Connection"
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
                Send-Alert "UNSIGNED PROCESS" "$($proc.ProcessName) (PID:$($proc.Id)) - $($proc.Path)" -Category "Process"
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
                Send-Alert "NEW LISTENING PORT" "$key - $($proc.ProcessName)" -Category "Listener"
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
        if ($hash) { $script:RegistryBaseline[$key] = $hash }
    }
    Write-Ok "Registry baseline created ($($keys.Count) keys)"
}

function Watch-Registry {
    $criticalKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $criticalKeys) {
        $hash = Get-RegistryHash -KeyPath $key
        if ($hash -and $script:RegistryBaseline.ContainsKey($key) -and $script:RegistryBaseline[$key] -ne $hash) {
            Send-Alert "REGISTRY CHANGED" "Key: $key" -Category "Registry"
            Write-Log "Registry change: $key | Old: $($script:RegistryBaseline[$key].Substring(0,16))... New: $($hash.Substring(0,16))..." -Level "ALERT"
            $script:RegistryBaseline[$key] = $hash
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
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    try {
        $hash = (Get-FileHash -Path $hostsPath -Algorithm SHA256).Hash
        if ($null -eq $script:HostsHash) {
            $script:HostsHash = $hash
        } elseif ($script:HostsHash -ne $hash) {
            Send-Alert "HOSTS FILE MODIFIED" "DNS redirection may have changed!" -Category "Hosts"
            $script:HostsHash = $hash
        }
    } catch {}
}

# --- MAIN LOOP ---
function Start-Monitoring {
    $banner = @"

  ======================================================
    SECURITY MONITORING SYSTEM v3.0
    Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Computer: $env:COMPUTERNAME
    User: $env:USERNAME
    Scan Interval: $IntervalSeconds seconds
    Log Directory: $LogDir
  ======================================================

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Log "=== MONITORING STARTED === Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"

    # Create baselines
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

    $cycle = 0
    $fwCheckInterval = 30

    while ($true) {
        $cycle++
        $ts = Get-Date -Format "HH:mm:ss"

        Watch-Connections
        Watch-Processes
        Watch-Listeners
        Watch-SecurityEvents
        Watch-Registry
        Watch-HostsFile

        if ($cycle % $fwCheckInterval -eq 0) {
            Write-Status "[$ts] Running firmware integrity check..."
            $fwChanges = Compare-FirmwareBaseline
            if ($fwChanges -and $fwChanges.Count -gt 0) {
                foreach ($change in $fwChanges) {
                    Send-Alert "FIRMWARE $($change.Type)" "$($change.File) - $($change.Detail)" -Category "Firmware"
                }
            }

            $drvChanges = Compare-DriverBaseline
            if ($drvChanges -and $drvChanges.Count -gt 0) {
                foreach ($change in $drvChanges) {
                    Send-Alert $change.Type $change.Detail -Category "Driver"
                }
            }

            $svcChanges = Compare-ServiceBaseline
            if ($svcChanges -and $svcChanges.Count -gt 0) {
                foreach ($change in $svcChanges) {
                    Send-Alert $change.Type $change.Detail -Category "Service"
                }
            }
        }

        if ($cycle % 6 -eq 0) {
            $uptime = (Get-Date) - $script:StartTime
            $uptimeStr = "{0:D2}h {1:D2}m {2:D2}s" -f $uptime.Hours, $uptime.Minutes, $uptime.Seconds
            Write-Host "[$ts] Uptime: $uptimeStr | Alerts: $($script:AlertCount) | Connections: $($script:KnownRemotes.Count) | Processes: $($script:KnownProcesses.Count)" -ForegroundColor DarkGray
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

# --- START ---
try {
    Start-Monitoring
} catch {
    Write-Log "ERROR: $($_.Exception.Message)" -Level "ERROR"
    Write-Alert "Monitoring error: $($_.Exception.Message)"
} finally {
    Write-Log "=== MONITORING STOPPED === Total alerts: $script:AlertCount" -Level "INFO"
    Write-Host "`nMonitoring stopped. Total alerts: $script:AlertCount" -ForegroundColor Yellow
    Write-Host "Log files: $LogDir" -ForegroundColor Cyan
}
