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
    5.0.0
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

# --- ALERT HISTORY (for GUI detail view) ---
$script:AlertHistory = [System.Collections.ArrayList]@()
$script:DashboardForm = $null

# ============================================================================
#  UNIFIED DASHBOARD GUI - All features in one modern tabbed window
# ============================================================================
function Show-Dashboard {
    param([string]$OpenTab = "Status")

    # If dashboard already open, bring to front
    try {
        if ($script:DashboardForm -and -not $script:DashboardForm.IsDisposed) {
            $script:DashboardForm.Show()
            $script:DashboardForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            $script:DashboardForm.BringToFront()
            $script:DashboardForm.Activate()
            return
        }
    } catch {
        $script:DashboardForm = $null
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

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
    $form.TopMost = $true

    # Minimize to tray instead of closing
    $form.Add_FormClosing({
        param($s, $e)
        $e.Cancel = $true
        $s.Hide()
    })

    $script:DashboardForm = $form

    # ── Sidebar (left navigation) ──
    $sidebar = New-Object System.Windows.Forms.Panel
    $sidebar.Location = New-Object System.Drawing.Point(0, 0)
    $sidebar.Size = New-Object System.Drawing.Size(200, 680)
    $sidebar.BackColor = $colSidebar
    $sidebar.Dock = "Left"
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
    $verLabel.Text = "v5.0 Dashboard"
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

    # ── Content area (right side) ──
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Location = New-Object System.Drawing.Point(200, 0)
    $contentPanel.Size = New-Object System.Drawing.Size(850, 680)
    $contentPanel.BackColor = $colBg
    $contentPanel.Dock = "Fill"
    $form.Controls.Add($contentPanel)

    # Create page panels (each tab is a Panel that fills contentPanel)
    $pages = @{}
    foreach ($pageName in @("Status", "Alerts", "Settings", "Logs")) {
        $p = New-Object System.Windows.Forms.Panel
        $p.Dock = "Fill"
        $p.BackColor = $colBg
        $p.Visible = $false
        $p.AutoScroll = $true
        $contentPanel.Controls.Add($p)
        $pages[$pageName] = $p
    }

    # Sidebar nav buttons
    $navButtons = @()
    $navItems = @(
        @{ Name = "Status";   Icon = "[S]"; Text = "  Status" },
        @{ Name = "Alerts";   Icon = "[A]"; Text = "  Alerts" },
        @{ Name = "Settings"; Icon = "[C]"; Text = "  Settings" },
        @{ Name = "Logs";     Icon = "[L]"; Text = "  Logs" }
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

    # Navigation switching function
    function Switch-Page {
        param([string]$targetName)
        foreach ($pKey in $pages.Keys) { $pages[$pKey].Visible = ($pKey -eq $targetName) }
        foreach ($nb in $navButtons) {
            if ($nb.Tag -eq $targetName) {
                $nb.BackColor = $colAccentDim
                $nb.ForeColor = $colTextMain
                $nb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            } else {
                $nb.BackColor = $colSidebar
                $nb.ForeColor = $colTextDim
                $nb.Font = New-Object System.Drawing.Font("Segoe UI", 10)
            }
        }
    }

    # Bind each nav button with its own captured tag value
    foreach ($b in $navButtons) {
        $tag = $b.Tag
        $b.Add_Click({ Switch-Page $tag }.GetNewClosure())
    }

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

    # Status indicator
    $statusDot = New-Object System.Windows.Forms.Label
    $statusDot.Text = "MONITORING ACTIVE"
    $statusDot.Location = New-Object System.Drawing.Point(540, 22)
    $statusDot.Size = New-Object System.Drawing.Size(250, 24)
    $statusDot.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $statusDot.ForeColor = $colGreen
    $statusDot.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $statusPage.Controls.Add($statusDot)

    # Stat cards
    function New-StatCard {
        param($parent, $x, $y, $label, $valueVar)
        $card = New-Object System.Windows.Forms.Panel
        $card.Location = New-Object System.Drawing.Point($x, $y)
        $card.Size = New-Object System.Drawing.Size(185, 90)
        $card.BackColor = $colCard
        $parent.Controls.Add($card)

        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $label
        $lbl.Location = New-Object System.Drawing.Point(12, 8)
        $lbl.Size = New-Object System.Drawing.Size(165, 20)
        $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $lbl.ForeColor = $colTextDim
        $card.Controls.Add($lbl)

        $val = New-Object System.Windows.Forms.Label
        $val.Text = "0"
        $val.Name = $valueVar
        $val.Location = New-Object System.Drawing.Point(12, 30)
        $val.Size = New-Object System.Drawing.Size(165, 50)
        $val.Font = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
        $val.ForeColor = $colTextMain
        $card.Controls.Add($val)
        return $val
    }

    $lblAlerts      = New-StatCard $statusPage 25  65  "Total Alerts"         "valAlerts"
    $lblConnections = New-StatCard $statusPage 220 65  "Active Connections"   "valConns"
    $lblProcesses   = New-StatCard $statusPage 415 65  "Tracked Processes"    "valProcs"
    $lblUptime      = New-StatCard $statusPage 610 65  "Uptime"               "valUptime"
    $lblUptime.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)

    # Computer info
    $infoBox = New-Object System.Windows.Forms.Panel
    $infoBox.Location = New-Object System.Drawing.Point(25, 170)
    $infoBox.Size = New-Object System.Drawing.Size(770, 75)
    $infoBox.BackColor = $colCard
    $statusPage.Controls.Add($infoBox)

    $infoItems = @(
        @{ L = "Computer";  V = $env:COMPUTERNAME; X = 15 },
        @{ L = "User";      V = $env:USERNAME;     X = 210 },
        @{ L = "Interval";  V = "${IntervalSeconds}s"; X = 405 },
        @{ L = "Log Dir";   V = $LogDir;           X = 540 }
    )
    foreach ($ii in $infoItems) {
        $il = New-Object System.Windows.Forms.Label
        $il.Text = $ii.L
        $il.Location = New-Object System.Drawing.Point($ii.X, 10)
        $il.Size = New-Object System.Drawing.Size(180, 18)
        $il.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $il.ForeColor = $colTextDim
        $infoBox.Controls.Add($il)

        $iv = New-Object System.Windows.Forms.Label
        $iv.Text = $ii.V
        $iv.Location = New-Object System.Drawing.Point($ii.X, 30)
        $iv.Size = New-Object System.Drawing.Size(180, 30)
        $iv.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
        $iv.ForeColor = $colTextMain
        $infoBox.Controls.Add($iv)
    }

    # Recent alerts preview on status page
    $recentLabel = New-Object System.Windows.Forms.Label
    $recentLabel.Text = "Recent Alerts"
    $recentLabel.Location = New-Object System.Drawing.Point(25, 260)
    $recentLabel.Size = New-Object System.Drawing.Size(300, 24)
    $recentLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $recentLabel.ForeColor = $colOrange
    $statusPage.Controls.Add($recentLabel)

    $recentList = New-Object System.Windows.Forms.ListView
    $recentList.Name = "recentList"
    $recentList.Location = New-Object System.Drawing.Point(25, 288)
    $recentList.Size = New-Object System.Drawing.Size(770, 300)
    $recentList.View = "Details"
    $recentList.FullRowSelect = $true
    $recentList.GridLines = $true
    $recentList.BackColor = $colCard
    $recentList.ForeColor = $colTextMain
    $recentList.Font = New-Object System.Drawing.Font("Consolas", 9)
    [void]$recentList.Columns.Add("Time", 130)
    [void]$recentList.Columns.Add("Category", 90)
    [void]$recentList.Columns.Add("Title", 180)
    [void]$recentList.Columns.Add("Message", 360)
    $recentList.Add_DoubleClick({
        try {
            $sel = $recentList.SelectedItems
            if ($sel.Count -gt 0) {
                $idx = $sel[0].Tag
                $ad = $script:AlertHistory[$idx]
                Show-AlertDetail -AlertData $ad -ParentForm $form
            }
        } catch {}
    })
    $statusPage.Controls.Add($recentList)

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 2: ALERTS (full history + detail panel)
    # ═══════════════════════════════════════════════════════════════
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
    $alertsPage.Controls.Add($alertCountLabel)

    # Full alert list
    $alertListView = New-Object System.Windows.Forms.ListView
    $alertListView.Name = "alertListView"
    $alertListView.Location = New-Object System.Drawing.Point(25, 58)
    $alertListView.Size = New-Object System.Drawing.Size(770, 290)
    $alertListView.View = "Details"
    $alertListView.FullRowSelect = $true
    $alertListView.GridLines = $true
    $alertListView.BackColor = $colCard
    $alertListView.ForeColor = $colTextMain
    $alertListView.Font = New-Object System.Drawing.Font("Consolas", 9)
    [void]$alertListView.Columns.Add("Time", 130)
    [void]$alertListView.Columns.Add("Category", 90)
    [void]$alertListView.Columns.Add("Title", 180)
    [void]$alertListView.Columns.Add("Message", 360)
    $alertsPage.Controls.Add($alertListView)

    # Detail panel below the list
    $detailBox = New-Object System.Windows.Forms.Panel
    $detailBox.Name = "detailBox"
    $detailBox.Location = New-Object System.Drawing.Point(25, 358)
    $detailBox.Size = New-Object System.Drawing.Size(770, 230)
    $detailBox.BackColor = $colCard
    $detailBox.AutoScroll = $true
    $alertsPage.Controls.Add($detailBox)

    $detailTitle = New-Object System.Windows.Forms.Label
    $detailTitle.Name = "detailTitle"
    $detailTitle.Text = "Select an alert to view details"
    $detailTitle.Location = New-Object System.Drawing.Point(15, 10)
    $detailTitle.Size = New-Object System.Drawing.Size(550, 26)
    $detailTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $detailTitle.ForeColor = $colTextDim
    $detailBox.Controls.Add($detailTitle)

    $detailContent = New-Object System.Windows.Forms.Panel
    $detailContent.Name = "detailContent"
    $detailContent.Location = New-Object System.Drawing.Point(15, 40)
    $detailContent.Size = New-Object System.Drawing.Size(730, 130)
    $detailContent.BackColor = $colCard
    $detailContent.AutoScroll = $true
    $detailBox.Controls.Add($detailContent)

    # IP Lookup button (hidden until connection alert selected)
    $ipLookupBtn = New-Object System.Windows.Forms.Button
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
    $ipLookupBtn.Add_Click({ if ($ipLookupBtn.Tag) { Start-Process "https://ipinfo.io/$($ipLookupBtn.Tag)" } })
    $detailBox.Controls.Add($ipLookupBtn)

    # Open log button
    $openLogBtn = New-Object System.Windows.Forms.Button
    $openLogBtn.Text = "Open Alert Log"
    $openLogBtn.Location = New-Object System.Drawing.Point(310, 180)
    $openLogBtn.Size = New-Object System.Drawing.Size(160, 34)
    $openLogBtn.FlatStyle = "Flat"
    $openLogBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $openLogBtn.ForeColor = $colTextMain
    $openLogBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $openLogBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $openLogBtn.Add_Click({ if (Test-Path $AlertFile) { Start-Process notepad.exe $AlertFile } })
    $detailBox.Controls.Add($openLogBtn)

    # Click on alert row → populate detail panel
    $alertListView.Add_SelectedIndexChanged({
        try {
            $sel = $alertListView.SelectedItems
            if ($sel.Count -eq 0) { return }
            $idx = $sel[0].Tag
            if ($idx -ge $script:AlertHistory.Count) { return }
            $ad = $script:AlertHistory[$idx]

            $detailTitle.Text = "$($ad.Title)"
            $detailTitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 50, 60)

            $detailContent.Controls.Clear()
            $dy = 0
            foreach ($key in $ad.Details.Keys) {
                $kl = New-Object System.Windows.Forms.Label
                $kl.Text = "${key}:"
                $kl.Location = New-Object System.Drawing.Point(0, $dy)
                $kl.Size = New-Object System.Drawing.Size(140, 20)
                $kl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                $kl.ForeColor = [System.Drawing.Color]::FromArgb(100, 160, 255)
                $detailContent.Controls.Add($kl)

                $vl = New-Object System.Windows.Forms.Label
                $vl.Text = "$($ad.Details[$key])"
                $vl.Location = New-Object System.Drawing.Point(145, $dy)
                $vl.Size = New-Object System.Drawing.Size(560, 20)
                $vl.Font = New-Object System.Drawing.Font("Consolas", 9)
                $vl.ForeColor = [System.Drawing.Color]::White
                $detailContent.Controls.Add($vl)
                $dy += 24
            }

            # Show/hide IP lookup button
            if ($ad.RemoteIP) {
                $ipLookupBtn.Text = "Lookup $($ad.RemoteIP) on ipinfo.io"
                $ipLookupBtn.Tag = "$($ad.RemoteIP)"
                $ipLookupBtn.Visible = $true
            } else {
                $ipLookupBtn.Visible = $false
            }
        } catch {}
    })

    # Track how many alerts we've already rendered
    $script:RenderedAlertCount = 0

    # Incremental refresh - only add NEW alerts since last render
    function Update-AlertsList {
        $total = $script:AlertHistory.Count
        if ($total -eq $script:RenderedAlertCount) { return }

        # Add only new items (from RenderedAlertCount to total-1)
        for ($i = $script:RenderedAlertCount; $i -lt $total; $i++) {
            $a = $script:AlertHistory[$i]
            $itemColor = $colTextMain
            if ($a.Category -eq "Connection") { $itemColor = $colOrange }
            elseif ($a.Category -eq "Process")  { $itemColor = $colRed }
            elseif ($a.Category -eq "Firmware") { $itemColor = [System.Drawing.Color]::FromArgb(255, 80, 80) }

            # Insert at top of alert list (newest first)
            $item = New-Object System.Windows.Forms.ListViewItem($a.Timestamp)
            $item.SubItems.Add($a.Category) | Out-Null
            $item.SubItems.Add($a.Title) | Out-Null
            $item.SubItems.Add($a.Message) | Out-Null
            $item.Tag = $i
            $item.ForeColor = $itemColor
            $alertListView.Items.Insert(0, $item) | Out-Null

            # Insert at top of recent list (keep max 10)
            $r = New-Object System.Windows.Forms.ListViewItem($a.Timestamp)
            $r.SubItems.Add($a.Category) | Out-Null
            $r.SubItems.Add($a.Title) | Out-Null
            $r.SubItems.Add($a.Message) | Out-Null
            $r.Tag = $i
            $r.ForeColor = $itemColor
            $recentList.Items.Insert(0, $r) | Out-Null
            while ($recentList.Items.Count -gt 10) {
                $recentList.Items.RemoveAt($recentList.Items.Count - 1)
            }
        }
        $script:RenderedAlertCount = $total
        $alertCountLabel.Text = "$total alerts"
        $lblAlerts.Text = "$($script:AlertCount)"
    }

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 3: SETTINGS (notification preferences - live edit)
    # ═══════════════════════════════════════════════════════════════
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

    $settingsCheckboxes = @{}
    $sy = 85
    foreach ($opt in $options) {
        $card = New-Object System.Windows.Forms.Panel
        $card.Location = New-Object System.Drawing.Point(25, $sy)
        $card.Size = New-Object System.Drawing.Size(770, 48)
        $card.BackColor = $colCard
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
        $card.Controls.Add($descLbl)

        # Instant save on toggle
        $capturedKey = $opt.Key
        $capturedCb = $cb
        $cb.Add_CheckedChanged({
            try {
                $script:NotifyConfig | Add-Member -MemberType NoteProperty -Name $capturedKey -Value $capturedCb.Checked -Force
                $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
            } catch {}
        }.GetNewClosure())

        $sy += 52
    }

    # Select All / Deselect All buttons
    $selAllBtn = New-Object System.Windows.Forms.Button
    $selAllBtn.Text = "Select All"
    $selAllBtn.Location = New-Object System.Drawing.Point(25, ($sy + 10))
    $selAllBtn.Size = New-Object System.Drawing.Size(120, 34)
    $selAllBtn.FlatStyle = "Flat"
    $selAllBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $selAllBtn.ForeColor = $colTextMain
    $selAllBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $selAllBtn.Add_Click({ foreach ($c in $settingsCheckboxes.Values) { $c.Checked = $true } })
    $settingsPage.Controls.Add($selAllBtn)

    $deselAllBtn = New-Object System.Windows.Forms.Button
    $deselAllBtn.Text = "Deselect All"
    $deselAllBtn.Location = New-Object System.Drawing.Point(155, ($sy + 10))
    $deselAllBtn.Size = New-Object System.Drawing.Size(120, 34)
    $deselAllBtn.FlatStyle = "Flat"
    $deselAllBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $deselAllBtn.ForeColor = $colTextMain
    $deselAllBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $deselAllBtn.Add_Click({ foreach ($c in $settingsCheckboxes.Values) { $c.Checked = $false } })
    $settingsPage.Controls.Add($deselAllBtn)

    $savedLabel = New-Object System.Windows.Forms.Label
    $savedLabel.Text = "Settings are saved automatically"
    $savedLabel.Location = New-Object System.Drawing.Point(290, ($sy + 16))
    $savedLabel.Size = New-Object System.Drawing.Size(300, 20)
    $savedLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $savedLabel.ForeColor = $colGreen
    $settingsPage.Controls.Add($savedLabel)

    # ═══════════════════════════════════════════════════════════════
    #  PAGE 4: LOGS (open/view log files)
    # ═══════════════════════════════════════════════════════════════
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
        $openBtn.Location = New-Object System.Drawing.Point(610, 12)
        $openBtn.Size = New-Object System.Drawing.Size(70, 32)
        $openBtn.FlatStyle = "Flat"
        $openBtn.BackColor = $colAccentDim
        $openBtn.ForeColor = $colTextMain
        $openBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $capturedFile = $lf.File
        $openBtn.Add_Click({ if (Test-Path $capturedFile) { Start-Process notepad.exe $capturedFile } })
        $logCard.Controls.Add($openBtn)

        $folderBtn = New-Object System.Windows.Forms.Button
        $folderBtn.Text = "Folder"
        $folderBtn.Location = New-Object System.Drawing.Point(690, 12)
        $folderBtn.Size = New-Object System.Drawing.Size(70, 32)
        $folderBtn.FlatStyle = "Flat"
        $folderBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
        $folderBtn.ForeColor = $colTextMain
        $folderBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $folderBtn.Add_Click({ Start-Process explorer.exe $LogDir })
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
        $capturedBl = $bl.File
        $blOpenBtn.Add_Click({ if (Test-Path $capturedBl) { Start-Process notepad.exe $capturedBl } })
        $blCard.Controls.Add($blOpenBtn)

        $ly += 50
    }

    # ── Status updater timer ──
    $script:DashTimer = New-Object System.Windows.Forms.Timer
    $script:DashTimer.Interval = 5000
    $script:DashTimer.Add_Tick({
        try {
            if ($form.Visible -and -not $form.IsDisposed) {
                $lblAlerts.Text = "$($script:AlertCount)"
                $lblConnections.Text = "$($script:KnownRemotes.Count)"
                $lblProcesses.Text = "$($script:KnownProcesses.Count)"
                $up = (Get-Date) - $script:StartTime
                $lblUptime.Text = "{0:D2}h {1:D2}m" -f [int]$up.TotalHours, $up.Minutes
                Update-AlertsList
            }
        } catch {}
    })
    $script:DashTimer.Start()

    # Open default tab
    Switch-Page $OpenTab

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
    $script:TrayIcon.Icon = [System.Drawing.SystemIcons]::Shield
    $script:TrayIcon.Text = "SecurityMonitor - Click to open Dashboard"
    $script:TrayIcon.Visible = $true

    # LEFT CLICK on tray icon → open Dashboard
    $script:TrayIcon.Add_Click({
        param($s, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            Show-Dashboard
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
    $dashItem.Add_Click({ Show-Dashboard })
    $contextMenu.Items.Add($dashItem) | Out-Null

    $alertsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Alerts")
    $alertsItem.Add_Click({ Show-Dashboard -OpenTab "Alerts" })
    $contextMenu.Items.Add($alertsItem) | Out-Null

    $settingsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Settings")
    $settingsItem.Add_Click({ Show-Dashboard -OpenTab "Settings" })
    $contextMenu.Items.Add($settingsItem) | Out-Null

    $logsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Logs")
    $logsItem.Add_Click({ Show-Dashboard -OpenTab "Logs" })
    $contextMenu.Items.Add($logsItem) | Out-Null

    $contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("Stop Monitoring")
    $exitItem.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 80)
    $exitItem.Add_Click({
        $script:TrayIcon.Visible = $false
        $script:TrayIcon.Dispose()
        [Environment]::Exit(0)
    })
    $contextMenu.Items.Add($exitItem) | Out-Null

    $script:TrayIcon.ContextMenuStrip = $contextMenu

    # Click on balloon tip: open ipinfo.io for IP + show dashboard alerts tab
    $script:TrayIcon.Add_BalloonTipClicked({
        if ($null -ne $script:LastAlertData) {
            if ($script:LastAlertData.RemoteIP) {
                Start-Process "https://ipinfo.io/$($script:LastAlertData.RemoteIP)"
            }
            Show-Dashboard -OpenTab "Alerts"
        }
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
            $tipText = $Message
            if ($AlertData -and $AlertData.RemoteIP) {
                $tipText = "$Message`nClick to lookup IP on ipinfo.io"
            } else {
                $tipText = "$Message`nClick to view details"
            }
            $script:TrayIcon.BalloonTipText = $tipText
            $script:TrayIcon.ShowBalloonTip(8000)
            return $true
        } catch {}
    }

    # Fallback: Toast notification with launch action
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        $launchUrl = ""
        if ($AlertData -and $AlertData.RemoteIP) {
            $launchUrl = "https://ipinfo.io/$($AlertData.RemoteIP)"
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

function Send-Alert {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Category = "",
        [string]$RemoteIP = "",
        [hashtable]$ExtraDetails = @{}
    )
    $script:AlertCount++
    Write-Log "$Title - $Message" -Level "ALERT"

    # Build alert data for GUI
    $alertData = @{
        Title     = $Title
        Message   = $Message
        Category  = $Category
        RemoteIP  = $RemoteIP
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Details   = @{
            "Alert Type"  = $Title
            "Description" = $Message
            "Computer"    = $env:COMPUTERNAME
            "User"        = $env:USERNAME
        }
    }
    # Merge extra details
    foreach ($key in $ExtraDetails.Keys) {
        $alertData.Details[$key] = $ExtraDetails[$key]
    }
    # Add IP-specific details for connection alerts
    if ($Category -eq "Connection" -and $RemoteIP) {
        $alertData.Details["Remote IP"]   = $RemoteIP
        $alertData.Details["IP Lookup"]   = "https://ipinfo.io/$RemoteIP"
    }

    [void]$script:AlertHistory.Add($alertData)

    # Only send toast notification if this category is enabled in user preferences
    $shouldNotify = $true
    if ($Category -ne "" -and -not (Test-NotifyEnabled -Category $Category)) {
        $shouldNotify = $false
    }

    if ($shouldNotify) {
        Send-ToastNotification -Title $Title -Message $Message -AlertData $alertData
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
    SECURITY MONITORING SYSTEM v5.0
    Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Computer: $env:COMPUTERNAME
    User: $env:USERNAME
    Scan Interval: $IntervalSeconds seconds
    Log Directory: $LogDir
  ======================================================

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Log "=== MONITORING STARTED === Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"

    # Initialize system tray icon for clickable notifications
    Initialize-TrayIcon
    Write-Ok "System tray icon initialized (click notifications for details)"

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
                    Send-Alert "FIRMWARE $($change.Type)" "$($change.File) - $($change.Detail)" -Category "Firmware" -ExtraDetails @{
                    "File Path"    = $change.File
                    "Change Type"  = $change.Type
                    "Detail"       = $change.Detail
                }
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

        # Process Windows Forms events so tray icon and click handlers stay responsive
        [System.Windows.Forms.Application]::DoEvents()

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
    # Clean up tray icon
    if ($script:TrayIcon) {
        $script:TrayIcon.Visible = $false
        $script:TrayIcon.Dispose()
    }
    Write-Log "=== MONITORING STOPPED === Total alerts: $script:AlertCount" -Level "INFO"
    Write-Host "`nMonitoring stopped. Total alerts: $script:AlertCount" -ForegroundColor Yellow
    Write-Host "Log files: $LogDir" -ForegroundColor Cyan
}
