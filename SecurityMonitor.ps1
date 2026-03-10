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

    # If dashboard already open, bring to front, restart timers, and switch tab
    try {
        if ($script:DashboardForm -and -not $script:DashboardForm.IsDisposed) {
            $script:DashboardForm.Show()
            $script:DashboardForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            $script:DashboardForm.BringToFront()
            $script:DashboardForm.Activate()
            # Resume timers that were paused on hide
            try { if ($script:DashTimer)  { $script:DashTimer.Start() } } catch {}
            try { if ($script:PulseTimer) { $script:PulseTimer.Start() } } catch {}
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

    # Minimize to tray instead of closing - pause timers to save resources
    $form.Add_FormClosing({
        param($s, $e)
        $e.Cancel = $true
        $s.Hide()
        try { if ($script:DashTimer)  { $script:DashTimer.Stop() } } catch {}
        try { if ($script:PulseTimer) { $script:PulseTimer.Stop() } } catch {}
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
    foreach ($pageName in @("Status", "Alerts", "Settings", "Logs")) {
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
    $script:SwitchPageFn = {
        param([string]$targetName)
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
        @{ L = "Defender"; X = 12 },
        @{ L = "Firewall"; X = 165 },
        @{ L = "UAC";      X = 318 },
        @{ L = "RDP";      X = 471 }
    )
    $script:SecPostureDots = @{}
    $script:SecPostureLabels = @{}
    foreach ($spi in $spItems) {
        $dot = New-Object System.Windows.Forms.Panel
        $dot.Location = New-Object System.Drawing.Point($spi.X, 28)
        $dot.Size = New-Object System.Drawing.Size(12, 12)
        $dot.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $secPosturePanel.Controls.Add($dot)
        $script:SecPostureDots[$spi.L] = $dot

        $spLbl = New-Object System.Windows.Forms.Label
        $spLbl.Text = "$($spi.L): ..."
        $spLbl.Location = New-Object System.Drawing.Point(($spi.X + 18), 26)
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
                    $bgColor = [System.Drawing.Color]::FromArgb(0, 80, 150)
                } elseif ($isEven) {
                    $bgColor = [System.Drawing.Color]::FromArgb(28, 28, 44)
                } else {
                    $bgColor = [System.Drawing.Color]::FromArgb(34, 34, 52)
                }
                $bgBrush = New-Object System.Drawing.SolidBrush($bgColor)
                $e.Graphics.FillRectangle($bgBrush, $e.Bounds)
                $bgBrush.Dispose()

                # Text color
                if ($isSelected) {
                    $txtColor = [System.Drawing.Color]::White
                } else {
                    $txtColor = $e.Item.ForeColor
                    # Dim the non-primary columns slightly
                    if ($e.ColumnIndex -gt 0 -and -not $isSelected) {
                        if ($e.ColumnIndex -eq 1) {
                            # Category column - use item color but slightly brighter
                            $txtColor = $e.Item.ForeColor
                        } elseif ($e.ColumnIndex -ge 3) {
                            $txtColor = [System.Drawing.Color]::FromArgb(170, 170, 190)
                        }
                    }
                }
                $txtBrush = New-Object System.Drawing.SolidBrush($txtColor)
                $cellFont = $e.Item.Font
                if ($e.ColumnIndex -eq 0) {
                    $cellFont = New-Object System.Drawing.Font("Consolas", 8.5)
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
                if ($e.ColumnIndex -eq 0) { $cellFont.Dispose() }

                # Subtle separator line between rows
                $sepPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 40, 60), 1)
                $e.Graphics.DrawLine($sepPen, $e.Bounds.Left, ($e.Bounds.Bottom - 1), $e.Bounds.Right, ($e.Bounds.Bottom - 1))
                $sepPen.Dispose()
            } catch {
                $e.DrawDefault = $true
            }
        })
    }

    # ── System Health Gauges ──
    $healthLabel = New-Object System.Windows.Forms.Label
    $healthLabel.Text = "System Health"
    $healthLabel.Location = New-Object System.Drawing.Point(25, 390)
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

    $script:CpuGauge  = New-GaugeBar $statusPage 25  415 "CPU"  "cpuBar"
    $script:RamGauge  = New-GaugeBar $statusPage 275 415 "RAM"  "ramBar"
    $script:DiskGauge = New-GaugeBar $statusPage 525 415 "DISK" "diskBar"

    # Recent alerts preview on status page (Enhancement 4: "View All >>" link)
    $recentLabel = New-Object System.Windows.Forms.Label
    $recentLabel.Text = "Recent Alerts"
    $recentLabel.Location = New-Object System.Drawing.Point(25, 470)
    $recentLabel.Size = New-Object System.Drawing.Size(300, 24)
    $recentLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $recentLabel.ForeColor = $colOrange
    $statusPage.Controls.Add($recentLabel)

    # "View All >>" link next to Recent Alerts title
    $viewAllLink = New-Object System.Windows.Forms.LinkLabel
    $viewAllLink.Text = "View All >>"
    $viewAllLink.Location = New-Object System.Drawing.Point(700, 474)
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
    $recentList.Location = New-Object System.Drawing.Point(25, 498)
    $recentList.Size = New-Object System.Drawing.Size(770, 170)
    $recentList.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    Style-ListView $recentList
    [void]$recentList.Columns.Add("Time", 120)
    [void]$recentList.Columns.Add("Sev", 50)
    [void]$recentList.Columns.Add("Category", 90)
    [void]$recentList.Columns.Add("Title", 180)
    [void]$recentList.Columns.Add("Message", 310)
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
                    "CRIT" { [System.Drawing.Color]::FromArgb(255, 60, 60) }
                    "HIGH" { [System.Drawing.Color]::FromArgb(255, 160, 40) }
                    "MED"  { [System.Drawing.Color]::FromArgb(255, 220, 50) }
                    "LOW"  { [System.Drawing.Color]::White }
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
    $alertListView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    Style-ListView $alertListView
    [void]$alertListView.Columns.Add("Time", 120)
    [void]$alertListView.Columns.Add("Sev", 50)
    [void]$alertListView.Columns.Add("Category", 90)
    [void]$alertListView.Columns.Add("Title", 180)
    [void]$alertListView.Columns.Add("Message", 310)
    $alertsPage.Controls.Add($alertListView)

    # Detail panel below the list
    $detailBox = New-Object System.Windows.Forms.Panel
    $detailBox.Name = "detailBox"
    $detailBox.Location = New-Object System.Drawing.Point(25, 358)
    $detailBox.Size = New-Object System.Drawing.Size(770, 230)
    $detailBox.BackColor = $colCard
    $detailBox.AutoScroll = $true
    $detailBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
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
    $openLogBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $openLogBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $openLogBtn.Tag = $AlertFile
    $openLogBtn.Add_Click({ if ($this.Tag -and (Test-Path $this.Tag)) { Start-Process notepad.exe $this.Tag } })
    $detailBox.Controls.Add($openLogBtn)

    # Click on alert row → populate detail panel with auto-sizing
    $alertListView.Add_SelectedIndexChanged({
        try {
            $sel = $this.SelectedItems
            if ($sel.Count -eq 0) { return }
            $idx = $sel[0].Tag
            if ($idx -ge $script:AlertHistory.Count) { return }
            $ad = $script:AlertHistory[$idx]

            $script:DetailTitle.Text = "$($ad.Title)"
            $script:DetailTitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 50, 60)

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

            # Auto-resize DetailContent panel to fit all rows
            $script:DetailContent.Height = [Math]::Max(80, $dy + 5)

            # Reposition buttons below content
            $btnY = $script:DetailContent.Bottom + 8
            $script:IpLookupBtn.Location = New-Object System.Drawing.Point(15, $btnY)
            $script:OpenLogBtn.Location = New-Object System.Drawing.Point(310, $btnY)

            # Show/hide IP lookup button
            if ($ad.RemoteIP) {
                $script:IpLookupBtn.Text = "Lookup $($ad.RemoteIP) on ipinfo.io"
                $script:IpLookupBtn.Tag = "$($ad.RemoteIP)"
                $script:IpLookupBtn.Visible = $true
            } else {
                $script:IpLookupBtn.Visible = $false
            }
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

            for ($i = $script:RenderedAlertCount; $i -lt $total; $i++) {
                $a = $script:AlertHistory[$i]
                $itemColor = switch ($a.Severity) {
                    "CRIT" { [System.Drawing.Color]::FromArgb(255, 60, 60) }
                    "HIGH" { [System.Drawing.Color]::FromArgb(255, 160, 40) }
                    "MED"  { [System.Drawing.Color]::FromArgb(255, 220, 50) }
                    "LOW"  { [System.Drawing.Color]::White }
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
            $script:RenderedAlertCount = $total
            $script:AlertCountLabel.Text = "$total alerts"
            $script:LblAlerts.Text = "$($script:AlertCount)"
        } catch {}
    }

  } catch { Write-Host "[!] Alerts page error: $_" -ForegroundColor Red }

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

    # Select All / Deselect All buttons
    $selAllBtn = New-Object System.Windows.Forms.Button
    $selAllBtn.Text = "Select All"
    $selAllBtn.Location = New-Object System.Drawing.Point(25, ($sy + 10))
    $selAllBtn.Size = New-Object System.Drawing.Size(120, 34)
    $selAllBtn.FlatStyle = "Flat"
    $selAllBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $selAllBtn.ForeColor = $colTextMain
    $selAllBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $selAllBtn.Add_Click({
        $script:SuppressSettingsSave = $true
        foreach ($c in $script:SettingsCheckboxes.Values) { $c.Checked = $true }
        $script:SuppressSettingsSave = $false
        $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8
    })
    $settingsPage.Controls.Add($selAllBtn)

    $deselAllBtn = New-Object System.Windows.Forms.Button
    $deselAllBtn.Text = "Deselect All"
    $deselAllBtn.Location = New-Object System.Drawing.Point(155, ($sy + 10))
    $deselAllBtn.Size = New-Object System.Drawing.Size(120, 34)
    $deselAllBtn.FlatStyle = "Flat"
    $deselAllBtn.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $deselAllBtn.ForeColor = $colTextMain
    $deselAllBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $deselAllBtn.Add_Click({
        $script:SuppressSettingsSave = $true
        foreach ($c in $script:SettingsCheckboxes.Values) { $c.Checked = $false }
        $script:SuppressSettingsSave = $false
        $script:NotifyConfig | ConvertTo-Json | Set-Content -Path $script:ConfigFilePath -Encoding UTF8
    })
    $settingsPage.Controls.Add($deselAllBtn)

    $savedLabel = New-Object System.Windows.Forms.Label
    $savedLabel.Text = "Settings are saved automatically"
    $savedLabel.Location = New-Object System.Drawing.Point(290, ($sy + 16))
    $savedLabel.Size = New-Object System.Drawing.Size(300, 20)
    $savedLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $savedLabel.ForeColor = $colGreen
    $settingsPage.Controls.Add($savedLabel)

  } catch { Write-Host "[!] Settings page error: $_" -ForegroundColor Red }

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
  } catch { Write-Host "[!] Logs page error: $_" -ForegroundColor Red }

    # ── Status updater timer ──
    $script:DashTimer = New-Object System.Windows.Forms.Timer
    $script:DashTimer.Interval = 5000
    $script:DashTimer.Add_Tick({
        try {
            if ($script:DashboardForm -and $script:DashboardForm.Visible -and -not $script:DashboardForm.IsDisposed) {
                $script:LblAlerts.Text = "$($script:AlertCount)"
                $script:LblConnections.Text = "$($script:KnownRemotes.Count)"
                $script:LblProcesses.Text = "$($script:KnownProcesses.Count)"
                $up = (Get-Date) - $script:StartTime
                $script:LblUptime.Text = "{0:D2}h {1:D2}m" -f [int]$up.TotalHours, $up.Minutes
                & $script:UpdateAlertsListFn

                # Update scan count
                try { if ($script:ScanCountLabel) { $script:ScanCountLabel.Text = "$($script:MonitorCycle)" } } catch {}

                # Update CPU/RAM/Disk gauges
                try {
                    $cpuLoad = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 0)
                    $os = Get-CimInstance Win32_OperatingSystem
                    $ramUsed = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 0)
                    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
                    $diskUsed = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 0)

                    $maxW = 220
                    $colGreen  = [System.Drawing.Color]::FromArgb(0, 200, 100)
                    $colYellow = [System.Drawing.Color]::FromArgb(255, 220, 50)
                    $colRed    = [System.Drawing.Color]::FromArgb(255, 60, 60)

                    foreach ($gauge in @(@{G=$script:CpuGauge; V=$cpuLoad}, @{G=$script:RamGauge; V=$ramUsed}, @{G=$script:DiskGauge; V=$diskUsed})) {
                        $pct = [math]::Max(0, [math]::Min(100, $gauge.V))
                        $gauge.G.Label.Text = "$pct%"
                        $gauge.G.Fill.Width = [math]::Round($maxW * $pct / 100)
                        if ($pct -ge 90) { $gauge.G.Fill.BackColor = $colRed }
                        elseif ($pct -ge 70) { $gauge.G.Fill.BackColor = $colYellow }
                        else { $gauge.G.Fill.BackColor = $colGreen }
                    }
                } catch {}

                # Update Security Posture indicators
                try {
                    $colGreenSp = [System.Drawing.Color]::FromArgb(0, 200, 100)
                    $colRedSp   = [System.Drawing.Color]::FromArgb(255, 60, 60)
                    $colGraySp  = [System.Drawing.Color]::FromArgb(80, 80, 80)

                    # Defender
                    try {
                        $defStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                        if ($defStatus -and $defStatus.AntivirusEnabled) {
                            $script:SecPostureDots["Defender"].BackColor = $colGreenSp
                            $script:SecPostureLabels["Defender"].Text = "Defender: ON"
                            $script:SecPostureLabels["Defender"].ForeColor = $colGreenSp
                        } else {
                            $script:SecPostureDots["Defender"].BackColor = $colRedSp
                            $script:SecPostureLabels["Defender"].Text = "Defender: OFF"
                            $script:SecPostureLabels["Defender"].ForeColor = $colRedSp
                        }
                    } catch {
                        $script:SecPostureDots["Defender"].BackColor = $colGraySp
                        $script:SecPostureLabels["Defender"].Text = "Defender: N/A"
                    }

                    # Firewall
                    try {
                        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                        $allEnabled = ($fwProfiles | Where-Object { $_.Enabled }).Count -eq $fwProfiles.Count
                        if ($allEnabled) {
                            $script:SecPostureDots["Firewall"].BackColor = $colGreenSp
                            $script:SecPostureLabels["Firewall"].Text = "Firewall: ON"
                            $script:SecPostureLabels["Firewall"].ForeColor = $colGreenSp
                        } else {
                            $script:SecPostureDots["Firewall"].BackColor = $colRedSp
                            $script:SecPostureLabels["Firewall"].Text = "Firewall: PARTIAL"
                            $script:SecPostureLabels["Firewall"].ForeColor = $colRedSp
                        }
                    } catch {
                        $script:SecPostureDots["Firewall"].BackColor = $colGraySp
                        $script:SecPostureLabels["Firewall"].Text = "Firewall: N/A"
                    }

                    # UAC
                    try {
                        $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
                        if ($uacVal -eq 1) {
                            $script:SecPostureDots["UAC"].BackColor = $colGreenSp
                            $script:SecPostureLabels["UAC"].Text = "UAC: Enabled"
                            $script:SecPostureLabels["UAC"].ForeColor = $colGreenSp
                        } else {
                            $script:SecPostureDots["UAC"].BackColor = $colRedSp
                            $script:SecPostureLabels["UAC"].Text = "UAC: DISABLED"
                            $script:SecPostureLabels["UAC"].ForeColor = $colRedSp
                        }
                    } catch {}

                    # RDP
                    try {
                        $rdpVal = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
                        if ($rdpVal -eq 1) {
                            $script:SecPostureDots["RDP"].BackColor = $colGreenSp
                            $script:SecPostureLabels["RDP"].Text = "RDP: Disabled"
                            $script:SecPostureLabels["RDP"].ForeColor = $colGreenSp
                        } else {
                            $script:SecPostureDots["RDP"].BackColor = $colRedSp
                            $script:SecPostureLabels["RDP"].Text = "RDP: ENABLED"
                            $script:SecPostureLabels["RDP"].ForeColor = $colRedSp
                        }
                    } catch {}
                } catch {}

                # Update Network Activity summary
                try {
                    $netConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                        Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.|::1|::$)' }
                    $totalConns = if ($netConns) { $netConns.Count } else { 0 }
                    $topProcs = $netConns | Group-Object -Property OwningProcess |
                        Sort-Object Count -Descending | Select-Object -First 5 |
                        ForEach-Object {
                            $pName = (Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName
                            if (-not $pName) { $pName = "PID:$($_.Name)" }
                            "$pName($($_.Count))"
                        }
                    $topStr = if ($topProcs) { $topProcs -join "  |  " } else { "None" }
                    $script:NetActivityLabel.Text = "Active: $totalConns connections   Top: $topStr"
                } catch {}
            }
        } catch {}
    })
    $script:DashTimer.Start()

    # Set open tab and switch page
    $script:DashboardOpenTab = $OpenTab

    # Switch page immediately (sets Visible/BringToFront)
    try { & $script:SwitchPageFn $OpenTab } catch { Write-Host "[!] SwitchPage error: $_" -ForegroundColor Red }

    # Also switch after form is shown to ensure rendering
    $form.Add_Shown({
        try {
            & $script:SwitchPageFn $script:DashboardOpenTab
            $script:ContentPanel.Refresh()
        } catch { Write-Host "[!] Shown SwitchPage error: $_" -ForegroundColor Red }
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
            try { Show-Dashboard } catch { Write-Host "[!] Dashboard error: $_" -ForegroundColor Red }
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
    $dashItem.Add_Click({ try { Show-Dashboard } catch { Write-Host "[!] Dashboard error: $_" -ForegroundColor Red } })
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

function Get-AlertSeverity {
    param([string]$Title, [string]$Category)
    if ($Category -eq "Registry Tampering") { return "CRIT" }
    if ($Title -match "FIRMWARE.*(DELETED|MODIFIED)") { return "CRIT" }
    if ($Title -match "REGISTRY TAMPERING|EXECUTABLE BLOCKED|DEFENDER EXCLUSION") { return "CRIT" }
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
            "Severity"    = $severity
            "Alert Type"  = $Title
            "Description" = $Message
            "Computer"    = $env:COMPUTERNAME
            "User"        = $env:USERNAME
        }
    }
    foreach ($key in $ExtraDetails.Keys) {
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

    $shouldNotify = $true
    if ($Category -ne "" -and -not (Test-NotifyEnabled -Category $Category)) {
        $shouldNotify = $false
    }

    if ($shouldNotify) {
        $tipIcon = if ($severity -eq "CRIT") { "Error" } elseif ($severity -match "HIGH|MED") { "Warning" } else { "Info" }
        Send-ToastNotification -Title "[$severity] $Title" -Message $Message -AlertData $alertData
    }

    if (-not $Silent) {
        Write-Alert "[$severity] $Title - $Message"
        if ($shouldNotify) {
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

# --- ANTI-TAMPERING REGISTRY MONITORING ---
# Detects registry keys that hackers use to disable security tools, PowerShell, Defender, etc.
function Watch-RegistryTampering {
    $tamperChecks = @(
        # IFEO debugger redirects (blocks executables from running)
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on PowerShell - prevents PowerShell from running" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell_ise.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on PowerShell ISE" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Task Manager - blocks taskmgr" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Registry Editor" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Defender Engine - disables antivirus" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MpCmdRun.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Defender CLI" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cmd.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Command Prompt" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mmc.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Management Console" },

        # Windows Defender disabling
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; BadIf = "1"; Desc = "Windows Defender AntiSpyware DISABLED via policy" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; BadIf = "1"; Desc = "Windows Defender AntiVirus DISABLED via policy" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; BadIf = "1"; Desc = "Defender Real-Time Protection DISABLED" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; BadIf = "1"; Desc = "Defender Behavior Monitoring DISABLED" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; BadIf = "1"; Desc = "Defender On-Access Protection DISABLED" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; BadIf = "1"; Desc = "Defender Download Scanning DISABLED" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; BadIf = "1"; Desc = "Defender Scan on RT Enable DISABLED" },

        # UAC bypass / disable
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; BadIf = "0"; Desc = "UAC COMPLETELY DISABLED - critical security bypass" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; BadIf = "0"; Desc = "UAC admin prompt DISABLED - silent elevation" },

        # UAC bypass via COM hijacking
        @{ Path = "HKCU:\Software\Classes\ms-settings\shell\open\command"; Name = "(Default)"; BadIf = "exists"; Desc = "UAC BYPASS via ms-settings COM hijack" },
        @{ Path = "HKCU:\Software\Classes\mscfile\shell\open\command"; Name = "(Default)"; BadIf = "exists"; Desc = "UAC BYPASS via mscfile COM hijack" },

        # Disable Task Manager and system tools
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; BadIf = "1"; Desc = "Task Manager DISABLED via policy" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; BadIf = "1"; Desc = "Registry Editor DISABLED via policy" },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Name = "DisableCMD"; BadIf = "1"; Desc = "Command Prompt DISABLED via policy" },

        # PowerShell execution and logging
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; BadIf = "0"; Desc = "PowerShell Script Block Logging DISABLED - hides attacker commands" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; BadIf = "0"; Desc = "PowerShell Module Logging DISABLED" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableTranscripting"; BadIf = "0"; Desc = "PowerShell Transcription DISABLED" },

        # AMSI (Antimalware Scan Interface) disable
        @{ Path = "HKCU:\Software\Microsoft\Windows Script\Settings"; Name = "AmsiEnable"; BadIf = "0"; Desc = "AMSI DISABLED - allows malicious scripts to bypass scanning" },

        # Firewall disable
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall DISABLED (Standard profile)" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall DISABLED (Domain profile)" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall DISABLED (Public profile)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall service DISABLED (Standard)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"; Name = "EnableFirewall"; BadIf = "0"; Desc = "Windows Firewall service DISABLED (Public)" },

        # Event Log tampering
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name = "Enabled"; BadIf = "0"; Desc = "Security Event Log DISABLED" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; Name = "Enabled"; BadIf = "0"; Desc = "System Event Log DISABLED" },

        # Notification suppression (hides security alerts)
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "EnableBalloonTips"; BadIf = "0"; Desc = "Balloon notification tips DISABLED - hides security alerts" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoTrayItemsDisplay"; BadIf = "1"; Desc = "System tray icons HIDDEN - hides security monitor" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "HideSCAHealth"; BadIf = "1"; Desc = "Security Center icon HIDDEN" },

        # Executable blocklist
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisallowRun"; BadIf = "1"; Desc = "Executable blocklist ACTIVE - may block security tools" },

        # Security service tampering
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"; Name = "Start"; BadIf = "4"; Desc = "Windows Defender SERVICE DISABLED" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc"; Name = "Start"; BadIf = "4"; Desc = "Security Center SERVICE DISABLED" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc"; Name = "Start"; BadIf = "4"; Desc = "Firewall SERVICE DISABLED" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"; Name = "Start"; BadIf = "4"; Desc = "Event Log SERVICE DISABLED" },

        # Winlogon persistence hijack
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "Shell"; BadIf = "notexplorer"; Desc = "Winlogon Shell HIJACKED - should be explorer.exe" },

        # MiniNt key (disables security event logging)
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt"; Name = "(KeyExists)"; BadIf = "exists"; Desc = "MiniNt key EXISTS - disables Security event logging (WinPE trick)" },

        # Security Center notification suppression
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Security Center"; Name = "AntiVirusDisableNotify"; BadIf = "1"; Desc = "AntiVirus disable notifications SUPPRESSED" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Security Center"; Name = "FirewallDisableNotify"; BadIf = "1"; Desc = "Firewall disable notifications SUPPRESSED" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Security Center"; Name = "UpdatesDisableNotify"; BadIf = "1"; Desc = "Update disable notifications SUPPRESSED" },

        # Windows Script Host disable
        @{ Path = "HKLM:\Software\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; BadIf = "0"; Desc = "Windows Script Host DISABLED" },
        @{ Path = "HKCU:\Software\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; BadIf = "0"; Desc = "Windows Script Host DISABLED (user)" },

        # ═══ PowerShell Execution Policy tampering (blocks scripts from running) ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; Name = "ExecutionPolicy"; BadIf = "Restricted"; Desc = "PowerShell ExecutionPolicy set to RESTRICTED - blocks ALL scripts" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; Name = "ExecutionPolicy"; BadIf = "Restricted"; Desc = "PowerShell ExecutionPolicy RESTRICTED (user level)" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Name = "EnableScripts"; BadIf = "0"; Desc = "PowerShell scripts DISABLED via Group Policy" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"; Name = "ExecutionPolicy"; BadIf = "Restricted"; Desc = "PowerShell ExecutionPolicy RESTRICTED via GPO" },

        # ═══ PowerShell Constrained Language Mode (cripples .NET access = kills WinForms GUI) ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; Name = "__PSLockdownPolicy"; BadIf = "4"; Desc = "PowerShell CONSTRAINED LANGUAGE MODE - blocks .NET/WinForms/CIM calls" },

        # ═══ IFEO targeting SecurityMonitor specifically ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecurityMonitor.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger targeting SecurityMonitor!" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\pwsh.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on PowerShell 7 (pwsh.exe)" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wscript.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on WScript" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cscript.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on CScript" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\eventvwr.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Event Viewer" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msconfig.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on MSConfig" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\perfmon.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Performance Monitor" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Process Explorer" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp64.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Process Explorer 64" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\autoruns.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Autoruns" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\autoruns64.exe"; Name = "Debugger"; BadIf = "exists"; Desc = "IFEO Debugger on Autoruns64" },

        # ═══ Software Restriction Policies (SRP - can block PowerShell/scripts) ═══
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"; Name = "DefaultLevel"; BadIf = "0"; Desc = "Software Restriction Policy: DEFAULT DISALLOWED - blocks unsigned executables" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"; Name = "TransparentEnabled"; BadIf = "0"; Desc = "SRP transparency DISABLED - blocks DLL loading" },

        # ═══ AppLocker (WDAC precursor - can block PowerShell scripts) ═══
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script"; Name = "EnforcementMode"; BadIf = "1"; Desc = "AppLocker Script rules ENFORCED - may block PowerShell scripts" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe"; Name = "EnforcementMode"; BadIf = "1"; Desc = "AppLocker Exe rules ENFORCED - may block executables" },

        # ═══ WMI/CIM tampering (SecurityMonitor uses CIM for CPU/RAM/process data) ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt"; Name = "Start"; BadIf = "4"; Desc = "WMI Service DISABLED - breaks CIM/WMI monitoring queries" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc"; Name = "Start"; BadIf = "4"; Desc = "IP Helper Service DISABLED - breaks network monitoring" },

        # ═══ Windows Notification suppression (hides SecurityMonitor tray/toasts) ═══
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"; Name = "ToastEnabled"; BadIf = "0"; Desc = "Toast notifications DISABLED - hides SecurityMonitor alerts" },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; BadIf = "1"; Desc = "Notification Center DISABLED - hides all alerts" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; BadIf = "1"; Desc = "Notification Center DISABLED (machine policy)" },

        # ═══ Remote access persistence (attacker maintaining access) ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "fDenyTSConnections"; BadIf = "0"; Desc = "Remote Desktop ENABLED at service level" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name = "UserAuthentication"; BadIf = "0"; Desc = "RDP Network Level Authentication DISABLED - weaker security" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fAllowUnsolicited"; BadIf = "1"; Desc = "Unsolicited Remote Assistance ALLOWED" },

        # ═══ Scheduled Tasks tampering (can kill SecurityMonitor periodically) ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"; Name = "(KeyExists)"; BadIf = "checkchildren"; Desc = "Scheduled task tree check" },

        # ═══ Windows Update disable (prevents security patches) ═══
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; BadIf = "1"; Desc = "Windows Auto-Update DISABLED via policy" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"; Name = "Start"; BadIf = "4"; Desc = "Windows Update Service DISABLED" },

        # ═══ Credential stealing preparation ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; BadIf = "1"; Desc = "WDigest cleartext passwords ENABLED - credential theft setup" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableRestrictedAdmin"; BadIf = "0"; Desc = "Restricted Admin mode manipulation detected" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; BadIf = "0"; Desc = "LSA Protection DISABLED - allows credential dumping" },

        # ═══ Network security weakening ═══
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; BadIf = "1"; Desc = "SMBv1 ENABLED - vulnerable to EternalBlue/WannaCry" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RequireSecuritySignature"; BadIf = "0"; Desc = "SMB signing NOT required - allows relay attacks" },

        # ═══ Boot/startup hijacking ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "Userinit"; BadIf = "notdefault"; Desc = "Winlogon Userinit HIJACKED" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "AppInit_DLLs"; BadIf = "exists_nonempty"; Desc = "AppInit_DLLs SET - DLL injection on every process" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "LoadAppInit_DLLs"; BadIf = "1"; Desc = "AppInit_DLLs loading ENABLED - DLL injection active" },

        # ═══ Audit policy tampering ═══
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name = "ProcessCreationIncludeCmdLine_Enabled"; BadIf = "0"; Desc = "Process command-line auditing DISABLED - hides attacker activity" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Name = "MaxSize"; BadIf = "toosmall"; Desc = "Security event log size check" }
    )

    foreach ($check in $tamperChecks) {
        try {
            # Special case: check if key itself exists
            if ($check.Name -eq "(KeyExists)") {
                if (Test-Path $check.Path) {
                    $alertKey = "TAMPER:$($check.Path)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY TAMPERING" $check.Desc -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path" = $check.Path
                            "Threat"        = $check.Desc
                            "Action"        = "INVESTIGATE IMMEDIATELY - This key should NOT exist"
                        }
                    }
                }
                continue
            }

            # Special case: Winlogon Shell check
            if ($check.BadIf -eq "notexplorer") {
                $val = (Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue).$($check.Name)
                if ($val -and $val -ne "explorer.exe") {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY TAMPERING" "$($check.Desc) - Current: $val" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Value Name"     = $check.Name
                            "Current Value"  = "$val"
                            "Expected Value" = "explorer.exe"
                            "Threat"         = $check.Desc
                        }
                    }
                }
                continue
            }

            # Special case: Winlogon Userinit check
            if ($check.BadIf -eq "notdefault") {
                $val = (Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue).$($check.Name)
                $defaultUserinit = "C:\Windows\system32\userinit.exe,"
                if ($val -and $val -ne $defaultUserinit -and $val -ne "C:\Windows\system32\userinit.exe") {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY TAMPERING" "$($check.Desc) - Current: $val" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Value Name"     = $check.Name
                            "Current Value"  = "$val"
                            "Expected"       = $defaultUserinit
                            "Threat"         = "Startup hijack - malware injected into boot sequence"
                        }
                    }
                }
                continue
            }

            # Special case: AppInit_DLLs non-empty check
            if ($check.BadIf -eq "exists_nonempty") {
                $val = (Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue).$($check.Name)
                if ($val -and "$val".Trim().Length -gt 0) {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY TAMPERING" "$($check.Desc) - DLLs: $val" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Injected DLLs"  = "$val"
                            "Threat"         = "DLL injection into every process via AppInit_DLLs"
                            "Action"         = "Clear AppInit_DLLs value and set LoadAppInit_DLLs to 0"
                        }
                    }
                }
                continue
            }

            # Special case: Event log size too small (attacker shrinks to overwrite evidence)
            if ($check.BadIf -eq "toosmall") {
                $val = (Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue).$($check.Name)
                if ($val -and [int]$val -lt 1048576) {
                    $alertKey = "TAMPER:$($check.Path)\$($check.Name)"
                    if (-not $script:TamperAlerted.ContainsKey($alertKey)) {
                        $script:TamperAlerted[$alertKey] = $true
                        Send-Alert "REGISTRY TAMPERING" "Security event log MAX SIZE reduced to $([math]::Round($val/1024))KB" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path"  = $check.Path
                            "Current Size"   = "$([math]::Round($val/1024))KB"
                            "Minimum Safe"   = "1024KB (1MB)"
                            "Threat"         = "Small log size causes rapid overwrite - destroys forensic evidence"
                        }
                    }
                }
                continue
            }

            # Special case: Skip scheduled task tree check (handled separately below)
            if ($check.BadIf -eq "checkchildren") { continue }

            if (-not (Test-Path $check.Path)) { continue }
            $val = (Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue).$($check.Name)
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
                    Send-Alert "REGISTRY TAMPERING" $check.Desc -Category "Registry Tampering" -ExtraDetails @{
                        "Registry Path"  = $check.Path
                        "Value Name"     = $check.Name
                        "Current Value"  = "$val"
                        "Threat"         = $check.Desc
                        "Action"         = "INVESTIGATE AND REMEDIATE - This may indicate active compromise"
                    }
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
                        Send-Alert "EXECUTABLE BLOCKED" "DisallowRun: $($p.Value) is BLOCKED from running" -Category "Registry Tampering" -ExtraDetails @{
                            "Registry Path" = $disallowPath
                            "Blocked Exe"   = $p.Value
                            "Threat"        = "Security tool blocked via DisallowRun policy"
                            "Action"        = "Remove this entry to restore access"
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
                            Send-Alert "DEFENDER EXCLUSION" "Suspicious exclusion: $($p.Name)" -Category "Registry Tampering" -ExtraDetails @{
                                "Registry Path"   = $ep
                                "Excluded Target"  = $p.Name
                                "Threat"           = "Malware often adds Defender exclusions to hide itself"
                                "Action"           = "Verify this exclusion is legitimate"
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

            # Start the monitoring timer now that baselines are ready
            $script:MonitorTimer = New-Object System.Windows.Forms.Timer
            $script:MonitorTimer.Interval = ($IntervalSeconds * 1000)
            $script:MonitorTimer.Add_Tick({
                try {
                    $script:MonitorTimer.Stop()
                    $script:MonitorCycle++
                    $ts = Get-Date -Format "HH:mm:ss"

                    Watch-Connections
                    Watch-Processes
                    Watch-Listeners
                    Watch-SecurityEvents
                    Watch-Registry
                    Watch-RegistryTampering
                    Watch-HostsFile

                    if ($script:MonitorCycle % $script:FwCheckInterval -eq 0) {
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

    # Auto-open dashboard on first launch
    try { Show-Dashboard } catch { Write-Host "[!] Auto-open dashboard error: $_" -ForegroundColor Red }

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
    if ($script:PulseTimer) { try { $script:PulseTimer.Stop(); $script:PulseTimer.Dispose() } catch {} }
    if ($script:DashTimer) { try { $script:DashTimer.Stop(); $script:DashTimer.Dispose() } catch {} }
    # Release instance mutex
    if ($script:AppMutex) {
        try { $script:AppMutex.ReleaseMutex() } catch {}
        try { $script:AppMutex.Dispose() } catch {}
    }
    Write-Log "=== MONITORING STOPPED === Total alerts: $script:AlertCount" -Level "INFO"
    Write-Host "`nMonitoring stopped. Total alerts: $script:AlertCount" -ForegroundColor Yellow
    Write-Host "Log files: $LogDir" -ForegroundColor Cyan
}
