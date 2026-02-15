#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Donanim ve Sistem Guvenlik Izleme Araci
.DESCRIPTION
    Ag baglantilari, surecler, firmware hash butunlugu, surucu degisiklikleri
    ve guvenlik olaylarini surekli izler. Zaman damgali kanit loglari uretir.
.AUTHOR
    SecurityMonitor - Adli Bilisim Izleme
.VERSION
    1.0.0
#>

param(
    [int]$IntervalSeconds = 10,
    [string]$LogDir = "$PSScriptRoot\Logs",
    [string]$BaselineDir = "$PSScriptRoot\Baselines",
    [switch]$Silent
)

# --- YAPILANDIRMA ---
$ErrorActionPreference = "SilentlyContinue"
$script:StartTime = Get-Date
$script:AlertCount = 0

# Renk kodlari
function Write-Status  { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok      { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Alert   { param($Msg) Write-Host "[!] ALERT: $Msg" -ForegroundColor Red }
function Write-Warn    { param($Msg) Write-Host "[~] $Msg" -ForegroundColor Yellow }

# --- DIZINLERI OLUSTUR ---
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

# --- LOG FONKSIYONLARI ---
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

function Send-Alert {
    param([string]$Title, [string]$Message)
    $script:AlertCount++
    Write-Alert "$Title - $Message"
    Write-Log "$Title - $Message" -Level "ALERT"

    if (-not $Silent) {
        # Windows toast bildirimi
        try {
            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
            $balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon = [System.Drawing.SystemIcons]::Warning
            $balloon.BalloonTipIcon = "Warning"
            $balloon.BalloonTipTitle = "GUVENLIK UYARISI: $Title"
            $balloon.BalloonTipText = $Message
            $balloon.Visible = $true
            $balloon.ShowBalloonTip(5000)
            Start-Sleep -Milliseconds 100
        } catch {}

        # Uyari sesi
        try { [System.Console]::Beep(1000, 300); [System.Console]::Beep(1500, 300) } catch {}
    }
}

# --- FIRMWARE HASH BASELINE ---
function Get-FirmwareFiles {
    $paths = @()
    # UEFI/BIOS ile iliskili sistem dosyalari
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
    Write-Status "Firmware baseline olusturuluyor (bu birkaç dakika surebilir)..."
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
    Write-Ok "$count firmware/surucu dosyasi baseline'a kaydedildi"
    Write-Log "Firmware baseline olusturuldu: $count dosya" -Level "INFO"
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
            $changes += @{ File = $filePath; Type = "SILINDI"; Detail = "Firmware dosyasi silindi!" }
            continue
        }
        try {
            $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
            if ($currentHash -ne $expected.Hash) {
                $changes += @{
                    File   = $filePath
                    Type   = "DEGISTIRILDI"
                    Detail = "Hash degisti! Onceki: $($expected.Hash.Substring(0,16))... Simdiki: $($currentHash.Substring(0,16))..."
                }
            }
        } catch {}
    }
    # Yeni eklenen dosyalar
    $currentFiles = Get-FirmwareFiles
    foreach ($f in $currentFiles) {
        if (-not $baseline.PSObject.Properties[$f.FullName]) {
            $changes += @{ File = $f.FullName; Type = "YENI"; Detail = "Yeni firmware/surucu dosyasi tespit edildi!" }
        }
    }
    return $changes
}

# --- SURUCU BASELINE ---
function New-DriverBaseline {
    Write-Status "Surucu baseline olusturuluyor..."
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
    Write-Ok "$($driverList.Count) surucu baseline'a kaydedildi"
    Write-Log "Surucu baseline olusturuldu: $($driverList.Count) surucu" -Level "INFO"
}

function Compare-DriverBaseline {
    if (-not (Test-Path $DriverBaseline)) { return }
    $baseline = Get-Content $DriverBaseline -Raw | ConvertFrom-Json
    $current = Get-CimInstance Win32_SystemDriver | Select-Object Name, State, Started
    $baseNames = $baseline | ForEach-Object { $_.Name }
    $currNames = $current | ForEach-Object { $_.Name }
    $changes = @()
    # Yeni yuklenenmis suruculer
    foreach ($d in $current) {
        if ($d.Name -notin $baseNames) {
            $changes += @{ Driver = $d.Name; Type = "YENI_SURUCU"; Detail = "Yeni surucu yuklendi: $($d.Name)" }
        }
    }
    # Kaldirilan suruculer
    foreach ($b in $baseline) {
        if ($b.Name -notin $currNames) {
            $changes += @{ Driver = $b.Name; Type = "KALDIRILAN_SURUCU"; Detail = "Surucu kaldirildi: $($b.Name)" }
        }
    }
    return $changes
}

# --- SERVIS BASELINE ---
function New-ServiceBaseline {
    Write-Status "Servis baseline olusturuluyor..."
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
    Write-Ok "$($svcList.Count) servis baseline'a kaydedildi"
}

function Compare-ServiceBaseline {
    if (-not (Test-Path $ServiceBaseline)) { return }
    $baseline = Get-Content $ServiceBaseline -Raw | ConvertFrom-Json
    $current = Get-Service | Select-Object Name, Status, StartType
    $baseNames = $baseline | ForEach-Object { $_.Name }
    $changes = @()
    foreach ($s in $current) {
        if ($s.Name -notin $baseNames) {
            $changes += @{ Service = $s.Name; Type = "YENI_SERVIS"; Detail = "Yeni servis tespit edildi: $($s.Name) [$($s.Status)]" }
        }
    }
    return $changes
}

# --- AG IZLEME ---
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
            $logEntry = "YENI BAGLANTI: $($conn.ProcessName) (PID:$($conn.PID)) -> $($conn.RemoteAddr):$($conn.RemotePort) | Yol: $($conn.ProcessPath)"

            Write-Log $logEntry -Level "INFO" -Target $ConnectionLog

            if (-not $isKnown) {
                Send-Alert "BILINMEYEN BAGLANTI" "$($conn.ProcessName) -> $($conn.RemoteAddr):$($conn.RemotePort)"
            } else {
                Write-Warn "Bilinen baglanti: $($conn.ProcessName) -> $($conn.RemoteAddr):$($conn.RemotePort)"
            }
        }
    }
    # Kapanan baglantilari temizle
    $currentKeys = $current | ForEach-Object { "$($_.RemoteAddr):$($_.RemotePort)|$($_.PID)" }
    $staleKeys = $script:KnownRemotes.Keys | Where-Object { $_ -notin $currentKeys }
    foreach ($k in $staleKeys) {
        $script:KnownRemotes.Remove($k)
    }
}

# --- SUREC IZLEME ---
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

            $logEntry = "YENI SUREC: $($proc.ProcessName) (PID:$($proc.Id)) | Yol: $($proc.Path) | Imzali: $isSigned"
            Write-Log $logEntry -Level "INFO" -Target $ProcessLog

            if (-not $isKnown -and $proc.Path -and -not $isSigned) {
                Send-Alert "IMZASIZ SUREC" "$($proc.ProcessName) (PID:$($proc.Id)) - $($proc.Path)"
            }
        }
    }
    # Kapanan surecleri temizle
    $currentPids = $current | ForEach-Object { $_.Id }
    $stalePids = $script:KnownProcesses.Keys | Where-Object { $_ -notin $currentPids }
    foreach ($p in $stalePids) {
        $info = $script:KnownProcesses[$p]
        Write-Log "SUREC KAPANDI: $($info.Name) (PID:$p)" -Level "INFO" -Target $ProcessLog
        $script:KnownProcesses.Remove($p)
    }
}

# --- DINLEYEN PORT IZLEME ---
$script:KnownListeners = @{}

function Watch-Listeners {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                 Where-Object { $_.LocalAddress -notmatch "^(127\.|::1)" }
    foreach ($l in $listeners) {
        $key = "$($l.LocalAddress):$($l.LocalPort)"
        if (-not $script:KnownListeners.ContainsKey($key)) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $script:KnownListeners[$key] = $proc.ProcessName
            $logEntry = "YENI DINLEYEN PORT: $key | Surec: $($proc.ProcessName) (PID:$($l.OwningProcess)) | Yol: $($proc.Path)"
            Write-Log $logEntry -Level "INFO"

            $isSystem = $proc.ProcessName -in @("svchost","lsass","services","wininit","spoolsv","System","steam")
            if (-not $isSystem) {
                Send-Alert "YENI DINLEYEN PORT" "$key - $($proc.ProcessName)"
            }
        }
    }
}

# --- GUVENLIK OLAYI IZLEME ---
$script:LastEventTime = Get-Date

function Watch-SecurityEvents {
    $dangerousEventIds = @(
        4624,   # Basarili giris (Type 3,10 onemli)
        4625,   # Basarisiz giris denemesi
        4648,   # Acik kimlik bilgileriyle giris
        4672,   # Ozel ayricaliklar atandi
        4688,   # Yeni surec olusturuldu
        4697,   # Servis yuklendi
        4720,   # Kullanici hesabi olusturuldu
        4732,   # Grup uyeligine eklendi
        7045    # Yeni servis yuklendi (System log)
    )
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            StartTime = $script:LastEventTime
            Id        = $dangerousEventIds
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($evt in $events) {
            $logEntry = "GUVENLIK OLAYI [ID:$($evt.Id)] $($evt.TimeCreated) - $($evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length)))"
            Write-Log $logEntry -Level "WARN"

            # Uzaktan giris (Type 3 veya 10) ozellikle tehlikeli
            if ($evt.Id -eq 4624 -and $evt.Message -match "Logon Type:\s+(3|10)") {
                Send-Alert "UZAKTAN GIRIS TESPIT EDILDI" "Logon Type: $($Matches[1]) - $($evt.TimeCreated)"
            }
            # Basarisiz giris
            if ($evt.Id -eq 4625) {
                Send-Alert "BASARISIZ GIRIS DENEMESI" "$($evt.TimeCreated)"
            }
            # Yeni kullanici olusturuldu
            if ($evt.Id -eq 4720) {
                Send-Alert "YENI KULLANICI HESABI OLUSTURULDU" "$($evt.TimeCreated)"
            }
            # Yeni servis
            if ($evt.Id -eq 4697 -or $evt.Id -eq 7045) {
                Send-Alert "YENI SERVIS YUKLENDI" "$($evt.TimeCreated)"
            }
        }
        $script:LastEventTime = Get-Date
    } catch {}
}

# --- KAYIT DEFTERI IZLEME ---
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
    Write-Ok "Kayit defteri baseline olusturuldu ($($keys.Count) anahtar)"
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
            Send-Alert "KAYIT DEFTERI DEGISTI" "Anahtar: $key"
            Write-Log "Registry degisikligi: $key | Eski: $($script:RegistryBaseline[$key].Substring(0,16))... Yeni: $($hash.Substring(0,16))..." -Level "ALERT"
            $script:RegistryBaseline[$key] = $hash
        }
    }

    # RDP durumu
    try {
        $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections).fDenyTSConnections
        if ($rdp -eq 0) {
            Send-Alert "RDP ACIK" "Uzak Masaustu baglantisi etkinlestirildi!"
        }
    } catch {}
}

# --- HOSTS DOSYASI IZLEME ---
$script:HostsHash = $null

function Watch-HostsFile {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    try {
        $hash = (Get-FileHash -Path $hostsPath -Algorithm SHA256).Hash
        if ($null -eq $script:HostsHash) {
            $script:HostsHash = $hash
        } elseif ($script:HostsHash -ne $hash) {
            Send-Alert "HOSTS DOSYASI DEGISTIRILDI" "DNS yonlendirmesi degismis olabilir!"
            $script:HostsHash = $hash
        }
    } catch {}
}

# --- ANA DONGU ---
function Start-Monitoring {
    $banner = @"

  ======================================================
    GUVENLIK IZLEME SISTEMI v1.0
    Baslangic: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Bilgisayar: $env:COMPUTERNAME
    Kullanici: $env:USERNAME
    Tarama Araligi: $IntervalSeconds saniye
    Log Dizini: $LogDir
  ======================================================

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Log "=== IZLEME BASLATILDI === Bilgisayar: $env:COMPUTERNAME | Kullanici: $env:USERNAME" -Level "INFO"

    # Baseline olustur
    $fwBaseline = $null
    if (Test-Path $FirmwareBaseline) {
        Write-Ok "Mevcut firmware baseline yuklendi"
        $fwBaseline = Get-Content $FirmwareBaseline -Raw | ConvertFrom-Json
    } else {
        $fwBaseline = New-FirmwareBaseline
    }

    if (-not (Test-Path $DriverBaseline)) {
        New-DriverBaseline
    } else {
        Write-Ok "Mevcut surucu baseline yuklendi"
    }

    if (-not (Test-Path $ServiceBaseline)) {
        New-ServiceBaseline
    } else {
        Write-Ok "Mevcut servis baseline yuklendi"
    }

    New-RegistryBaseline

    # Mevcut surecleri kaydet
    Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } | ForEach-Object {
        $script:KnownProcesses[$_.Id] = @{ Name = $_.ProcessName; Path = $_.Path; Time = Get-Date }
    }

    # Mevcut baglantilari kaydet
    Get-ConnectionSnapshot | ForEach-Object {
        $key = "$($_.RemoteAddr):$($_.RemotePort)|$($_.PID)"
        $script:KnownRemotes[$key] = Get-Date
    }

    # Mevcut dinleyicileri kaydet
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -notmatch "^(127\.|::1)" } | ForEach-Object {
        $key = "$($_.LocalAddress):$($_.LocalPort)"
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $script:KnownListeners[$key] = $proc.ProcessName
    }

    # Hosts dosyasi ilk hash
    try {
        $script:HostsHash = (Get-FileHash "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256).Hash
    } catch {}

    Write-Host ""
    Write-Ok "Izleme aktif. Durdurmak icin Ctrl+C basin."
    Write-Host "-----------------------------------------------------------" -ForegroundColor DarkGray

    $cycle = 0
    $fwCheckInterval = 30  # Her 30 dongude firmware kontrolu (yaklasik 5 dk)

    while ($true) {
        $cycle++
        $ts = Get-Date -Format "HH:mm:ss"

        # Her dongude
        Watch-Connections
        Watch-Processes
        Watch-Listeners
        Watch-SecurityEvents
        Watch-Registry
        Watch-HostsFile

        # Periyodik firmware ve surucu kontrolu
        if ($cycle % $fwCheckInterval -eq 0) {
            Write-Status "[$ts] Firmware butunluk kontrolu yapiliyor..."
            $fwChanges = Compare-FirmwareBaseline
            if ($fwChanges -and $fwChanges.Count -gt 0) {
                foreach ($change in $fwChanges) {
                    Send-Alert "FIRMWARE $($change.Type)" "$($change.File) - $($change.Detail)"
                }
            }

            $drvChanges = Compare-DriverBaseline
            if ($drvChanges -and $drvChanges.Count -gt 0) {
                foreach ($change in $drvChanges) {
                    Send-Alert $change.Type $change.Detail
                }
            }

            $svcChanges = Compare-ServiceBaseline
            if ($svcChanges -and $svcChanges.Count -gt 0) {
                foreach ($change in $svcChanges) {
                    Send-Alert $change.Type $change.Detail
                }
            }
        }

        # Durum gosterimi (her 6 dongude = ~1 dk)
        if ($cycle % 6 -eq 0) {
            $uptime = (Get-Date) - $script:StartTime
            $uptimeStr = "{0:D2}s {1:D2}d {2:D2}sn" -f $uptime.Hours, $uptime.Minutes, $uptime.Seconds
            Write-Host "[$ts] Calisma: $uptimeStr | Uyari: $($script:AlertCount) | Baglanti: $($script:KnownRemotes.Count) | Surec: $($script:KnownProcesses.Count)" -ForegroundColor DarkGray
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

# --- BASLATMA ---
try {
    Start-Monitoring
} catch {
    Write-Log "HATA: $($_.Exception.Message)" -Level "ERROR"
    Write-Alert "Izleme hatasi: $($_.Exception.Message)"
} finally {
    Write-Log "=== IZLEME DURDURULDU === Toplam uyari: $script:AlertCount" -Level "INFO"
    Write-Host "`nIzleme durduruldu. Toplam uyari: $script:AlertCount" -ForegroundColor Yellow
    Write-Host "Log dosyalari: $LogDir" -ForegroundColor Cyan
}
