# SecurityMonitor - Real-Time Security Monitoring Dashboard

A PowerShell-based security monitoring tool with a modern dark-themed WinForms dashboard. Performs continuous system-level monitoring including network connections, processes, drivers, services, registry tampering, and **AI-powered threat detection** — all running locally with no cloud dependency.

![SecurityMonitor Dashboard](screenshots/dashboard.png)

## Features

### Dashboard
- **Modern Dark UI**: Tabbed WinForms dashboard with sidebar navigation, stat cards, gauges, and OwnerDraw ListViews
- **Live Status Page**: Real-time CPU/RAM/Disk gauges, connection count, process count, uptime, security posture indicators (Defender, Firewall, UAC, RDP)
- **Alert History**: Filterable by severity and category, with detail panel, export to CSV, and action buttons (Kill Process, Stop/Start Service, Block IP, Restore Registry)
- **System Tray**: Runs minimized to tray with balloon/toast notifications; single-instance detection via named mutex
- **Responsive Layout**: All panels, cards, gauges, and ListViews resize proportionally with the window

### AI Threat Detection (Optional)
- **Behavioral Analysis Engine**: Fully local heuristic scanning — no cloud, no signatures needed
  - Suspicious parent-child process trees (e.g. Word → cmd.exe)
  - Encoded/obfuscated PowerShell command detection
  - Download cradles and Defender evasion patterns
  - Known attack tool detection (mimikatz, rubeus, etc.)
  - Unsigned executables in suspicious locations (Temp, Downloads, Public)
  - High-entropy (randomized) process name detection
  - Fileless/deleted executable detection
  - System process masquerading (svchost.exe from wrong path)
- **HollowsHunter Integration**: Optional memory injection scanner — detects process hollowing, DLL injection, IAT hooking, shellcode, and inline hooks
- **Self-Exclusion**: Automatically whitelists its own process tree to avoid false positives
- **Dedicated AI Threats Tab**: ListView with risk-colored findings, detail panel, and Kill Process button
- **Configurable**: Enable/disable from Settings tab; off by default to save resources

### Monitoring Engines
- **Firmware Integrity**: SHA-256 hash monitoring of `.sys`, `.efi`, `.rom`, `.bin`, `.fw`, `.cap` files
- **Network Connections**: Real-time tracking of outbound connections with IP lookup and firewall blocking
- **Process Monitoring**: New process detection with signature verification
- **Driver Monitoring**: New/removed driver detection
- **Service Monitoring**: New service detection with Stop/Start actions
- **Registry Tampering**: 90+ registry checks (IFEO, Defender policies, COM hijacking, startup keys, etc.)
- **Security Events**: Remote logons, failed logins, new accounts, new service installs via Windows Event Log
- **RDP Status**: Immediate detection when Remote Desktop is enabled/disabled
- **Hosts File**: DNS redirection change detection

### Settings & Notifications
- **Per-Category Toggles**: Enable/disable each monitoring category independently
- **Threat Detail Mode**: Optional severity levels and threat/recommendation details (off by default for a neutral experience)
- **Windows Toast Notifications**: Toggle desktop notifications on/off; alerts always remain in the GUI
- **AI Detection Toggle**: Enable/disable AI scanning with resource usage warning
- **Instant Save**: All settings persist immediately to `notification_config.json`

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges
- (Optional) [HollowsHunter](https://github.com/hasherezade/hollows_hunter/releases) — place `hollows_hunter.exe` in the `Tools\` folder for memory scanning

## Installation

### Quick Install (Recommended)

Download and run the installer in one command — downloads all project files, installs HollowsHunter, creates desktop shortcut, auto-start task, and begins monitoring:

```powershell
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $d=\"$env:USERPROFILE\SecurityMonitor\"; md $d -Force >$null; Invoke-WebRequest 'https://github.com/xyzwebmaster/SecurityMonitor/archive/refs/heads/master.zip' -OutFile '$env:TEMP\SM.zip' -UseBasicParsing; Expand-Archive '$env:TEMP\SM.zip' '$env:TEMP\SM_ext' -Force; cp '$env:TEMP\SM_ext\SecurityMonitor-master\*' $d -Recurse -Force; md '$d\Tools' -Force >$null; Invoke-WebRequest 'https://github.com/hasherezade/hollows_hunter/releases/download/v0.4.1.1/hollows_hunter64.exe' -OutFile '$d\Tools\hollows_hunter.exe' -UseBasicParsing; rm '$env:TEMP\SM.zip','$env:TEMP\SM_ext' -Recurse -Force -EA 0; & '$d\Install.ps1'"
```

Or if you already have the files locally:

```powershell
powershell -ExecutionPolicy Bypass -File Install.ps1
```

The installer automatically:
1. Downloads the full repository to `%USERPROFILE%\SecurityMonitor\` (if not already present)
2. Downloads [HollowsHunter](https://github.com/hasherezade/hollows_hunter) for AI memory scanning
3. Creates directories, scheduled task, and desktop shortcut
4. Starts monitoring immediately

### Manual Start

Run directly as Administrator without the installer:

```powershell
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1
```

### Desktop Shortcut

The installer creates a desktop shortcut via `Launcher.ps1`. The launcher handles:
- Starting SecurityMonitor with UAC elevation if not already running
- Opening the dashboard if an instance is already active (via signal file)

## Usage

```powershell
# Interactive mode (dashboard opens)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1

# Silent mode (tray only, no console)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -Silent

# Custom scan interval
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -IntervalSeconds 5
```

## Log Files

| File | Contents |
|------|----------|
| `Logs/monitor_YYYY-MM-DD.log` | General monitoring records |
| `Logs/alerts_YYYY-MM-DD.log` | Alert events only |
| `Logs/connections_YYYY-MM-DD.log` | Network connection history |
| `Logs/processes_YYYY-MM-DD.log` | Process start/stop records |

## Baseline Files

| File | Contents |
|------|----------|
| `Baselines/firmware_hashes.json` | Firmware/driver file hashes |
| `Baselines/driver_baseline.json` | Loaded driver list |
| `Baselines/service_baseline.json` | Service list |

## Uninstall

```powershell
Unregister-ScheduledTask -TaskName "SecurityMonitor" -Confirm:$false
```

## License

MIT
