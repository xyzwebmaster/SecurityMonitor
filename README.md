# SecurityMonitor - System Security Monitoring Tool

A PowerShell-based tool that performs continuous hardware and system-level security monitoring with **real-time Windows desktop notifications**. On first run, a GUI lets you choose exactly which types of changes you want to be notified about.

## Features

- **First-Run Setup GUI**: A graphical settings window lets you select which alert categories to receive as desktop notifications
- **Windows Toast Notifications**: All selected alert types are delivered as native Windows 10/11 toast notifications, even when running silently in the background
- **Firmware Integrity Check**: Monitors SHA-256 hashes of driver and firmware files (`.sys`, `.efi`, `.rom`, `.bin`, `.fw`, `.cap`), notifies on modification, deletion, or new files
- **Network Connection Monitoring**: Tracks all outbound connections in real-time, notifies on unknown/unwhitelisted connections
- **Process Monitoring**: Captures newly started processes, notifies for unsigned executables
- **Driver Monitoring**: Notifies when new drivers are loaded or existing ones are removed
- **Service Monitoring**: Notifies when new services are detected
- **Registry Monitoring**: Notifies on changes to critical startup registry keys (Run, RunOnce)
- **Security Event Monitoring**: Watches Windows Event Log and notifies for remote logons, failed login attempts, new account creation, new service installation
- **RDP Monitoring**: Immediate notification when Remote Desktop is enabled
- **Hosts File Monitoring**: Notification on DNS redirection changes
- **Timestamped Logging**: All events are recorded in forensic-evidence format with timestamps
- **Auto-Start**: Registers itself on first run to start automatically on every Windows logon

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

## Installation

Just run once as Administrator — it shows the settings GUI, then registers itself to auto-start on every Windows logon:

```powershell
# Open PowerShell as Administrator and run:
powershell -ExecutionPolicy Bypass -File C:\Users\<username>\SecurityMonitor\SecurityMonitor.ps1
```

On first launch:
1. A settings window appears where you choose which alert types to receive notifications for
2. The tool registers itself as a scheduled task (auto-starts on every boot)
3. Monitoring begins immediately

Alternatively, use the installer script for a guided setup:

```powershell
powershell -ExecutionPolicy Bypass -File Install.ps1
```

## Usage

```powershell
# Normal mode (with console output)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1

# Silent mode (no console output, but toast notifications are ALWAYS sent)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -Silent

# Custom scan interval (5 seconds)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -IntervalSeconds 5
```

## Notification Settings

On first run, a GUI window lets you enable/disable notifications for each category:

| Category | Description |
|----------|-------------|
| Firmware Integrity Changes | Driver/firmware file hash modifications, deletions, new files |
| Driver Changes | New drivers loaded or removed |
| New Services | Newly installed Windows services |
| Unknown Network Connections | Outbound connections from unrecognized processes |
| Unsigned Processes | Processes without valid digital signatures |
| New Listening Ports | Ports opened by non-system processes |
| Registry Startup Key Changes | Changes to Run/RunOnce keys |
| Security Events | Remote logons, failed logins, new accounts |
| Remote Desktop (RDP) Status | RDP being enabled |
| Hosts File Modifications | DNS redirection changes |

To change your preferences, delete `notification_config.json` and restart — the settings GUI will appear again.

## How Notifications Work

SecurityMonitor uses native Windows 10/11 toast notifications (with a legacy balloon fallback). Notifications are **always sent** for enabled categories regardless of the `-Silent` flag. This means:

- **Scheduled task (background)**: Runs silently, no console window, but you still get desktop toast notifications
- **Interactive mode**: You get both console output AND toast notifications

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
