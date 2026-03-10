# SecurityMonitor - System Security Monitoring Tool

A PowerShell-based tool that performs continuous hardware and system-level security monitoring with **real-time Windows desktop notifications**. When any change is detected — firmware modification, new driver, unknown network connection, or suspicious security event — you instantly receive a Windows toast notification on your desktop.

## Features

- **Windows Toast Notifications**: All detected changes are delivered as native Windows 10/11 toast notifications in real-time, even when running silently in the background as a scheduled task
- **Firmware Integrity Check**: Monitors SHA-256 hashes of driver and firmware files (`.sys`, `.efi`, `.rom`, `.bin`, `.fw`, `.cap`), instantly notifies on any modification, deletion, or new file
- **Network Connection Monitoring**: Tracks all outbound connections in real-time, sends notification on unknown/unwhitelisted connections
- **Process Monitoring**: Captures newly started processes, sends notification for unsigned executables
- **Driver Monitoring**: Sends notification when new drivers are loaded or existing ones are removed
- **Service Monitoring**: Sends notification when new services are detected
- **Registry Monitoring**: Sends notification on changes to critical startup registry keys (Run, RunOnce)
- **Security Event Monitoring**: Watches Windows Event Log and sends notifications for remote logons, failed login attempts, new account creation, new service installation
- **RDP Monitoring**: Immediate notification when Remote Desktop is enabled
- **Hosts File Monitoring**: Notification on DNS redirection changes
- **Timestamped Logging**: All events are recorded in forensic-evidence format with timestamps

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

## Installation

Just run once as Administrator — it automatically registers itself to start on every Windows logon:

```powershell
# Open PowerShell as Administrator and run:
powershell -ExecutionPolicy Bypass -File C:\Users\<username>\SecurityMonitor\SecurityMonitor.ps1
```

That's it. From now on, it will auto-start silently every time Windows boots.

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

## How Notifications Work

SecurityMonitor uses native Windows 10/11 toast notifications (with a legacy balloon fallback). Notifications are **always sent** regardless of whether the `-Silent` flag is used. This means:

- **Scheduled task (background)**: Runs silently with `-Silent`, no console window, but you still get desktop toast notifications for every alert
- **Interactive mode**: You get both console output AND toast notifications

Every `Send-Alert` call in the monitoring loop triggers a toast notification. This covers:
- Firmware file hash changes (modified, deleted, or new files)
- New/removed drivers and services
- Unknown network connections
- Unsigned processes
- Registry startup key changes
- Remote Desktop being enabled
- Hosts file modifications
- Suspicious security events (remote logon, failed logon, new user, new service)

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
