# SecurityMonitor - System Security Monitoring Tool

A PowerShell-based tool that performs continuous hardware and system-level security monitoring.

## Features

- **Network Connection Monitoring**: Tracks all outbound connections in real-time, alerts on unknown connections
- **Process Monitoring**: Captures newly started processes, reports unsigned executables
- **Firmware Integrity Check**: Monitors SHA-256 hashes of driver and firmware files, detects modifications
- **Driver Monitoring**: Alerts when new drivers are loaded or existing ones are removed
- **Service Monitoring**: Detects newly added services
- **Registry Monitoring**: Captures changes to critical startup registry keys
- **Security Event Monitoring**: Watches Windows Event Log for suspicious logons, failed login attempts, new account creation, etc.
- **RDP Monitoring**: Immediately alerts when Remote Desktop is enabled
- **Hosts File Monitoring**: Detects DNS redirection changes
- **Timestamped Logging**: All events are recorded in a format suitable for forensic evidence
- **Windows Toast Notifications**: Real-time desktop notifications for all security alerts

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

## Installation

```powershell
# Open PowerShell as Administrator
cd C:\Users\<username>\SecurityMonitor
powershell -ExecutionPolicy Bypass -File Install.ps1
```

## Usage

```powershell
# Normal mode (with console output)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1

# Silent mode (notifications only on alerts)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -Silent

# Custom scan interval (5 seconds)
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
