# All-in-One Whitehat Security Tool — Real-Time Monitoring & Threat Detection

A pure PowerShell security monitoring tool with a modern dark-themed WinForms dashboard. Performs continuous system-level monitoring with **8-engine AI threat detection** covering memory injection, kernel integrity, BYOVD attacks, hidden processes, and hardware security — all running locally with zero cloud dependency and zero external binaries.

![SecurityMonitor Dashboard](screenshots/dashboard.png)

## Quick Install

Open PowerShell as Administrator and paste:

```powershell
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest 'https://raw.githubusercontent.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool/master/Install.ps1' -OutFile '$env:TEMP\SM_Install.ps1' -UseBasicParsing; & '$env:TEMP\SM_Install.ps1'"
```

Downloads the project, creates a scheduled task + desktop shortcut, and starts monitoring immediately.

## Features

### Dashboard (6 Tabs)
- **Status** — Live stat cards, CPU/RAM/Disk gauges, 8-indicator Security Posture panel, Network Activity, AI Detection summary, Recent Alerts
- **Alerts** — Filterable alert history with severity/category/search, detail panel, 6 action buttons (Kill Process, Block IP, Stop Service, Restore Registry, IP Lookup, Open Log), CSV export
- **AI Threats** — 8-engine on-demand threat scanner with risk-colored ListView and detail panel
- **Settings** — Display settings, Firewall/Network protection toggles, DNS provider + DoH (IPv4/IPv6), hosts-file blocking
- **Logs** — Quick access to daily log files and baseline snapshots
- **Console** — Live color-coded debug/error output for all operations

### 8-Engine AI Threat Detection

On-demand scanning from the AI Threats tab — no background resource usage until you click "Scan."

| # | Engine | What It Detects |
|---|--------|----------------|
| 1 | **MemScanner** | RWX memory regions (shellcode), unbacked executable memory (injection), suspicious DLL paths, process hollowing (size mismatch) |
| 2 | **Behavioral** | Suspicious parent-child trees, encoded PowerShell, download cradles, Defender evasion, known attack tools, fileless processes, process masquerading |
| 3 | **SecureBoot/TPM** | Secure Boot disabled, TPM not ready, BitLocker off, Kernel DMA Protection missing |
| 4 | **BYOVD** | 40+ known vulnerable driver hashes (loldrivers.io), unsigned boot drivers, tampered driver signatures |
| 5 | **HiddenProc** | API cross-reference: Get-Process vs WMI vs NtQuerySystemInformation — mismatches reveal rootkit-hidden processes |
| 6 | **ETW** | Code Integrity violations, privilege escalation volume, rogue PnP devices, Sysmon unsigned driver loads |
| 7 | **DriverSig** | All running drivers checked for valid signatures, hash mismatches, missing-on-disk files |
| 8 | **Hypervisor** | HVCI (Memory Integrity) status, Credential Guard, VM detection |

Uses Windows API P/Invoke (`VirtualQueryEx`, `NtQuerySystemInformation`) for memory and process scanning — no external tools required.

### Security Posture (Status Page)

8 real-time indicators polled by background runspace:

| Row 1 | Row 2 |
|-------|-------|
| Defender: ON/OFF | SecureBoot: ON/OFF |
| Firewall: ON/PARTIAL | TPM: Ready/N/A |
| UAC: Enabled/DISABLED | HVCI: ON/OFF |
| RDP: Disabled/ENABLED | BitLocker: ON/OFF |

### Firewall & Network Protection (Settings Tab)

All settings use elevated PowerShell with async verification (pessimistic revert on UAC cancel):

| Setting | Effect |
|---------|--------|
| Domain/Private/Public Firewall Profile | Enable with safe defaults (`-DefaultOutboundAction Allow`) |
| Block All Inbound | Firewall profile default + explicit block rule + WFP |
| Block All Outbound | Firewall profile default + explicit block rule + WFP |
| Block ICMP Ping | Firewall rule blocks incoming echo requests |
| Block LAN Traffic | 6 rules blocking 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 |
| Block Device Connections | SMB/NetBIOS/LLMNR/mDNS/SSDP/UPnP firewall rules + service disable |
| Block Trackers/Malware/Telemetry | Hosts file domain blocking |
| Prevent DNS Bypass | Port 53 firewall lock |

### DNS & Secure DNS

- **6 DNS Providers**: Cloudflare, Quad9, Google, OpenDNS, AdGuard, or System Default
- **DNS over HTTPS (DoH)**: Sets per-adapter `DohFlags=1` (automatic template) for both IPv4 and IPv6 via Windows native API (`Add-DnsClientDohServerAddress` + .NET Registry API)
- **Auto re-apply**: When DNS provider changes while DoH is active, DoH is automatically re-configured for the new provider

### 10 Continuous Monitoring Categories

Each independently toggleable from Settings:

| Category | What It Monitors |
|----------|-----------------|
| Firmware Integrity | SHA-256 hash changes of `.sys`, `.efi`, `.rom`, `.bin`, `.fw`, `.cap` files |
| Driver Changes | New drivers loaded or existing drivers removed |
| New Services | Newly installed Windows services |
| Network Connections | Outbound connections from unrecognized processes |
| Unsigned Processes | Processes without valid digital signatures |
| New Listening Ports | Ports opened by non-system processes |
| Registry Tampering | 90+ checks: IFEO debuggers, Defender policies, COM hijacking, UAC bypass, AMSI disable, etc. |
| Security Events | Remote logons, failed logins, new accounts, service installs (Event Log) |
| RDP Status | Remote Desktop enabled/disabled detection |
| Hosts File | DNS redirection changes |

### Architecture
- **Non-blocking UI**: Heavy I/O runs in background runspaces via synchronized hashtables
- **No `.GetNewClosure()`**: All async callbacks use `$script:FWCallbackData` + `$this.Tag` pattern (avoids PS 5.1 module scope bugs)
- **No external binaries**: Pure PowerShell + P/Invoke. No hollows_hunter, no CHIPSEC, no third-party tools
- **No IPSec commands**: Removed to prevent Defender CobaltStrike false positives
- **Console tab**: Every operation logged with timestamps and color-coded severity

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

## Installation

### One-Line Install (Recommended)

```powershell
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest 'https://raw.githubusercontent.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool/master/Install.ps1' -OutFile '$env:TEMP\SM_Install.ps1' -UseBasicParsing; & '$env:TEMP\SM_Install.ps1'"
```

### Manual Start

```powershell
# Interactive mode (dashboard opens)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1

# Silent mode (tray only)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -Silent

# Custom scan interval
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -IntervalSeconds 5
```

## File Structure

```
SecurityMonitor/
├── SecurityMonitor.ps1      # Main script (~7000 lines) — monitoring + dashboard + all engines
├── SmWfpEngine.ps1          # WFP (Windows Filtering Platform) helper for firewall rules
├── Launcher.ps1             # Desktop shortcut target (UAC + single-instance)
├── Install.ps1              # Installer (downloads repo, creates task/shortcut)
├── notification_config.json # User preferences (auto-generated)
├── Logs/
│   ├── monitor_YYYY-MM-DD.log
│   ├── alerts_YYYY-MM-DD.log
│   ├── connections_YYYY-MM-DD.log
│   └── processes_YYYY-MM-DD.log
├── Baselines/
│   ├── firmware_hashes.json
│   ├── driver_baseline.json
│   └── service_baseline.json
├── driver/SmKext/src/       # Kernel driver source (WFP callout — optional)
└── screenshots/
    └── dashboard.png
```

## Uninstall

```powershell
Unregister-ScheduledTask -TaskName "SecurityMonitor" -Confirm:$false
Remove-Item "$env:USERPROFILE\Desktop\SecurityMonitor.lnk" -ErrorAction SilentlyContinue
```

## License

MIT
