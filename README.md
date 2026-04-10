# All-in-One Whitehat Security Tool

A real-time Windows security monitoring tool written in C# / .NET 8 / WinForms. Compiles to a single self-contained `.exe`.

This repository previously also contained a PowerShell implementation (`SecurityMonitor.ps1`) plus an experimental C kernel driver. Both have been removed — only the C# version remains. The C# version was built specifically to sidestep the AMSI heuristic detections (`Heur.BZC.ZFV.Boxter`, `HackTool:PowerShell/Mimikatz`, etc.) that the PowerShell version reliably triggered because of its plaintext attack-tool name lists, hidden-window plus execution-policy-bypass combination, and download-cradle install pattern.

A compiled `.exe` avoids those problems entirely:

| Old PowerShell problem | How the compiled `.exe` solves it |
|------------------------|-----------------------------------|
| AMSI scans script content for malware substrings | No script — code is JIT-compiled from a binary assembly |
| Each detection pattern sits in plain text in the source | Patterns live as compiled constants, not visible to AMSI |
| `-ExecutionPolicy Bypass -WindowStyle Hidden` flagged | Native `.exe`, no PowerShell flags involved |
| Persistence + download + hidden window in one script = `Heur.Boxter` | Single binary, no install cradle |
| Slow start (interpret + JIT 7 000 lines on every run) | Compiled binary starts in ~150 ms |
| End user has to allow PowerShell execution policy | End user just runs `WhitehatSecurity.exe` |

## Build

Requires the **.NET 8 SDK** (https://dotnet.microsoft.com/download — `winget install Microsoft.DotNet.SDK.8`).

```pwsh
dotnet build -c Release
```

Single-file self-contained release (one `.exe`, no .NET runtime needed on the target machine):

```pwsh
dotnet publish -c Release -r win-x64 --self-contained
```

The published binary lives at `bin\Release\net8.0-windows\win-x64\publish\WhitehatSecurity.exe`.

## Install / Uninstall

The `.exe` is its own installer. Just download `WhitehatSecurity.exe` from the latest release and double-click it:

- **First run from outside Program Files**: a small dialog asks whether you want to install system-wide. Yes → triggers UAC, then:
  - copies the `.exe` to `C:\Program Files\Whitehat Security\`
  - registers in Windows **Apps & Features**
  - creates a **Start Menu** shortcut
  - creates a shortcut on **the user's Desktop** (handles OneDrive Known Folder Move) and on the **Public Desktop**
  - adds an **HKLM\…\Run** entry so the program **auto-starts at every logon** in tray-only mode (`--silent`)
- **Uninstall**: open *Settings → Apps → Apps & Features*, find **Whitehat Security**, click *Uninstall*. Or run `WhitehatSecurity.exe --uninstall` from a terminal. The uninstaller removes the install dir, both desktop shortcuts, the Start Menu shortcut, the Apps & Features registry entry, and the auto-start Run entry.

CLI flags:

| Flag | Effect |
|------|--------|
| (none) | Tray icon + dashboard |
| `--silent` | Tray icon only, no dashboard auto-open, no install prompt |
| `--install` | Copy self to Program Files, register in Add/Remove Programs (must be run elevated; UAC is requested automatically when triggered from the first-run dialog) |
| `--uninstall` | Remove install dir, shortcuts, registry entry (run elevated) |
| `--quiet` | Suppress success/error message boxes during install/uninstall |

## Layout

```
.
├── WhitehatSecurity.csproj
├── app.manifest                  # asInvoker / DPI / longPath manifest
├── Program.cs                    # entry point + single-instance mutex
└── src/
    ├── Core/
    │   ├── NotifyConfig.cs       # JSON config (notification_config.json)
    │   ├── Logger.cs             # daily rolling log files
    │   ├── Alert.cs              # alert record + AlertGate
    │   └── MonitorHost.cs        # background loop runner
    ├── Engines/
    │   ├── IMonitorEngine.cs     # engine contract
    │   ├── ConnectionEngine.cs   # outbound TCP / new remote IPs
    │   ├── ListenerEngine.cs     # new listening sockets
    │   ├── ProcessEngine.cs      # unsigned new processes
    │   ├── DriverEngine.cs       # new / removed kernel drivers
    │   ├── ServiceEngine.cs      # new Windows services
    │   ├── RegistryEngine.cs     # Run/RunOnce + tampering keys
    │   ├── HostsEngine.cs        # hosts-file hash watch
    │   └── FirmwareEngine.cs     # .sys / .efi / .rom hashing
    ├── Native/
    │   ├── NativeMethods.cs      # P/Invoke (kernel32, ntdll, iphlpapi)
    │   ├── NativeStructs.cs      # MIB_TCPROW_OWNER_PID, etc.
    │   └── NotifyIconPromote.cs  # Win11 IsPromoted registry helper
    └── Ui/
        ├── TrayApplicationContext.cs
        ├── DashboardForm.cs
        ├── DashboardForm.Designer.cs
        └── ToastNotifier.cs
```

## Features

| Feature                                              | Status |
|------------------------------------------------------|:------:|
| Six-page sidebar dashboard (Status / Alerts / AI Threats / Settings / Logs / Console) | ✓ |
| Self-installing single .exe (Apps & Features integration) | ✓ |
| Auto-start at logon via HKLM Run key (`--silent`)    | ✓ |
| Desktop + Start Menu shortcuts on install            | ✓ |
| System tray icon + context menu                      | ✓ |
| Windows 11 NotifyIcon `IsPromoted` self-promotion    | ✓ |
| Balloon / toast notifications                        | ✓ |
| Outbound TCP connection tracker                      | ✓ |
| New listening port detection                         | ✓ |
| Unsigned process detection                           | ✓ |
| Driver baseline + change detection                   | ✓ |
| Service baseline + change detection                  | ✓ |
| Run / RunOnce registry watch                         | ✓ |
| Tamper-key registry watch (32 + 64-bit views)        | ✓ |
| Hosts-file SHA-256 watch                             | ✓ |
| Firmware (`.sys` / `.efi` / `.rom`) hash watch       | ✓ |
| Hidden process detection via `NtQuerySystemInformation` | ✓ |
| RWX private memory scanner                           | ✓ |
| BYOVD vulnerable driver detection                    | ✓ |
| **`Connection` notification opt-in by default**      | ✓ |
| Per-day rolling log files                            | ✓ |
| Single-instance mutex                                | ✓ |
| Status page **live** posture row (Defender / Firewall / UAC / RDP / SecureBoot / TPM / HVCI / BitLocker) | ✓ |
| Alerts page search + severity & category filters     | ✓ |
| Alerts page export to CSV / JSON                     | ✓ |
| Alerts page sortable column headers                  | ✓ |
| Audible alert (`BeepOnAlert`)                        | ✓ |
| Alert detail toggle (`ShowThreatDetails`)            | ✓ |
| 3 firewall profile toggles + 5 firewall block rules  | ✓ |
| Hosts-based blocklists (Trackers / Malware / Telemetry) | ✓ |
| DNS provider switching with revert-on-failure        | ✓ |
| DNS-over-HTTPS (Windows 11)                          | ✓ |
| Block DNS bypass (port 53 outbound)                  | ✓ |
| ETW provider listener                                | TODO |
| WinRT toast (vs legacy balloons)                     | TODO |
| Sidebar collapse animation                           | TODO |
| Live charts on Status page                           | TODO |

The TODO items are documented in the source so adding them later does not require changes to the `IMonitorEngine` contract or the dispatcher.

## Run

```pwsh
.\WhitehatSecurity.exe            # tray + dashboard
.\WhitehatSecurity.exe --silent   # tray only, no dashboard auto-open
```

The first run writes `notification_config.json` next to the executable with the **same defaults** as the PowerShell version, including `Connection = false` (the noisiest category is opt-in).

## License

Same as the parent repository.
