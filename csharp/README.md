# All-in-One Whitehat Security Tool — C# Port

A faithful C# / .NET 8 / WinForms port of the original PowerShell `SecurityMonitor.ps1`. Compiles to a single `.exe` for easier deployment and to reduce AMSI false positives that the PowerShell version triggers.

## Why a C# port

The PowerShell original is ~7 000 lines and reliably trips heuristic AV detection (`Heur.BZC.ZFV.Boxter`, `HackTool:PowerShell/Mimikatz`, etc.) because it combines persistence, hidden execution, native API calls and lists of attack-tool names — a behavior pattern that AV engines flag as a malware installer even though it is purely defensive.

A compiled `.exe` solves several problems at once:

| Problem with the PowerShell original | How the C# port fixes it |
|--------------------------------------|--------------------------|
| AMSI scans script content for malware substrings | No script — code is JIT-compiled from a signed assembly |
| Each detection-pattern string sits in plain text in the source | Patterns live as constants in a binary, not visible to AMSI |
| `-ExecutionPolicy Bypass -WindowStyle Hidden` combination flagged | Native `.exe`, no PowerShell flags involved |
| Persistence + download + hidden window in one script = `Heur.Boxter` | Installer and runtime are separate compiled binaries |
| Slow start (interpret + JIT 7 000 lines on every run) | Compiled binary starts in ~150 ms |
| End user has to allow PowerShell execution policy | End user just runs `WhitehatSecurity.exe` |

## Build

Requires the **.NET 8 SDK** (https://dotnet.microsoft.com/download).

```pwsh
cd csharp
dotnet build -c Release
```

Single-file self-contained release (one `.exe`, no .NET runtime needed on the target machine):

```pwsh
dotnet publish -c Release -r win-x64 --self-contained
```

The published binary lives at `bin\Release\net8.0-windows\win-x64\publish\WhitehatSecurity.exe`.

## Layout

```
csharp/
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

## Functional parity matrix vs the PowerShell original

| Feature                                 | PowerShell | C# port |
|-----------------------------------------|:----------:|:-------:|
| System tray icon + context menu         | ✓ | ✓ |
| Win11 NotifyIcon `IsPromoted` fix       | ✓ | ✓ |
| Toast / balloon notifications           | ✓ | ✓ |
| Dashboard with Alerts/Logs/Settings tabs | ✓ | ✓ |
| Outbound TCP connection tracking        | ✓ | ✓ |
| New listening port detection            | ✓ | ✓ |
| Unsigned process detection              | ✓ | ✓ |
| Driver baseline + change detection      | ✓ | ✓ |
| Service baseline + change detection     | ✓ | ✓ |
| Run / RunOnce registry watch            | ✓ | ✓ |
| Tamper-key registry watch               | ✓ | ✓ |
| Hosts file hash watch                   | ✓ | ✓ |
| Firmware (.sys/.efi/.rom) hash watch    | ✓ | ✓ |
| Hidden process via NtQuerySystemInformation | ✓ | ✓ |
| **`Connection` notification opt-in by default** | ✓ | ✓ |
| Per-day rolling log files               | ✓ | ✓ |
| BYOVD vulnerable driver detection       | ✓ | (see TODO) |
| WinForms dashboard charts               | ✓ | (see TODO) |
| Memory-region scanning (ML risk-scoring)| ✓ | (see TODO) |

The "see TODO" items are the noisiest / heaviest engines. They are documented in the source as `// TODO: port from SecurityMonitor.ps1 line N` markers and are designed so that adding them later does not require changes to the engine contract or the dispatcher.

## Run

```pwsh
.\WhitehatSecurity.exe            # tray + dashboard
.\WhitehatSecurity.exe --silent   # tray only, no dashboard auto-open
```

The first run writes `notification_config.json` next to the executable with the **same defaults** as the PowerShell version, including `Connection = false` (the noisiest category is opt-in).

## License

Same as the parent repository.
