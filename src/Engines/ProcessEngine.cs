// SPDX-License-Identifier: MIT
// Detects new processes that are unsigned or running from suspicious paths.
// Mirrors the "2c. Unsigned executables in suspicious locations" block in
// SecurityMonitor.ps1 (~line 712).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using WhitehatSecurity.Core;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Engines;

public sealed class ProcessEngine : IMonitorEngine
{
    public string Name => "Processes";

    private readonly HashSet<int> _knownPids = new();

    private static readonly string[] SuspiciousPathFragments =
    {
        @"\Temp\",
        @"\AppData\Local\Temp\",
        @"\Downloads\",
        @"\Users\Public\",
    };

    public void Initialize()
    {
        // Materialise the snapshot then dispose every Process so we never
        // leak the open kernel handles that Process.GetProcesses returns.
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return; }
        try
        {
            foreach (var p in procs)
            {
                if (p.Id == 0 || p.Id == 4) continue;   // Idle / System
                _knownPids.Add(p.Id);
            }
        }
        finally
        {
            foreach (var p in procs) p.Dispose();
        }
    }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();
        var currentPids = new HashSet<int>();
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return alerts; }

        try
        {
            foreach (var p in procs)
            {
                if (p.Id == 0 || p.Id == 4) continue;   // Idle / System
                currentPids.Add(p.Id);
                if (!_knownPids.Add(p.Id)) continue;

                string? exePath;
                try { exePath = p.MainModule?.FileName; }
                catch { continue; }
                if (string.IsNullOrEmpty(exePath)) continue;

                bool inSuspiciousPath = false;
                foreach (var frag in SuspiciousPathFragments)
                {
                    if (exePath.Contains(frag, StringComparison.OrdinalIgnoreCase))
                    {
                        inSuspiciousPath = true;
                        break;
                    }
                }

                bool signed = AuthenticodeVerifier.IsTrusted(exePath);

                // Decision matrix:
                //   unsigned + suspicious path → CRIT (probable malware drop)
                //   unsigned anywhere          → HIGH
                //   signed + suspicious path   → MED  (legit-looking installer
                //                                       running from Downloads)
                //   signed everywhere else     → no alert (too noisy)
                //
                // The signed-suspicious-path case is why v7.3.x users saw
                // zero Process alerts in normal use: most modern apps are
                // signed, so the unsigned-only branch never fired. Adding
                // the suspicious-path branch catches "user just downloaded
                // and ran an installer" without flooding the dashboard
                // every time a system service starts.
                if (!signed && inSuspiciousPath)
                {
                    alerts.Add(MakeAlert(p, exePath,
                        "UNSIGNED PROCESS IN SUSPICIOUS LOCATION",
                        AlertSeverity.Crit));
                }
                else if (!signed)
                {
                    alerts.Add(MakeAlert(p, exePath,
                        "UNSIGNED NEW PROCESS",
                        AlertSeverity.High));
                }
                else if (inSuspiciousPath)
                {
                    alerts.Add(MakeAlert(p, exePath,
                        "PROCESS LAUNCHED FROM DOWNLOAD/TEMP FOLDER",
                        AlertSeverity.Med));
                }
            }
        }
        finally
        {
            // Dispose every Process — including the ones we yielded above —
            // because we materialise the alerts before returning.
            foreach (var p in procs) p.Dispose();
            _knownPids.IntersectWith(currentPids);
        }

        return alerts;
    }

    /// <summary>
    /// Builds a Process-category Alert with the common fields populated.
    /// Used by the three branches in the decision matrix above so the
    /// matrix stays compact.
    /// </summary>
    private static Alert MakeAlert(Process p, string exePath, string title, AlertSeverity sev)
        => new(
            Timestamp:   DateTime.Now,
            Category:    "Process",
            Title:       title,
            Message:     $"{p.ProcessName} (PID {p.Id})  {exePath}",
            Severity:    sev,
            ProcessName: p.ProcessName,
            ProcessId:   p.Id,
            Path:        exePath);

}
