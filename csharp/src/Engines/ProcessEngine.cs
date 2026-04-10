// SPDX-License-Identifier: MIT
// Detects new processes that are unsigned or running from suspicious paths.
// Mirrors the "2c. Unsigned executables in suspicious locations" block in
// SecurityMonitor.ps1 (~line 712).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using WhitehatSecurity.Core;

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
        foreach (var p in SafeEnumerate())
            _knownPids.Add(p.Id);
    }

    public IEnumerable<Alert> Scan()
    {
        foreach (var p in SafeEnumerate())
        {
            if (!_knownPids.Add(p.Id)) continue;

            string? exePath;
            try { exePath = p.MainModule?.FileName; }
            catch { continue; }
            if (string.IsNullOrEmpty(exePath)) continue;

            bool inSuspiciousPath = false;
            foreach (var frag in SuspiciousPathFragments)
            {
                if (exePath.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    inSuspiciousPath = true;
                    break;
                }
            }

            bool isSigned = IsAuthenticodeSigned(exePath);

            if (!isSigned)
            {
                yield return new Alert(
                    Timestamp:   DateTime.Now,
                    Category:    "Process",
                    Title:       inSuspiciousPath ? "UNSIGNED PROCESS IN SUSPICIOUS LOCATION" : "UNSIGNED NEW PROCESS",
                    Message:     $"{p.ProcessName} (PID {p.Id})",
                    Severity:    inSuspiciousPath ? AlertSeverity.High : AlertSeverity.Med,
                    ProcessName: p.ProcessName,
                    ProcessId:   p.Id,
                    Path:        exePath);
            }
        }
    }

    private static IEnumerable<Process> SafeEnumerate()
    {
        Process[] all;
        try { all = Process.GetProcesses(); }
        catch { yield break; }

        foreach (var p in all)
        {
            if (p.Id == 0 || p.Id == 4) continue;   // Idle / System
            yield return p;
        }
    }

    /// <summary>
    /// Best-effort Authenticode signature check using
    /// X509Certificate.CreateFromSignedFile. Returns false on any error so
    /// inaccessible system processes are not reported as unsigned (we just
    /// skip them by virtue of MainModule throwing first).
    /// </summary>
    private static bool IsAuthenticodeSigned(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            // X509Certificate.CreateFromSignedFile returns the embedded
            // certificate if the PE has an Authenticode signature, otherwise
            // throws CryptographicException.
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            return cert.Subject.Length > 0;
        }
        catch
        {
            return false;
        }
    }
}
