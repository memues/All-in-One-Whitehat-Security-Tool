// SPDX-License-Identifier: MIT
// Driver baseline + change detection. Mirrors the New-DriverBaseline /
// driver-diff blocks in SecurityMonitor.ps1.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class DriverEngine : IMonitorEngine
{
    public string Name => "Drivers";

    private readonly Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);

    public void Initialize()
    {
        foreach (var d in EnumerateDrivers())
            _baseline[d.Name] = d.PathAt;
    }

    public IEnumerable<Alert> Scan()
    {
        var current = EnumerateDrivers().ToDictionary(d => d.Name, d => d.PathAt, StringComparer.OrdinalIgnoreCase);

        // New drivers
        foreach (var (name, path) in current)
        {
            if (_baseline.ContainsKey(name)) continue;

            yield return new Alert(
                Timestamp: DateTime.Now,
                Category:  "Driver",
                Title:     "NEW DRIVER",
                Message:   $"{name} ({path})",
                Severity:  AlertSeverity.High,
                Path:      path);

            _baseline[name] = path;
        }

        // Removed drivers
        var removed = new List<string>();
        foreach (var name in _baseline.Keys)
            if (!current.ContainsKey(name))
                removed.Add(name);

        foreach (var name in removed)
        {
            yield return new Alert(
                Timestamp: DateTime.Now,
                Category:  "Driver",
                Title:     "DRIVER REMOVED",
                Message:   name,
                Severity:  AlertSeverity.Med);
            _baseline.Remove(name);
        }
    }

    private readonly record struct DriverRecord(string Name, string PathAt);

    private static IEnumerable<DriverRecord> EnumerateDrivers()
    {
        // Win32_SystemDriver returns kernel-mode drivers (Service Type = 1 or 2)
        // — same set Get-WmiObject Win32_SystemDriver returns in PowerShell.
        ManagementObjectCollection? results;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, PathName FROM Win32_SystemDriver");
            results = searcher.Get();
        }
        catch
        {
            yield break;
        }

        foreach (ManagementObject mo in results)
        {
            string? name = mo["Name"]?.ToString();
            string? path = mo["PathName"]?.ToString();
            if (string.IsNullOrEmpty(name)) continue;
            yield return new DriverRecord(name!, path ?? "");
            mo.Dispose();
        }
    }
}
