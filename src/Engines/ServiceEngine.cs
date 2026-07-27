// SPDX-License-Identifier: MIT
// Service baseline + new service detection. Mirrors New-ServiceBaseline in
// SecurityMonitor.ps1. Uses ServiceController instead of WMI for speed.

using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class ServiceEngine : IMonitorEngine
{
    public string Name => "Services";

    private readonly HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);

    public void Initialize()
    {
        foreach (var name in EnumerateServiceNames())
            _baseline.Add(name);
    }

    public IEnumerable<Alert> Scan()
    {
        var current = EnumerateServiceNames().ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var name in current)
        {
            if (_baseline.Add(name))
            {
                var path = ReadServicePath(name);
                yield return new Alert(
                    Timestamp: DateTime.Now,
                    Category:  "Service",
                    Title:     "NEW SERVICE",
                    Message:   string.IsNullOrWhiteSpace(path)
                        ? name
                        : $"{name} ({path})",
                    Severity:  AlertSeverity.High,
                    Path:      ThreatPath.Normalize(path),
                    Extra:     new Dictionary<string, string>
                    {
                        ["ServiceName"] = name,
                    });
            }
        }
    }

    private static string[] EnumerateServiceNames()
    {
        ServiceController[] all;
        try { all = ServiceController.GetServices(); }
        catch { return Array.Empty<string>(); }
        try
        {
            return all.Select(service => service.ServiceName).ToArray();
        }
        finally
        {
            foreach (var service in all)
                service.Dispose();
        }
    }

    private static string? ReadServicePath(string name)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}");
            return key?.GetValue(
                "ImagePath", null,
                Microsoft.Win32.RegistryValueOptions
                    .DoNotExpandEnvironmentNames)?.ToString();
        }
        catch { return null; }
    }
}
