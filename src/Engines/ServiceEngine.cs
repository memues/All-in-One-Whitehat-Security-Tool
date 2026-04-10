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
                yield return new Alert(
                    Timestamp: DateTime.Now,
                    Category:  "Service",
                    Title:     "NEW SERVICE",
                    Message:   name,
                    Severity:  AlertSeverity.High);
            }
        }
    }

    private static IEnumerable<string> EnumerateServiceNames()
    {
        ServiceController[] all;
        try { all = ServiceController.GetServices(); }
        catch { yield break; }

        foreach (var sc in all)
        {
            yield return sc.ServiceName;
            sc.Dispose();
        }
    }
}
