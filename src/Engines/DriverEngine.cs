// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Management;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class DriverEngine : IMonitorEngine
{
    public string Name => "Drivers";

    private readonly Dictionary<string, string> _baseline =
        new(StringComparer.OrdinalIgnoreCase);

    public void Initialize()
    {
        if (!TryEnumerateDrivers(out var drivers)) return;
        foreach (var driver in drivers)
            _baseline[driver.Name] = driver.Path;
    }

    public IEnumerable<Alert> Scan()
    {
        if (!TryEnumerateDrivers(out var drivers))
            yield break;

        var current = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var driver in drivers)
            current[driver.Name] = driver.Path;

        foreach (var (name, path) in current)
        {
            if (!_baseline.TryGetValue(name, out var previous))
            {
                yield return new Alert(
                    DateTime.Now, "Driver", "NEW DRIVER",
                    $"{name} ({path})", AlertSeverity.High, Path: path);
            }
            else if (!string.Equals(
                         previous, path, StringComparison.OrdinalIgnoreCase))
            {
                yield return new Alert(
                    DateTime.Now, "Driver", "DRIVER PATH CHANGED",
                    $"{name}: {previous} -> {path}",
                    AlertSeverity.High, Path: path);
            }

            _baseline[name] = path;
        }

        var removed = new List<string>();
        foreach (var name in _baseline.Keys)
            if (!current.ContainsKey(name))
                removed.Add(name);

        foreach (var name in removed)
        {
            yield return new Alert(
                DateTime.Now, "Driver", "DRIVER REMOVED",
                name, AlertSeverity.Med);
            _baseline.Remove(name);
        }
    }

    private static bool TryEnumerateDrivers(out List<DriverRecord> records)
    {
        records = new List<DriverRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, PathName FROM Win32_SystemDriver");
            using var results = searcher.Get();
            foreach (ManagementObject item in results)
            {
                try
                {
                    var name = item["Name"]?.ToString();
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    records.Add(new DriverRecord(
                        name, item["PathName"]?.ToString() ?? string.Empty));
                }
                finally
                {
                    item.Dispose();
                }
            }
            return true;
        }
        catch
        {
            records.Clear();
            return false;
        }
    }

    private readonly record struct DriverRecord(string Name, string Path);
}
