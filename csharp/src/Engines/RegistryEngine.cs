// SPDX-License-Identifier: MIT
// Watches Run/RunOnce keys and the tamper-key list from the PowerShell port
// (~line 6772). When a value under any of these keys changes, an alert is
// raised — independent of whether the change is benign (Windows Update) or
// malicious. The PS port had this exact "high noise, high signal" tradeoff.

using System;
using System.Collections.Generic;
using Microsoft.Win32;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class RegistryEngine : IMonitorEngine
{
    public string Name => "Registry";

    /// <summary>
    /// (RegistryHive, KeyPath, ValueName) → last observed value (string form).
    /// </summary>
    private readonly Dictionary<(RegistryHive, string, string), string?> _baseline = new();

    private static readonly (RegistryHive Hive, string Key, string Value)[] WatchedValues =
    {
        // Persistence keys
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "*"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "*"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run", "*"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "*"),

        // Tamper-key list — same set as PS port line ~6772-6800
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile", "EnableFirewall"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall"),
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\WinDefend", "Start"),
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\wscsvc", "Start"),
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mpssvc", "Start"),
    };

    public void Initialize()
    {
        foreach (var (hive, key, name) in WatchedValues)
            ScanKey(hive, key, name, baselineMode: true);
    }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();
        foreach (var (hive, key, name) in WatchedValues)
            ScanKey(hive, key, name, baselineMode: false, alerts: alerts);
        return alerts;
    }

    private void ScanKey(
        RegistryHive  hive,
        string        keyPath,
        string        valueNameOrStar,
        bool          baselineMode,
        List<Alert>?  alerts = null)
    {
        try
        {
            using var rootKey = OpenKey(hive);
            using var sub = rootKey.OpenSubKey(keyPath);
            if (sub is null) return;

            var valueNames = valueNameOrStar == "*"
                ? sub.GetValueNames()
                : new[] { valueNameOrStar };

            foreach (var vn in valueNames)
            {
                var current = sub.GetValue(vn)?.ToString();
                var slot = (hive, keyPath, vn);

                if (baselineMode)
                {
                    _baseline[slot] = current;
                    continue;
                }

                if (!_baseline.TryGetValue(slot, out var prev))
                {
                    _baseline[slot] = current;
                    if (current is not null)
                        alerts?.Add(MakeAlert(hive, keyPath, vn, "added", current));
                }
                else if (!Equals(prev, current))
                {
                    _baseline[slot] = current;
                    alerts?.Add(MakeAlert(hive, keyPath, vn, "changed", $"{prev} -> {current}"));
                }
            }
        }
        catch
        {
            // unreachable key — leave the baseline alone
        }
    }

    private static RegistryKey OpenKey(RegistryHive hive) => hive switch
    {
        RegistryHive.LocalMachine => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64),
        RegistryHive.CurrentUser  => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser,  RegistryView.Registry64),
        _                         => RegistryKey.OpenBaseKey(hive, RegistryView.Default),
    };

    private static Alert MakeAlert(RegistryHive hive, string keyPath, string value, string action, string detail)
        => new(
            Timestamp: DateTime.Now,
            Category:  "Registry",
            Title:     $"REGISTRY {action.ToUpperInvariant()}",
            Message:   $"{hive}\\{keyPath}!{value}: {detail}",
            Severity:  AlertSeverity.Med);
}
