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
    /// (RegistryHive, RegistryView, KeyPath, ValueName) → last observed
    /// string-form value. The RegistryView part lets us track the 32-bit
    /// (WOW6432Node) and 64-bit views of the same key independently — both
    /// are valid persistence locations on a 64-bit system.
    /// </summary>
    private readonly Dictionary<(RegistryHive, RegistryView, string, string), string?> _baseline = new();

    /// <summary>
    /// Both views are scanned on 64-bit systems. The 32-bit view sees the
    /// WOW6432Node namespace, where some malware hides persistence to evade
    /// 64-bit-only scanners.
    /// </summary>
    private static readonly RegistryView[] WatchedViews =
        Environment.Is64BitOperatingSystem
            ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
            : new[] { RegistryView.Registry32 };

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
        foreach (var view in WatchedViews)
            foreach (var (hive, key, name) in WatchedValues)
                ScanKey(hive, view, key, name, baselineMode: true);
    }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();
        foreach (var view in WatchedViews)
            foreach (var (hive, key, name) in WatchedValues)
                ScanKey(hive, view, key, name, baselineMode: false, alerts: alerts);
        return alerts;
    }

    private void ScanKey(
        RegistryHive  hive,
        RegistryView  view,
        string        keyPath,
        string        valueNameOrStar,
        bool          baselineMode,
        List<Alert>?  alerts = null)
    {
        try
        {
            using var rootKey = RegistryKey.OpenBaseKey(hive, view);
            using var sub = rootKey.OpenSubKey(keyPath);
            if (sub is null) return;

            var valueNames = valueNameOrStar == "*"
                ? sub.GetValueNames()
                : new[] { valueNameOrStar };

            foreach (var vn in valueNames)
            {
                var current = sub.GetValue(vn)?.ToString();
                var slot = (hive, view, keyPath, vn);

                if (baselineMode)
                {
                    _baseline[slot] = current;
                    continue;
                }

                if (!_baseline.TryGetValue(slot, out var prev))
                {
                    _baseline[slot] = current;
                    if (current is not null)
                        alerts?.Add(MakeAlert(hive, view, keyPath, vn, "added", current));
                }
                else if (!Equals(prev, current))
                {
                    _baseline[slot] = current;
                    alerts?.Add(MakeAlert(hive, view, keyPath, vn, "changed", $"{prev} -> {current}"));
                }
            }
        }
        catch
        {
            // unreachable key — leave the baseline alone
        }
    }

    private static Alert MakeAlert(
        RegistryHive hive,
        RegistryView view,
        string       keyPath,
        string       value,
        string       action,
        string       detail)
    {
        var viewTag = view == RegistryView.Registry32 ? " (32)" : "";
        return new Alert(
            Timestamp: DateTime.Now,
            Category:  "Registry",
            Title:     $"REGISTRY {action.ToUpperInvariant()}",
            Message:   $"{hive}{viewTag}\\{keyPath}!{value}: {detail}",
            Severity:  AlertSeverity.Med);
    }
}
