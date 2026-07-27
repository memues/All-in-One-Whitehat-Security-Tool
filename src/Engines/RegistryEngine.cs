// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class RegistryEngine : IMonitorEngine
{
    public string Name => "Registry";

    private readonly Dictionary<RegistrySlot, RegistryValueSnapshot> _baseline =
        new();

    private static readonly RegistryView[] WatchedViews =
        Environment.Is64BitOperatingSystem
            ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
            : new[] { RegistryView.Registry32 };

    private static readonly (RegistryHive Hive, string Key, string Value)[] WatchedValues =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "*"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "*"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run", "*"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "*"),
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
            foreach (var watched in WatchedValues)
                Capture(watched.Hive, view, watched.Key, watched.Value, true, null);
    }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();
        foreach (var view in WatchedViews)
            foreach (var watched in WatchedValues)
                Capture(
                    watched.Hive, view, watched.Key, watched.Value,
                    false, alerts);
        return alerts;
    }

    private void Capture(
        RegistryHive hive,
        RegistryView view,
        string keyPath,
        string valueNameOrStar,
        bool baselineMode,
        List<Alert>? alerts)
    {
        Dictionary<string, RegistryValueSnapshot> current;
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            using var key = root.OpenSubKey(keyPath);

            current = new Dictionary<string, RegistryValueSnapshot>(
                StringComparer.OrdinalIgnoreCase);
            if (key is null)
            {
                if (valueNameOrStar != "*")
                    current[valueNameOrStar] =
                        RegistryValueSnapshot.Missing;
            }
            else if (valueNameOrStar == "*")
            {
                foreach (var name in key.GetValueNames())
                    current[name] =
                        RegistryValueSnapshot.Capture(key, name);
            }
            else
            {
                current[valueNameOrStar] =
                    RegistryValueSnapshot.Capture(
                        key, valueNameOrStar);
            }
        }
        catch
        {
            return;
        }

        foreach (var (name, value) in current)
        {
            var slot = new RegistrySlot(hive, view, keyPath, name);
            if (baselineMode)
            {
                _baseline[slot] = value;
                continue;
            }

            if (!_baseline.TryGetValue(slot, out var previous))
            {
                _baseline[slot] = value;
                if (value.Exists)
                    alerts?.Add(MakeAlert(
                        slot, "added",
                        RegistryValueSnapshot.Missing, value));
            }
            else if (previous != value)
            {
                _baseline[slot] = value;
                var action = !previous.Exists && value.Exists
                    ? "added"
                    : value.Exists
                        ? "changed"
                        : "removed";
                alerts?.Add(MakeAlert(slot, action, previous, value));
            }
        }

        if (valueNameOrStar != "*" || baselineMode) return;

        var removed = _baseline.Keys.Where(slot =>
                slot.Hive == hive
                && slot.View == view
                && string.Equals(
                    slot.KeyPath, keyPath,
                    StringComparison.OrdinalIgnoreCase)
                && !current.ContainsKey(slot.ValueName))
            .ToList();
        foreach (var slot in removed)
        {
            var previous = _baseline[slot];
            if (!previous.Exists) continue;
            _baseline[slot] = RegistryValueSnapshot.Missing;
            alerts?.Add(MakeAlert(
                slot, "removed",
                previous, RegistryValueSnapshot.Missing));
        }
    }

    private static Alert MakeAlert(
        RegistrySlot slot,
        string action,
        RegistryValueSnapshot before,
        RegistryValueSnapshot after)
    {
        var viewTag = slot.View == RegistryView.Registry32 ? " (32)" : "";
        var root = RegistryRollbackService.HiveName(slot.Hive);
        var registryPath = $"{root}\\{slot.KeyPath}";
        var displayPath = $"{root}{viewTag}\\{slot.KeyPath}";
        var payload = new RegistryChangePayload(
            slot.Hive,
            slot.View,
            slot.KeyPath,
            slot.ValueName,
            action,
            before,
            after);
        return new Alert(
            DateTime.Now,
            "Registry",
            $"REGISTRY {action.ToUpperInvariant()}",
            $"{displayPath}!{slot.ValueName}: " +
            $"{before.ToDisplayText()} -> {after.ToDisplayText()}",
            AlertSeverity.Med,
            Extra: new Dictionary<string, string>
            {
                ["RegistryPath"] = registryPath,
                ["RegistryView"] =
                    slot.View == RegistryView.Registry32
                        ? "32"
                        : "64",
                ["ValueName"] = slot.ValueName,
                ["Change"] = action,
                ["Previous"] = before.ToDisplayText(),
                ["Detected"] = after.ToDisplayText(),
                [RegistryRollbackService.PayloadMetadataKey] =
                    payload.Encode(),
            });
    }

    private readonly record struct RegistrySlot(
        RegistryHive Hive,
        RegistryView View,
        string KeyPath,
        string ValueName);
}
