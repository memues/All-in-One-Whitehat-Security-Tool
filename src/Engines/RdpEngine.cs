// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using Microsoft.Win32;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class RdpEngine : IMonitorEngine
{
    public string Name => "RDP";
    private const string KeyPath =
        @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private bool? _enabled;

    public void Initialize() => _enabled = ReadEnabled();

    public IEnumerable<Alert> Scan()
    {
        var current = ReadEnabled();
        if (current is null || _enabled is null)
        {
            _enabled = current;
            yield break;
        }
        if (current == _enabled) yield break;

        _enabled = current;
        yield return new Alert(
            DateTime.Now,
            "RDP",
            current.Value ? "REMOTE DESKTOP ENABLED" : "REMOTE DESKTOP DISABLED",
            current.Value
                ? "Windows Remote Desktop was enabled."
                : "Windows Remote Desktop was disabled.",
            current.Value ? AlertSeverity.High : AlertSeverity.Info,
            Extra: new Dictionary<string, string>
            {
                ["RegistryPath"] =
                    $@"HKEY_LOCAL_MACHINE\{KeyPath}",
                ["ValueName"] = "fDenyTSConnections",
            });
    }

    private static bool? ReadEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath);
            var value = key?.GetValue("fDenyTSConnections");
            return value is int deny ? deny == 0 : null;
        }
        catch
        {
            return null;
        }
    }
}
