// SPDX-License-Identifier: MIT
// Run-as-admin command runner. The PowerShell port wraps every privileged
// action (firewall rule add/remove, DNS provider change, registry restore)
// in an "elevated PowerShell launcher" that triggers a UAC prompt and runs
// a small script. This file does the same thing from C#.
//
// We deliberately stay with shell-out instead of pulling in the WMI / WFP
// COM surfaces because the PS commands (Set-NetFirewallProfile,
// Set-DnsClientServerAddress, etc.) are battle-tested and well documented,
// and the cost of one extra process spawn per setting toggle is negligible.

using System;
using System.Diagnostics;
using System.IO;

namespace WhitehatSecurity.Core;

public static class ElevationHelper
{
    /// <summary>
    /// Writes the given PowerShell snippet to a temp file, launches it
    /// elevated via UAC, waits up to 30 s for it to finish, and returns the
    /// process exit code (0 = success). Logs failures via the supplied
    /// logger so they show up in the Console tab.
    /// </summary>
    public static int RunElevated(string script, Logger? logger = null)
    {
        string tmpFile = Path.Combine(Path.GetTempPath(),
            $"whs_elev_{Guid.NewGuid():N}.ps1");

        try
        {
            File.WriteAllText(tmpFile, script);

            var psi = new ProcessStartInfo
            {
                FileName        = "powershell.exe",
                Arguments       = $"-NoProfile -ExecutionPolicy Bypass -File \"{tmpFile}\"",
                Verb            = "runas",   // triggers UAC
                UseShellExecute = true,      // mandatory for Verb=runas
                WindowStyle     = ProcessWindowStyle.Hidden,
                CreateNoWindow  = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                logger?.Error("Elevation: Process.Start returned null");
                return -1;
            }

            if (!proc.WaitForExit(30_000))
            {
                logger?.Warn("Elevation: 30 s timeout, killing");
                try { proc.Kill(); } catch { }
                return -2;
            }

            int code = proc.ExitCode;
            if (code != 0)
                logger?.Warn($"Elevation: exit {code}");
            return code;
        }
        catch (Exception ex)
        {
            // Most common: user clicked No on UAC → throws Win32Exception
            logger?.Error($"Elevation failed: {ex.Message}");
            return -3;
        }
        finally
        {
            try { File.Delete(tmpFile); } catch { }
        }
    }

    // ------------------------------------------------------------------------
    // Common privileged actions, exposed as a small typed surface so the UI
    // doesn't have to know about PowerShell quoting.
    // ------------------------------------------------------------------------

    public static int SetFirewallProfile(string profile, bool enabled, Logger? logger = null)
    {
        // profile = "Domain" | "Private" | "Public"
        var state = enabled ? "True" : "False";
        return RunElevated(
            $"Set-NetFirewallProfile -Name {profile} -Enabled {state} -ErrorAction Stop",
            logger);
    }

    public static int SetBlockInboundRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? "Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Block -ErrorAction Stop"
            : "Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Allow -ErrorAction Stop";
        return RunElevated(script, logger);
    }

    public static int SetBlockOutboundRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? "Set-NetFirewallProfile -Name Domain,Private,Public -DefaultOutboundAction Block -ErrorAction Stop"
            : "Set-NetFirewallProfile -Name Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction Stop";
        return RunElevated(script, logger);
    }

    public static int SetBlockPingRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? "if (-not (Get-NetFirewallRule -DisplayName 'WHS_BlockICMP' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'WHS_BlockICMP' -Direction Inbound -Protocol ICMPv4 -Action Block | Out-Null }"
            : "Get-NetFirewallRule -DisplayName 'WHS_BlockICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule";
        return RunElevated(script, logger);
    }

    public static int BlockIpAddress(string ip, Logger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(ip)) return -4;
        var script = $@"
$ip = '{ip}'
$ruleIn  = ""WHS_Block_$ip" + @"_In""
$ruleOut = ""WHS_Block_$ip" + @"_Out""
if (-not (Get-NetFirewallRule -DisplayName $ruleIn  -ErrorAction SilentlyContinue)) {{
    New-NetFirewallRule -DisplayName $ruleIn  -Direction Inbound  -Action Block -RemoteAddress $ip -Profile Any | Out-Null
}}
if (-not (Get-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue)) {{
    New-NetFirewallRule -DisplayName $ruleOut -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
}}
";
        return RunElevated(script, logger);
    }

    public static int KillProcessElevated(int pid, Logger? logger = null)
        => RunElevated($"Stop-Process -Id {pid} -Force -ErrorAction Stop", logger);

    public static int SetDnsProvider(string providerName, Logger? logger = null)
    {
        // providerName comes from the Settings dropdown — see DnsProvider.cs
        var (v4Primary, v4Secondary) = providerName switch
        {
            "Cloudflare" => ("1.1.1.1",       "1.0.0.1"),
            "Quad9"      => ("9.9.9.9",       "149.112.112.112"),
            "Google"     => ("8.8.8.8",       "8.8.4.4"),
            "OpenDNS"    => ("208.67.222.222","208.67.220.220"),
            "AdGuard"    => ("94.140.14.14",  "94.140.15.15"),
            _            => ("",              ""),
        };

        string script;
        if (string.IsNullOrEmpty(v4Primary))
        {
            // Reset to DHCP
            script = "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }";
        }
        else
        {
            script = $"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('{v4Primary}','{v4Secondary}') }}";
        }
        return RunElevated(script, logger);
    }
}
