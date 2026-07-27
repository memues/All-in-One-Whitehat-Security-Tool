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
using System.Net;

namespace WhitehatSecurity.Core;

public static class ElevationHelper
{
    /// <summary>
    /// Re-launches this signed application with a narrowly-scoped internal
    /// command. Payloads used by remediation commands are Base64 and command
    /// names are fixed by the caller, so no shell is involved.
    /// </summary>
    public static int RunSelfElevated(
        string arguments,
        Logger? logger = null,
        int timeoutMilliseconds = 30_000)
    {
        if (string.IsNullOrWhiteSpace(arguments)
            || arguments.Contains('\r')
            || arguments.Contains('\n'))
            return -5;

        var self = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(self) || !File.Exists(self))
            return -1;

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = self,
                Arguments = arguments,
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null) return -1;
            if (!process.WaitForExit(timeoutMilliseconds))
            {
                logger?.Warn("Elevated remediation timed out.");
                try { process.Kill(); } catch { }
                return -2;
            }
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            logger?.Warn($"Elevated remediation was cancelled or failed: {ex.Message}");
            return -3;
        }
    }

    internal static int CleanupManagedChanges(Logger? logger = null)
    {
        const string script = @"
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like 'WHS_*' |
    Remove-NetFirewallRule -ErrorAction Stop

$hosts = ""$env:SystemRoot\System32\drivers\etc\hosts""
if (Test-Path $hosts) {
    $content = Get-Content $hosts -Raw
    $pattern = '(?s)# WHS-BEGIN-(Trackers|Malware|Telemetry).*?# WHS-END-\1\r?\n?'
    $content = [regex]::Replace($content, $pattern, '')
    [System.IO.File]::WriteAllText($hosts, $content)
}

$dataDir = Join-Path $env:ProgramData 'Whitehat Security'
$backup = Join-Path $dataDir 'dns-backup.json'
if (Test-Path $backup) {
    $saved = @(Get-Content $backup -Raw | ConvertFrom-Json)
    foreach ($adapter in $saved) {
        $addresses = @($adapter.ServerAddresses)
        if ($addresses.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $addresses
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
        }
    }
    if (Get-Command Remove-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        '1.1.1.1','9.9.9.9','8.8.8.8','94.140.14.14' | ForEach-Object {
            $address = $_
            Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue |
                Where-Object ServerAddress -eq $address |
                Remove-DnsClientDohServerAddress -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    Remove-Item $dataDir -Recurse -Force
}";
        return RunDirect(script, logger);
    }

    private static int RunDirect(string script, Logger? logger)
    {
        var tmpFile = Path.Combine(
            Path.GetTempPath(), $"whs_cleanup_{Guid.NewGuid():N}.ps1");
        try
        {
            File.WriteAllText(
                tmpFile, "$ErrorActionPreference = 'Stop'\r\n" + script);
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments =
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{tmpFile}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null) return -1;
            if (!process.WaitForExit(30_000))
            {
                try { process.Kill(); } catch { }
                return -2;
            }
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            logger?.Warn($"Cleanup failed: {ex.Message}");
            return -3;
        }
        finally
        {
            try { File.Delete(tmpFile); } catch { }
        }
    }

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
            File.WriteAllText(
                tmpFile,
                "$ErrorActionPreference = 'Stop'\r\n" + script);

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
        // Validate `profile` against an allowlist before interpolating it
        // into the elevated PowerShell snippet. The current UI only ever
        // passes one of these three strings, but defense in depth: every
        // value that crosses into a privileged script must be either
        // typed-validated or quoted, never trusted as-is.
        if (profile != "Domain" && profile != "Private" && profile != "Public")
        {
            logger?.Warn($"SetFirewallProfile: rejected invalid profile '{profile}'");
            return -5;
        }
        var state = enabled ? "True" : "False";
        return RunElevated(
            $"Set-NetFirewallProfile -Name {profile} -Enabled {state} -ErrorAction Stop",
            logger);
    }

    public static int SetBlockInboundRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? "if (-not (Get-NetFirewallRule -DisplayName 'WHS_BlockAllInbound' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'WHS_BlockAllInbound' -Direction Inbound -Action Block -Profile Any | Out-Null }"
            : "Get-NetFirewallRule -DisplayName 'WHS_BlockAllInbound' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop";
        return RunElevated(script, logger);
    }

    public static int SetBlockOutboundRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? "if (-not (Get-NetFirewallRule -DisplayName 'WHS_BlockAllOutbound' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'WHS_BlockAllOutbound' -Direction Outbound -Action Block -Profile Any | Out-Null }"
            : "Get-NetFirewallRule -DisplayName 'WHS_BlockAllOutbound' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop";
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

        // CRITICAL SECURITY FIX: previous versions interpolated `ip`
        // straight into a PowerShell script. An IP that contained
        // PowerShell metacharacters or single quotes (e.g. an attacker
        // poisoning a remote-IP-derived alert) would execute arbitrary
        // elevated code. Validate against IPAddress.TryParse first; once
        // an address has round-tripped through Parse, the canonical
        // string form is restricted to digits, dots, colons, and
        // hexadecimal — none of which can break out of a single-quoted
        // PowerShell literal.
        if (!IPAddress.TryParse(ip, out var parsed))
        {
            logger?.Warn($"BlockIpAddress: rejected non-IP value '{ip}'");
            return -5;
        }
        var safeIp = parsed.ToString();

        var script = $@"
$ip = '{safeIp}'
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

    public static int UnblockIpAddress(string ip, Logger? logger = null)
    {
        if (!IPAddress.TryParse(ip, out var parsed))
            return -5;
        var safeIp = parsed.ToString();
        var script = $@"
$ip = '{safeIp}'
$ruleIn  = ""WHS_Block_$ip" + @"_In""
$ruleOut = ""WHS_Block_$ip" + @"_Out""
Get-NetFirewallRule -DisplayName $ruleIn -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
Get-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
";
        return RunElevated(script, logger);
    }

    public static int KillProcessElevated(int pid, Logger? logger = null)
        => RunElevated($"Stop-Process -Id {pid} -Force -ErrorAction Stop", logger);

    // ------------------------------------------------------------------------
    //  v7.3.0 — settings that previously persisted to JSON only
    // ------------------------------------------------------------------------

    /// <summary>
    /// Block all RFC1918 traffic via firewall rules. Disrupts file/printer
    /// sharing on the local network — only enable if you really mean it.
    /// </summary>
    public static int SetBlockLanRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? @"
$names = 'WHS_BlockLAN_Out_192168','WHS_BlockLAN_Out_10','WHS_BlockLAN_Out_172'
$addrs = '192.168.0.0/16',          '10.0.0.0/8',          '172.16.0.0/12'
for ($i = 0; $i -lt $names.Count; $i++) {
    if (-not (Get-NetFirewallRule -DisplayName $names[$i] -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $names[$i] -Direction Outbound -Action Block -RemoteAddress $addrs[$i] -Profile Any | Out-Null
    }
}"
            : @"
'WHS_BlockLAN_Out_192168','WHS_BlockLAN_Out_10','WHS_BlockLAN_Out_172' | ForEach-Object {
    Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}";
        return RunElevated(script, logger);
    }

    /// <summary>
    /// Block SMB / NetBIOS / LLMNR / mDNS — kills network device discovery
    /// and file sharing on the local subnet without isolating the machine
    /// from the internet.
    /// </summary>
    public static int SetBlockDevicesRule(bool enabled, Logger? logger = null)
    {
        var script = enabled
            ? @"
$rules = @(
    @{ Name='WHS_BlockDev_SMB_Out';      Dir='Outbound'; Proto='TCP'; Port='445';  Side='RemotePort' },
    @{ Name='WHS_BlockDev_SMB_In';       Dir='Inbound';  Proto='TCP'; Port='445';  Side='LocalPort' },
    @{ Name='WHS_BlockDev_NetBIOS_Out';  Dir='Outbound'; Proto='TCP'; Port='139';  Side='RemotePort' },
    @{ Name='WHS_BlockDev_NetBIOS_In';   Dir='Inbound';  Proto='TCP'; Port='139';  Side='LocalPort' },
    @{ Name='WHS_BlockDev_NetBIOSU_Out'; Dir='Outbound'; Proto='UDP'; Port='137-138'; Side='RemotePort' },
    @{ Name='WHS_BlockDev_NetBIOSU_In';  Dir='Inbound';  Proto='UDP'; Port='137-138'; Side='LocalPort' },
    @{ Name='WHS_BlockDev_LLMNR_Out';    Dir='Outbound'; Proto='UDP'; Port='5355'; Side='RemotePort' },
    @{ Name='WHS_BlockDev_mDNS_Out';     Dir='Outbound'; Proto='UDP'; Port='5353'; Side='RemotePort' }
)
foreach ($r in $rules) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
        $args = @{ DisplayName=$r.Name; Direction=$r.Dir; Action='Block'; Protocol=$r.Proto; Profile='Any' }
        $args[$r.Side] = $r.Port
        New-NetFirewallRule @args | Out-Null
    }
}"
            : @"
'WHS_BlockDev_SMB_Out','WHS_BlockDev_SMB_In','WHS_BlockDev_NetBIOS_Out','WHS_BlockDev_NetBIOS_In','WHS_BlockDev_NetBIOSU_Out','WHS_BlockDev_NetBIOSU_In','WHS_BlockDev_LLMNR_Out','WHS_BlockDev_mDNS_Out' | ForEach-Object {
    Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}";
        return RunElevated(script, logger);
    }

    /// <summary>
    /// Add or remove a managed block of hostnames in the system hosts file.
    /// Categories: "Trackers", "Malware", "Telemetry". The block is wrapped
    /// in `# WHS-BEGIN-{category}` / `# WHS-END-{category}` markers so the
    /// uninstaller can find and remove it without touching anything else.
    /// </summary>
    public static int SetHostsBlocklist(string category, bool enabled, Logger? logger = null)
    {
        var domains = HostsBlocklists.ForCategory(category);
        if (domains.Length == 0) return 0;

        var beginMark = $"# WHS-BEGIN-{category}";
        var endMark   = $"# WHS-END-{category}";

        // Build the line list inside C# rather than embedding it in PS so we
        // do not have to worry about quoting. The PS script just rewrites
        // the hosts file with the managed block added or removed.
        var lines = string.Join("\r\n",
            System.Linq.Enumerable.Select(domains, d => "0.0.0.0  " + d));

        var b64Block = System.Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{beginMark}\r\n{lines}\r\n{endMark}\r\n"));

        var script = enabled
            ? $@"
$hosts = ""$env:SystemRoot\System32\drivers\etc\hosts""
$content = if (Test-Path $hosts) {{ Get-Content $hosts -Raw }} else {{ '' }}
# Strip any pre-existing managed block for this category, then append fresh
$pattern = '(?s)# WHS-BEGIN-{category}.*?# WHS-END-{category}\r?\n?'
$content = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, '')
$block = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64Block}'))
if (-not $content.EndsWith(""`r`n"")) {{ $content += ""`r`n"" }}
$content += $block
[System.IO.File]::WriteAllText($hosts, $content)"
            : $@"
$hosts = ""$env:SystemRoot\System32\drivers\etc\hosts""
if (Test-Path $hosts) {{
    $content = Get-Content $hosts -Raw
    $pattern = '(?s)# WHS-BEGIN-{category}.*?# WHS-END-{category}\r?\n?'
    $content = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, '')
    [System.IO.File]::WriteAllText($hosts, $content)
}}";
        return RunElevated(script, logger);
    }

    /// <summary>
    /// Block outbound port 53 traffic so applications can no longer bypass
    /// the system DNS resolver. Used together with DNS_Provider to enforce
    /// a specific DNS server for everything on the machine.
    /// </summary>
    public static int SetDnsBypassBlock(bool enabled, Logger? logger = null)
    {
        if (enabled)
        {
            logger?.Warn(
                "DNS bypass lock rejected: a blanket port-53 block also blocks the Windows DNS client.");
            return -6;
        }
        return RunElevated(
            "Get-NetFirewallRule -DisplayName 'WHS_DNSLock_Out' -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
            logger);
    }

    /// <summary>
    /// Configure DNS-over-HTTPS for the active providers. Requires Windows 11
    /// DNS client cmdlets. Enabling reports an error on unsupported systems
    /// instead of persisting a setting that was never applied.
    /// </summary>
    public static int SetDnsOverHttps(bool enabled, string provider, Logger? logger = null)
    {
        // DoH endpoints for the providers offered in the Settings dropdown
        var (v4Primary, dohTemplate) = provider switch
        {
            "Cloudflare" => ("1.1.1.1",        "https://cloudflare-dns.com/dns-query"),
            "Quad9"      => ("9.9.9.9",        "https://dns.quad9.net/dns-query"),
            "Google"     => ("8.8.8.8",        "https://dns.google/dns-query"),
            "AdGuard"    => ("94.140.14.14",   "https://dns.adguard.com/dns-query"),
            _            => ("",               ""),
        };

        if (!enabled)
        {
            if (string.IsNullOrEmpty(v4Primary)) return 0;
            var clearScript = $@"
if (Get-Command Remove-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {{
    Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue |
        Where-Object ServerAddress -eq '{v4Primary}' |
        Remove-DnsClientDohServerAddress -Confirm:$false -ErrorAction Stop
}}";
            return RunElevated(clearScript, logger);
        }
        if (string.IsNullOrEmpty(v4Primary)) return -5;

        var setScript = $@"
if (-not (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {{
    exit 6
}}
try {{
    Add-DnsClientDohServerAddress -ServerAddress '{v4Primary}' -DohTemplate '{dohTemplate}' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
}} catch {{
    Set-DnsClientDohServerAddress -ServerAddress '{v4Primary}' -DohTemplate '{dohTemplate}' -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction Stop
}}
Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {{
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('{v4Primary}')
}}";
        return RunElevated(setScript, logger);
    }

    public static int SetDnsProvider(string providerName, Logger? logger = null)
    {
        var valid = providerName is "None" or "Cloudflare" or "Quad9"
            or "Google" or "OpenDNS" or "AdGuard";
        if (!valid) return -5;
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
            script = @"
$backup = Join-Path $env:ProgramData 'Whitehat Security\dns-backup.json'
if (Test-Path $backup) {
    $saved = @(Get-Content $backup -Raw | ConvertFrom-Json)
    foreach ($adapter in $saved) {
        $addresses = @($adapter.ServerAddresses)
        if ($addresses.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $addresses
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
        }
    }
    Remove-Item $backup -Force
} else {
    Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
    }
}";
        }
        else
        {
            script = $@"
$backup = Join-Path $env:ProgramData 'Whitehat Security\dns-backup.json'
if (-not (Test-Path $backup)) {{
    $directory = Split-Path $backup -Parent
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $active = Get-NetAdapter | Where-Object Status -eq 'Up'
    $saved = foreach ($adapter in $active) {{
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
        [pscustomobject]@{{
            InterfaceIndex = $adapter.ifIndex
            ServerAddresses = @($dns.ServerAddresses)
        }}
    }}
    @($saved) | ConvertTo-Json -Depth 4 | Set-Content -Path $backup -Encoding UTF8
}}
Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {{
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('{v4Primary}','{v4Secondary}')
}}";
        }
        return RunElevated(script, logger);
    }
}
