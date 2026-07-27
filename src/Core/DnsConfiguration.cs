// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;

namespace WhitehatSecurity.Core;

/// <summary>
/// A DNS provider offered by the dashboard. Both IPv4 addresses are kept
/// together so provider switching and DNS-over-HTTPS cannot accidentally
/// configure only the primary resolver.
/// </summary>
public sealed record DnsProviderDefinition(
    string Name,
    string PrimaryIpv4,
    string SecondaryIpv4,
    string? DohTemplate);

/// <summary>
/// Builds the privileged PowerShell used for DNS changes. Keeping the script
/// generation separate makes the safety properties testable without changing
/// the machine's network configuration.
/// </summary>
public static class DnsConfiguration
{
    private static readonly IReadOnlyDictionary<string, DnsProviderDefinition>
        Providers = new Dictionary<string, DnsProviderDefinition>(
            StringComparer.Ordinal)
        {
            ["Cloudflare"] = new(
                "Cloudflare", "1.1.1.1", "1.0.0.1",
                "https://cloudflare-dns.com/dns-query"),
            ["Quad9"] = new(
                "Quad9", "9.9.9.9", "149.112.112.112",
                "https://dns.quad9.net/dns-query"),
            ["Google"] = new(
                "Google", "8.8.8.8", "8.8.4.4",
                "https://dns.google/dns-query"),
            ["OpenDNS"] = new(
                "OpenDNS", "208.67.222.222", "208.67.220.220", null),
            ["AdGuard"] = new(
                "AdGuard", "94.140.14.14", "94.140.15.15",
                "https://dns.adguard.com/dns-query"),
        };

    public static bool TryGetProvider(
        string providerName,
        out DnsProviderDefinition? provider)
    {
        if (providerName is null)
        {
            provider = null;
            return false;
        }
        return Providers.TryGetValue(providerName, out provider);
    }

    public static string BuildProviderScript(string providerName)
    {
        if (providerName == "None")
            return CommonPowerShell + ResetPowerShell;
        if (!TryGetProvider(providerName, out var provider)
            || provider is null)
            throw new ArgumentOutOfRangeException(
                nameof(providerName), providerName,
                "Unknown DNS provider.");

        return CommonPowerShell
            + ApplyProviderPowerShell
                .Replace("__PRIMARY__", provider.PrimaryIpv4)
                .Replace("__SECONDARY__", provider.SecondaryIpv4);
    }

    public static string BuildDohScript(
        bool enabled,
        string providerName)
    {
        if (!TryGetProvider(providerName, out var provider)
            || provider?.DohTemplate is null)
            throw new ArgumentOutOfRangeException(
                nameof(providerName), providerName,
                "The DNS provider does not support managed DoH.");

        var template = enabled
            ? EnableDohPowerShell
            : DisableDohPowerShell;
        return CommonPowerShell
            + template
                .Replace("__PRIMARY__", provider.PrimaryIpv4)
                .Replace("__SECONDARY__", provider.SecondaryIpv4)
                .Replace("__DOH_TEMPLATE__", provider.DohTemplate);
    }

    // Prefer interfaces that actually own a live default IPv4 route. This
    // avoids Hyper-V Default Switch and other "Up" virtual adapters that
    // reject Set-DnsClientServerAddress. The physical-adapter fallback keeps
    // the feature useful while a default route is briefly being renewed.
    private const string CommonPowerShell = """

function Get-WhsDnsTargetIndices {
    $upAdapters = @(Get-NetAdapter -ErrorAction Stop |
        Where-Object { $_.Status -eq 'Up' })
    $upIndices = @($upAdapters |
        Select-Object -ExpandProperty ifIndex -Unique)
    $indices = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $upIndices -contains [int]$_.InterfaceIndex } |
        Sort-Object RouteMetric |
        Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($indices.Count -eq 0) {
        $indices = @($upAdapters |
            Where-Object {
                $_.HardwareInterface -and -not $_.Virtual
            } |
            Select-Object -ExpandProperty ifIndex -Unique)
    }
    if ($indices.Count -eq 0) {
        throw 'No active IPv4 internet interface was found.'
    }
    return @($indices)
}

function Get-WhsDnsSnapshot {
    param([int[]] $InterfaceIndices)
    foreach ($index in $InterfaceIndices) {
        $adapter = Get-NetAdapter -InterfaceIndex $index `
            -ErrorAction Stop
        $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $adapter.InterfaceGuid
        $configured = ''
        try {
            $configured = [string](Get-ItemPropertyValue `
                -LiteralPath $registryPath -Name NameServer `
                -ErrorAction Stop)
        } catch {
            $configured = ''
        }
        $dns = Get-DnsClientServerAddress `
            -InterfaceIndex $index -AddressFamily IPv4 `
            -ErrorAction Stop
        [pscustomobject]@{
            InterfaceIndex = [int]$index
            InterfaceAlias = [string]$adapter.Name
            Automatic = [string]::IsNullOrWhiteSpace($configured)
            ServerAddresses = @($dns.ServerAddresses)
        }
    }
}

function Restore-WhsDnsSnapshot {
    param([object[]] $Snapshot)
    foreach ($item in @($Snapshot)) {
        $adapter = Get-NetAdapter `
            -InterfaceIndex ([int]$item.InterfaceIndex) `
            -ErrorAction SilentlyContinue
        if ($null -eq $adapter) { continue }
        if ([bool]$item.Automatic) {
            Set-DnsClientServerAddress `
                -InterfaceIndex ([int]$item.InterfaceIndex) `
                -ResetServerAddresses -ErrorAction Stop
        } else {
            $addresses = @($item.ServerAddresses)
            if ($addresses.Count -eq 0) {
                throw "Saved DNS configuration for interface $($item.InterfaceIndex) is empty."
            }
            Set-DnsClientServerAddress `
                -InterfaceIndex ([int]$item.InterfaceIndex) `
                -ServerAddresses $addresses -ErrorAction Stop
        }
    }
}

function Assert-WhsDnsAddresses {
    param([int] $InterfaceIndex, [string[]] $Expected)
    $actual = @((Get-DnsClientServerAddress `
        -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 `
        -ErrorAction Stop).ServerAddresses)
    if ($actual.Count -ne $Expected.Count) {
        throw "DNS verification failed on interface $InterfaceIndex."
    }
    for ($i = 0; $i -lt $Expected.Count; $i++) {
        if ($actual[$i] -ne $Expected[$i]) {
            throw "DNS verification failed on interface $InterfaceIndex."
        }
    }
}

function Assert-WhsDnsAutomatic {
    param([int] $InterfaceIndex)
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop
    $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $adapter.InterfaceGuid
    $configured = ''
    try {
        $configured = [string](Get-ItemPropertyValue `
            -LiteralPath $registryPath -Name NameServer `
            -ErrorAction Stop)
    } catch {
        $configured = ''
    }
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        throw "Automatic DNS verification failed on interface $InterfaceIndex."
    }
}

""";

    private const string ApplyProviderPowerShell = """
$targets = @(Get-WhsDnsTargetIndices)
$beforeApply = @(Get-WhsDnsSnapshot -InterfaceIndices $targets)
$backup = Join-Path $env:ProgramData `
    'Whitehat Security\dns-backup.json'
$createdBackup = $false
try {
    if (-not (Test-Path -LiteralPath $backup)) {
        $directory = Split-Path $backup -Parent
        New-Item -ItemType Directory -Path $directory `
            -Force -ErrorAction Stop | Out-Null
        @($beforeApply) | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $backup -Encoding UTF8 `
                -ErrorAction Stop
        $createdBackup = $true
    }
    foreach ($index in $targets) {
        Set-DnsClientServerAddress -InterfaceIndex $index `
            -ServerAddresses @('__PRIMARY__','__SECONDARY__') `
            -ErrorAction Stop
    }
    foreach ($index in $targets) {
        Assert-WhsDnsAddresses -InterfaceIndex $index `
            -Expected @('__PRIMARY__','__SECONDARY__')
    }
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        Restore-WhsDnsSnapshot -Snapshot $beforeApply
        if ($createdBackup) {
            Remove-Item -LiteralPath $backup -Force `
                -ErrorAction SilentlyContinue
        }
    } catch {
        throw "DNS apply failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";

    private const string ResetPowerShell = """
$targets = @(Get-WhsDnsTargetIndices)
$beforeReset = @(Get-WhsDnsSnapshot -InterfaceIndices $targets)
$backup = Join-Path $env:ProgramData `
    'Whitehat Security\dns-backup.json'
try {
    if (Test-Path -LiteralPath $backup) {
        $saved = @(Get-Content -LiteralPath $backup -Raw `
            -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
        $targetSet = @{}
        foreach ($index in $targets) {
            $targetSet[[int]$index] = $true
        }
        $saved = @($saved | Where-Object {
            $targetSet.ContainsKey([int]$_.InterfaceIndex)
        })
        if ($saved.Count -gt 0) {
            Restore-WhsDnsSnapshot -Snapshot $saved
            foreach ($item in $saved) {
                if ([bool]$item.Automatic) {
                    Assert-WhsDnsAutomatic `
                        -InterfaceIndex ([int]$item.InterfaceIndex)
                } else {
                    Assert-WhsDnsAddresses `
                        -InterfaceIndex ([int]$item.InterfaceIndex) `
                        -Expected @($item.ServerAddresses)
                }
            }
        } else {
            foreach ($index in $targets) {
                Set-DnsClientServerAddress -InterfaceIndex $index `
                    -ResetServerAddresses -ErrorAction Stop
                Assert-WhsDnsAutomatic -InterfaceIndex $index
            }
        }
        Remove-Item -LiteralPath $backup -Force `
            -ErrorAction Stop
    } else {
        foreach ($index in $targets) {
            Set-DnsClientServerAddress -InterfaceIndex $index `
                -ResetServerAddresses -ErrorAction Stop
            Assert-WhsDnsAutomatic -InterfaceIndex $index
        }
    }
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        Restore-WhsDnsSnapshot -Snapshot $beforeReset
    } catch {
        throw "DNS reset failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";

    private const string EnableDohPowerShell = """
if (-not (Get-Command Add-DnsClientDohServerAddress `
    -ErrorAction SilentlyContinue)) {
    exit 6
}
$addresses = @('__PRIMARY__','__SECONDARY__')
$targets = @(Get-WhsDnsTargetIndices)
$beforeDns = @(Get-WhsDnsSnapshot -InterfaceIndices $targets)
$beforeDoh = foreach ($address in $addresses) {
    $entry = Get-DnsClientDohServerAddress `
        -ServerAddress $address -ErrorAction SilentlyContinue
    if ($null -eq $entry) {
        [pscustomobject]@{
            ServerAddress = $address
            Exists = $false
        }
    } else {
        [pscustomobject]@{
            ServerAddress = $address
            Exists = $true
            DohTemplate = [string]$entry.DohTemplate
            AllowFallbackToUdp = [bool]$entry.AllowFallbackToUdp
            AutoUpgrade = [bool]$entry.AutoUpgrade
        }
    }
}
try {
    foreach ($address in $addresses) {
        $entry = Get-DnsClientDohServerAddress `
            -ServerAddress $address -ErrorAction SilentlyContinue
        if ($null -eq $entry) {
            Add-DnsClientDohServerAddress `
                -ServerAddress $address `
                -DohTemplate '__DOH_TEMPLATE__' `
                -AllowFallbackToUdp $false -AutoUpgrade $true `
                -ErrorAction Stop
        } else {
            Set-DnsClientDohServerAddress `
                -ServerAddress $address `
                -DohTemplate '__DOH_TEMPLATE__' `
                -AllowFallbackToUdp $false -AutoUpgrade $true `
                -ErrorAction Stop
        }
    }
    foreach ($index in $targets) {
        Set-DnsClientServerAddress -InterfaceIndex $index `
            -ServerAddresses $addresses -ErrorAction Stop
        Assert-WhsDnsAddresses -InterfaceIndex $index `
            -Expected $addresses
    }
    foreach ($address in $addresses) {
        $entry = Get-DnsClientDohServerAddress `
            -ServerAddress $address -ErrorAction Stop
        if (-not [bool]$entry.AutoUpgrade -or
            [string]$entry.DohTemplate -ne '__DOH_TEMPLATE__') {
            throw "DoH verification failed for $address."
        }
    }
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        Restore-WhsDnsSnapshot -Snapshot $beforeDns
        foreach ($item in $beforeDoh) {
            if ([bool]$item.Exists) {
                Set-DnsClientDohServerAddress `
                    -ServerAddress $item.ServerAddress `
                    -DohTemplate $item.DohTemplate `
                    -AllowFallbackToUdp ([bool]$item.AllowFallbackToUdp) `
                    -AutoUpgrade ([bool]$item.AutoUpgrade) `
                    -ErrorAction Stop
            } else {
                Remove-DnsClientDohServerAddress `
                    -ServerAddress $item.ServerAddress `
                    -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    } catch {
        throw "DoH apply failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";

    private const string DisableDohPowerShell = """
if (-not (Get-Command Set-DnsClientDohServerAddress `
    -ErrorAction SilentlyContinue)) {
    exit 6
}
$addresses = @('__PRIMARY__','__SECONDARY__')
$beforeDoh = foreach ($address in $addresses) {
    $entry = Get-DnsClientDohServerAddress `
        -ServerAddress $address -ErrorAction SilentlyContinue
    if ($null -ne $entry) {
        [pscustomobject]@{
            ServerAddress = $address
            DohTemplate = [string]$entry.DohTemplate
            AllowFallbackToUdp = [bool]$entry.AllowFallbackToUdp
            AutoUpgrade = [bool]$entry.AutoUpgrade
        }
    }
}
try {
    foreach ($item in @($beforeDoh)) {
        Set-DnsClientDohServerAddress `
            -ServerAddress $item.ServerAddress `
            -DohTemplate $item.DohTemplate `
            -AllowFallbackToUdp ([bool]$item.AllowFallbackToUdp) `
            -AutoUpgrade $false -ErrorAction Stop
    }
    foreach ($item in @($beforeDoh)) {
        $entry = Get-DnsClientDohServerAddress `
            -ServerAddress $item.ServerAddress -ErrorAction Stop
        if ([bool]$entry.AutoUpgrade) {
            throw "DoH disable verification failed for $($item.ServerAddress)."
        }
    }
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        foreach ($item in @($beforeDoh)) {
            Set-DnsClientDohServerAddress `
                -ServerAddress $item.ServerAddress `
                -DohTemplate $item.DohTemplate `
                -AllowFallbackToUdp ([bool]$item.AllowFallbackToUdp) `
                -AutoUpgrade ([bool]$item.AutoUpgrade) `
                -ErrorAction Stop
        }
    } catch {
        throw "DoH disable failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";
}
