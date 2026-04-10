// SPDX-License-Identifier: MIT
// "Bring Your Own Vulnerable Driver" detection. Compares the system driver
// list against a static catalogue of well-known signed-but-buggy drivers
// that attackers carry along to escalate to kernel without writing their
// own malicious driver (which would not be Microsoft-signed).
//
// The catalogue is intentionally tiny and conservative — every entry on it
// is publicly documented as having been used in real BYOVD attacks. The
// list lives in the source so the binary stays self-contained; a fancier
// build could refresh it from the loldrivers.io feed at startup.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class ByovdEngine : IMonitorEngine
{
    public string Name => "BYOVD";

    /// <summary>
    /// File names (no path, lowercase) of known-vulnerable but
    /// Microsoft-signed drivers that have been weaponised in published
    /// BYOVD attacks. Match is exact on the file basename.
    /// </summary>
    private static readonly HashSet<string> Catalogue = new(StringComparer.OrdinalIgnoreCase)
    {
        "rtcore64.sys",        // MSI Afterburner — used by RobbinHood, BlackByte
        "gdrv.sys",            // Gigabyte — Slingshot, Lazarus
        "asuso.sys",           // Asus — multiple ransomware campaigns
        "asio2.sys",           // Asus IO driver
        "asio3.sys",
        "asushwdrv.sys",
        "iqvw64e.sys",         // Intel — used in MyKings, KdMapper exploits
        "iqvw64.sys",
        "viragt64.sys",        // VirtualBox — Lazarus
        "vboxdrv.sys",
        "msio64.sys",          // MSI io driver
        "msio32.sys",
        "winring0x64.sys",     // RealTemp — many cryptominers
        "winring0.sys",
        "speedfan.sys",        // SpeedFan — early BYOVD example
        "amifldrv64.sys",      // AMI flash driver
        "process_hacker.sys",  // Process Hacker / KProcessHacker
        "kprocesshacker.sys",
        "procexp.sys",         // SysInternals Process Explorer (kernel)
        "procexp152.sys",
        "capcom.sys",          // Capcom Street Fighter V — first published BYOVD POC
        "dbutil_2_3.sys",      // Dell — CVE-2021-21551
        "dbutildrv2.sys",
        "ntiolib.sys",         // MSI
        "atillk64.sys",        // ATI
        "amdpowerprofiler.sys",
        "stcvsm.sys",          // Sentinel HASP
    };

    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);

    public void Initialize() { /* no baseline phase */ }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();

        ManagementObjectCollection? results;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, PathName FROM Win32_SystemDriver WHERE State = 'Running'");
            results = searcher.Get();
        }
        catch
        {
            return alerts;
        }

        foreach (ManagementObject mo in results)
        {
            try
            {
                var path = mo["PathName"]?.ToString() ?? "";
                var fileName = Path.GetFileName(path);
                if (string.IsNullOrEmpty(fileName)) continue;

                if (Catalogue.Contains(fileName) && _alerted.Add(fileName))
                {
                    alerts.Add(new Alert(
                        Timestamp: DateTime.Now,
                        Category:  "BYOVD",
                        Title:     "VULNERABLE DRIVER LOADED",
                        Message:   $"{fileName} is a known-vulnerable signed driver ({path})",
                        Severity:  AlertSeverity.High,
                        Path:      path));
                }
            }
            finally
            {
                mo.Dispose();
            }
        }

        return alerts;
    }
}
