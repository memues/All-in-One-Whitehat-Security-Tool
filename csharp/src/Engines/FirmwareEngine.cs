// SPDX-License-Identifier: MIT
// Hashes every .sys / .efi / .rom / .bin under known firmware/driver paths and
// alerts on any hash change, new file, or deleted file. Mirrors
// New-FirmwareBaseline + the firmware-diff block in SecurityMonitor.ps1
// (~line 5731).
//
// Phase 1: only watches C:\Windows\System32\drivers — the most common kernel
// driver location. The PS port also walks SystemRoot\inf, the EFI partition
// and a few OEM paths. Adding more roots is one line: extend WatchedRoots.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class FirmwareEngine : IMonitorEngine
{
    public string Name => "Firmware";

    private readonly Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] WatchedRoots =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"),
    };

    private static readonly string[] WatchedExtensions =
    {
        ".sys", ".efi", ".rom", ".bin",
    };

    public void Initialize()
    {
        foreach (var (path, hash) in EnumerateAndHash())
            _baseline[path] = hash;
    }

    public IEnumerable<Alert> Scan()
    {
        var current = EnumerateAndHash().ToDictionary(t => t.Path, t => t.Hash, StringComparer.OrdinalIgnoreCase);

        // Hash mismatch / new file
        foreach (var (path, hash) in current)
        {
            if (!_baseline.TryGetValue(path, out var prev))
            {
                yield return new Alert(
                    Timestamp: DateTime.Now,
                    Category:  "Firmware",
                    Title:     "NEW FIRMWARE FILE",
                    Message:   $"{Path.GetFileName(path)} ({hash[..16]}...)",
                    Severity:  AlertSeverity.High,
                    Path:      path);
            }
            else if (!string.Equals(prev, hash, StringComparison.OrdinalIgnoreCase))
            {
                yield return new Alert(
                    Timestamp: DateTime.Now,
                    Category:  "Firmware",
                    Title:     "FIRMWARE FILE HASH CHANGED",
                    Message:   $"{Path.GetFileName(path)}",
                    Severity:  AlertSeverity.Crit,
                    Path:      path);
            }
            _baseline[path] = hash;
        }

        // Deleted files
        var removed = _baseline.Keys.Where(k => !current.ContainsKey(k)).ToList();
        foreach (var k in removed)
        {
            yield return new Alert(
                Timestamp: DateTime.Now,
                Category:  "Firmware",
                Title:     "FIRMWARE FILE DELETED",
                Message:   Path.GetFileName(k),
                Severity:  AlertSeverity.Med,
                Path:      k);
            _baseline.Remove(k);
        }
    }

    private static IEnumerable<(string Path, string Hash)> EnumerateAndHash()
    {
        foreach (var root in WatchedRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (Array.IndexOf(WatchedExtensions, ext) < 0) continue;

                string? h = HashSafe(file);
                if (h is not null)
                    yield return (file, h);
            }
        }
    }

    private static string? HashSafe(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs  = File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(fs));
        }
        catch
        {
            return null;
        }
    }
}
