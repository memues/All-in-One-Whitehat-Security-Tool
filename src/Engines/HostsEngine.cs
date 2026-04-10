// SPDX-License-Identifier: MIT
// Watches the hosts file for content changes by hashing it on each scan.
// One alert per change. Mirrors line ~6708 of the PS port.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public sealed class HostsEngine : IMonitorEngine
{
    public string Name => "Hosts";

    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "drivers", "etc", "hosts");

    private string? _baselineHash;

    public void Initialize() => _baselineHash = HashFileSafe(_path);

    public IEnumerable<Alert> Scan()
    {
        var current = HashFileSafe(_path);
        if (current is null || current == _baselineHash) yield break;

        var prev = _baselineHash;
        _baselineHash = current;

        yield return new Alert(
            Timestamp: DateTime.Now,
            Category:  "Hosts",
            Title:     "HOSTS FILE CHANGED",
            Message:   $"{_path}: {prev?[..16] ?? "?"}... -> {current[..16]}...",
            Severity:  AlertSeverity.High,
            Path:      _path);
    }

    private static string? HashFileSafe(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var sha = SHA256.Create();
            using var fs  = File.OpenRead(path);
            var hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash);
        }
        catch
        {
            return null;
        }
    }
}
