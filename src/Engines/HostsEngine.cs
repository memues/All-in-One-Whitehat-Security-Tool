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

    private FileState _baseline;

    public void Initialize() => _baseline = ReadState(_path);

    public IEnumerable<Alert> Scan()
    {
        var current = ReadState(_path);
        if (current.Kind == FileStateKind.Unreadable) yield break;
        if (current == _baseline) yield break;

        var previous = _baseline;
        _baseline = current;

        yield return new Alert(
            Timestamp: DateTime.Now,
            Category:  "Hosts",
            Title:     current.Kind == FileStateKind.Missing
                ? "HOSTS FILE DELETED"
                : previous.Kind == FileStateKind.Missing
                    ? "HOSTS FILE CREATED"
                    : "HOSTS FILE CHANGED",
            Message:   DescribeChange(previous, current),
            Severity:  AlertSeverity.High,
            Path:      _path);
    }

    private string DescribeChange(FileState previous, FileState current)
        => $"{_path}: {Short(previous)} -> {Short(current)}";

    private static string Short(FileState state)
        => state.Kind switch
        {
            FileStateKind.Missing => "missing",
            FileStateKind.Unreadable => "unreadable",
            _ => $"{state.Hash![..16]}...",
        };

    private static FileState ReadState(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new FileState(FileStateKind.Missing, null);
            using var sha = SHA256.Create();
            using var fs  = File.OpenRead(path);
            var hash = sha.ComputeHash(fs);
            return new FileState(FileStateKind.Present, Convert.ToHexString(hash));
        }
        catch
        {
            return new FileState(FileStateKind.Unreadable, null);
        }
    }

    private enum FileStateKind { Missing, Present, Unreadable }
    private readonly record struct FileState(FileStateKind Kind, string? Hash);
}
