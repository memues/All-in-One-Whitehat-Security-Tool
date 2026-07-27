// SPDX-License-Identifier: MIT
// Per-day rolling log files. The format matches Write-Log in
// SecurityMonitor.ps1: "[timestamp] [host] [LEVEL] message".

using System;
using System.IO;
using System.Threading;

namespace WhitehatSecurity.Core;

public sealed class Logger
{
    private readonly string _logsDir;
    private readonly string _hostName;
    // .NET 8 has no `Lock` type (added in .NET 9 / C# 13). Plain object is fine.
    private readonly object _lock = new();

    public Logger(string logsDir)
    {
        _logsDir = logsDir;
        _hostName = Environment.MachineName;
        // Wrapped in try/catch so a non-writable directory (e.g., Program Files
        // when the .exe is launched as asInvoker) does not crash the entire
        // process. The Write method is also try/catch'd, so subsequent writes
        // simply drop on the floor if the directory cannot be created.
        try { Directory.CreateDirectory(_logsDir); } catch { }
    }

    /// <summary>
    /// Best-effort log retention. Deletes any *.log file in the logs dir
    /// whose LastWriteTime is older than <paramref name="maxAgeDays"/>.
    /// Called once at startup from Program.cs so the disk footprint
    /// stays bounded over months of running.
    /// </summary>
    public void CleanupOldLogs(int maxAgeDays = 30)
    {
        try
        {
            if (!Directory.Exists(_logsDir)) return;
            var cutoff = DateTime.Now.AddDays(-maxAgeDays);
            foreach (var file in Directory.EnumerateFiles(_logsDir, "*.log"))
            {
                try
                {
                    if (File.GetLastWriteTime(file) < cutoff)
                    {
                        File.Delete(file);
                        Info($"Deleted old log file {Path.GetFileName(file)}");
                    }
                }
                catch
                {
                    // skip files we can't touch (in use, locked by another
                    // process, denied by AV) — they'll be retried next start
                }
            }
        }
        catch
        {
            // never let log retention crash the process
        }
    }

    public void Info (string message)        => Write("INFO",  "monitor", message);
    public void Warn (string message)        => Write("WARN",  "monitor", message);
    public void Error(string message)        => Write("ERROR", "monitor", message);
    public void Alert(string message)        => Write("ALERT", "alerts",  message);

    public void Connection(string message)   => Write("INFO",  "connections", message);
    public void Process   (string message)   => Write("INFO",  "processes",   message);

    private void Write(string level, string stream, string message)
    {
        var now = DateTime.Now;
        var stamp = now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var line  = $"[{stamp}] [{_hostName}] [{level}] {message}";

        var file = Path.Combine(_logsDir, $"{stream}_{now:yyyy-MM-dd}.log");

        lock (_lock)
        {
            try
            {
                File.AppendAllText(file, line + Environment.NewLine);
            }
            catch
            {
                // logging must never throw — drop on the floor if disk is full
            }
        }

        // Also mirror INFO/WARN/ERROR to stdout when running attached. ALERT
        // entries are piped through the AlertSink to also reach the UI.
        if (stream == "monitor")
        {
            try { Console.WriteLine(line); } catch { }
        }
    }
}
