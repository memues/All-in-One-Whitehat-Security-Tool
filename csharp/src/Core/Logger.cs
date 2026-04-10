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
    private readonly Lock _lock = new();

    public Logger(string logsDir)
    {
        _logsDir = logsDir;
        _hostName = Environment.MachineName;
        Directory.CreateDirectory(_logsDir);
    }

    public void Info (string message)        => Write("INFO",  "monitor", message);
    public void Warn (string message)        => Write("WARN",  "monitor", message);
    public void Error(string message)        => Write("ERROR", "monitor", message);
    public void Alert(string message)        => Write("ALERT", "alerts",  message);

    public void Connection(string message)   => Write("INFO",  "connections", message);
    public void Process   (string message)   => Write("INFO",  "processes",   message);

    private void Write(string level, string stream, string message)
    {
        var stamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var line  = $"[{stamp}] [{_hostName}] [{level}] {message}";

        var file = Path.Combine(_logsDir, $"{stream}_{DateTime.Now:yyyy-MM-dd}.log");

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
