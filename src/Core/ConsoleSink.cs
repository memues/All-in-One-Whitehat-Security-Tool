// SPDX-License-Identifier: MIT
// In-memory ring buffer that captures every alert in a printable form so the
// Console tab in the dashboard can stream it. Also accepts free-form lines
// from the monitor host so the Console mirrors stdout-style logger output.

using System;
using System.Collections.Generic;

namespace WhitehatSecurity.Core;

public sealed class ConsoleSink : IAlertSink
{
    private readonly object _lock = new();
    private readonly Queue<string> _lines = new();
    private const int MaxLines = 2000;

    public event Action<string>? LineAppended;

    /// <summary>
    /// Number of lines that were silently evicted because the ring buffer
    /// was full. Surfaced on the Console page so the user can tell when
    /// log volume has exceeded the buffer's display window.
    /// </summary>
    public int LinesDropped { get; private set; }

    public void WriteLine(string line)
    {
        var stamp = $"[{DateTime.Now:HH:mm:ss}] {line}";
        lock (_lock)
        {
            _lines.Enqueue(stamp);
            while (_lines.Count > MaxLines)
            {
                _lines.Dequeue();
                LinesDropped++;
            }
        }
        try { LineAppended?.Invoke(stamp); } catch { }
    }

    public void Receive(Alert alert)
    {
        WriteLine($"[{alert.Severity.ToString().ToUpperInvariant()}] {alert.Category} - {alert.Title}: {alert.Message}");
    }

    public IReadOnlyCollection<string> Snapshot()
    {
        lock (_lock) return _lines.ToArray();
    }
}
