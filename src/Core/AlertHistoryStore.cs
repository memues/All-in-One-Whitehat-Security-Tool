// SPDX-License-Identifier: MIT
// Durable alert history.
//
// The dashboard's Alerts page is fed from DashboardSink, whose buffer lives
// only in memory. Everything raised before the process restarted was
// therefore gone the moment the tray app was restarted — the alerts were in
// alerts-YYYY-MM-DD.log, but the page the user actually looks at came up
// empty. That made the program look like it had stopped detecting anything.
//
// Alerts are appended here as JSON lines and replayed into the sink at
// startup, so the Alerts page shows real history across restarts, upgrades
// and reboots. The remediation payloads in Extra are preserved too, so an
// "Undo registry change" is still available after a restart.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WhitehatSecurity.Core;

public sealed class AlertHistoryStore
{
    /// <summary>
    /// Upper bound on retained records. The file is trimmed to this on load,
    /// which keeps it bounded without needing a background compaction pass.
    /// </summary>
    public const int MaxRetained = 2000;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _path;
    private readonly object _lock = new();

    public AlertHistoryStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    public string Path => _path;

    /// <summary>
    /// Reads the most recent <paramref name="max"/> alerts, oldest first.
    /// A malformed line is skipped rather than failing the whole load: a
    /// truncated final record after a hard power-off must not cost the user
    /// their entire history.
    /// </summary>
    public IReadOnlyList<Alert> Load(int max = MaxRetained)
    {
        if (max <= 0) return Array.Empty<Alert>();
        lock (_lock)
        {
            if (!File.Exists(_path)) return Array.Empty<Alert>();

            string[] lines;
            try { lines = File.ReadAllLines(_path); }
            catch { return Array.Empty<Alert>(); }

            var records = new List<Alert>(Math.Min(max, lines.Length));
            foreach (var line in lines.Length > max
                         ? lines[^max..]
                         : lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var dto = JsonSerializer.Deserialize<AlertRecord>(
                        line, JsonOpts);
                    if (dto is not null) records.Add(dto.ToAlert());
                }
                catch { /* skip the damaged record, keep the rest */ }
            }

            // Trim the file back to the retained window while we are here.
            if (lines.Length > MaxRetained)
            {
                try { File.WriteAllLines(_path, lines[^MaxRetained..]); }
                catch { /* trimming is best-effort */ }
            }

            return records;
        }
    }

    public void Append(Alert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        lock (_lock)
        {
            try
            {
                var directory = System.IO.Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);
                File.AppendAllText(
                    _path,
                    JsonSerializer.Serialize(
                        AlertRecord.From(alert), JsonOpts)
                    + Environment.NewLine);
            }
            catch { /* history is a convenience, never break the scan loop */ }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            try { File.Delete(_path); } catch { }
        }
    }

    /// <summary>
    /// On-disk shape. Kept separate from <see cref="Alert"/> so changing the
    /// in-memory record cannot silently invalidate saved history.
    /// </summary>
    private sealed class AlertRecord
    {
        public DateTime Timestamp { get; set; }
        public string Category { get; set; } = "";
        public string Title { get; set; } = "";
        public string Message { get; set; } = "";
        public string Severity { get; set; } = nameof(AlertSeverity.Info);
        public string? ProcessName { get; set; }
        public int? ProcessId { get; set; }
        public string? RemoteIp { get; set; }
        public int? RemotePort { get; set; }
        public string? FilePath { get; set; }
        public Dictionary<string, string>? Extra { get; set; }

        public static AlertRecord From(Alert alert) => new()
        {
            Timestamp = alert.Timestamp,
            Category = alert.Category,
            Title = alert.Title,
            Message = alert.Message,
            Severity = alert.Severity.ToString(),
            ProcessName = alert.ProcessName,
            ProcessId = alert.ProcessId,
            RemoteIp = alert.RemoteIp,
            RemotePort = alert.RemotePort,
            FilePath = alert.Path,
            Extra = alert.Extra is null
                ? null
                : new Dictionary<string, string>(alert.Extra),
        };

        public Alert ToAlert() => new(
            Timestamp,
            Category,
            Title,
            Message,
            Enum.TryParse<AlertSeverity>(Severity, out var severity)
                ? severity
                : AlertSeverity.Info,
            ProcessName,
            ProcessId,
            RemoteIp,
            RemotePort,
            FilePath,
            Extra is null
                ? null
                : new Dictionary<string, string>(Extra));
    }
}

/// <summary>
/// Sink that persists every dispatched alert. Registered alongside the
/// dashboard and toast sinks so history is written whether or not the
/// dashboard window happens to be open.
/// </summary>
public sealed class AlertHistorySink : IAlertSink
{
    private readonly AlertHistoryStore _store;

    public AlertHistorySink(AlertHistoryStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    public void Receive(Alert alert) => _store.Append(alert);
}
