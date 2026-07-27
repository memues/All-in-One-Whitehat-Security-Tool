// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

/// <summary>
/// Monitors high-value Windows Security events. Access to the Security log is
/// best-effort because standard-user policies can deny it.
/// </summary>
public sealed class SecurityEventEngine : IMonitorEngine
{
    public string Name => "Security Events";

    private readonly HashSet<long> _seen = new();
    private readonly Queue<long> _seenOrder = new();
    private readonly Logger? _logger;
    private bool _available = true;
    private const int MaxSeen = 4096;

    /// <summary>
    /// Reading the Security log requires elevation or membership of the
    /// local "Event Log Readers" group. The application ships as asInvoker,
    /// so on a normal install this engine is inert — and it used to go inert
    /// in complete silence, leaving the Settings page advertising remote
    /// logon, failed logon and new-account detection that could never fire.
    /// </summary>
    public bool IsAvailable => _available;

    public SecurityEventEngine(Logger? logger = null) => _logger = logger;

    public void Initialize()
    {
        // The scan query below sets TolerateQueryErrors so that one bad
        // record cannot abort a whole read. That same flag turns an access
        // denial into a null record instead of an exception, which is
        // indistinguishable from "the log is empty" — so availability has to
        // be established with a strict probe first, or the engine concludes
        // it is working fine while reading nothing at all.
        if (!CanReadSecurityLog())
        {
            MarkUnavailable(
                "the Windows Security log cannot be read by this account");
            return;
        }

        try { ReadRecent(TimeSpan.FromMinutes(2), markOnly: true); }
        catch (Exception ex)
        {
            MarkUnavailable($"{ex.GetType().Name}: {ex.Message}");
        }
    }

    public IEnumerable<Alert> Scan()
    {
        if (!_available) return Array.Empty<Alert>();
        try
        {
            return ReadRecent(TimeSpan.FromSeconds(30), markOnly: false);
        }
        catch (Exception ex)
        {
            MarkUnavailable($"{ex.GetType().Name}: {ex.Message}");
            return Array.Empty<Alert>();
        }
    }

    private void MarkUnavailable(string reason)
    {
        if (!_available) return;
        _available = false;
        _logger?.Warn(
            $"Security event monitoring is OFF: {reason}. "
            + "Remote logons, failed logons and new local accounts will not "
            + "raise alerts. Run the program elevated, or add this account "
            + "to the local \"Event Log Readers\" group, to enable it.");
    }

    /// <summary>
    /// Strict readability probe, used by Initialize and by the Settings page.
    ///
    /// TolerateQueryErrors is deliberately off here. With it on, a denied
    /// read returns null rather than throwing, so this would answer "yes,
    /// readable" on every standard-user install.
    /// </summary>
    public static bool CanReadSecurityLog()
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName)
            {
                TolerateQueryErrors = false,
                ReverseDirection = true,
            };
            using var reader = new EventLogReader(query);
            reader.ReadEvent(TimeSpan.FromSeconds(2))?.Dispose();
            return true;
        }
        catch { return false; }
    }

    private List<Alert> ReadRecent(TimeSpan window, bool markOnly)
    {
        var milliseconds = Math.Max(1000, (long)window.TotalMilliseconds);
        var queryText =
            $"*[System[((EventID=4624 or EventID=4625 or EventID=4720) and TimeCreated[timediff(@SystemTime) <= {milliseconds}])]]";
        var query = new EventLogQuery(
            "Security", PathType.LogName, queryText)
        {
            TolerateQueryErrors = true,
            ReverseDirection = true,
        };

        var alerts = new List<Alert>();
        using var reader = new EventLogReader(query);
        var readCount = 0;
        while (readCount++ < 512 && reader.ReadEvent() is { } record)
        {
            using (record)
            {
                if (record.RecordId is not long recordId
                    || !Remember(recordId))
                    continue;
                if (markOnly) continue;

                var data = ParseEventData(record.ToXml());
                if (record.Id == 4624
                    && (!data.TryGetValue("LogonType", out var logonType)
                        || logonType != "10"))
                    continue;

                var (title, severity) = record.Id switch
                {
                    4624 => ("REMOTE INTERACTIVE LOGON", AlertSeverity.Med),
                    4625 => ("FAILED WINDOWS LOGON", AlertSeverity.Med),
                    4720 => ("LOCAL ACCOUNT CREATED", AlertSeverity.High),
                    _ => ("SECURITY EVENT", AlertSeverity.Info),
                };

                var extra = new Dictionary<string, string>();
                CopyIfPresent(data, extra, "TargetUserName", "Account");
                CopyIfPresent(data, extra, "IpAddress", "RemoteAddress");
                alerts.Add(new Alert(
                    record.TimeCreated ?? DateTime.Now,
                    "Security",
                    title,
                    $"Windows Security event {record.Id} was recorded.",
                    severity,
                    Extra: extra.Count == 0 ? null : extra));
            }
        }
        return alerts;
    }

    private bool Remember(long recordId)
    {
        if (!_seen.Add(recordId)) return false;
        _seenOrder.Enqueue(recordId);
        while (_seenOrder.Count > MaxSeen)
            _seen.Remove(_seenOrder.Dequeue());
        return true;
    }

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        try
        {
            return XDocument.Parse(xml)
                .Descendants()
                .Where(element =>
                    element.Name.LocalName == "Data"
                    && element.Attribute("Name") is not null)
                .GroupBy(element =>
                    element.Attribute("Name")!.Value)
                .ToDictionary(
                    group => group.Key,
                    group => group.Last().Value,
                    StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);
        }
    }

    private static void CopyIfPresent(
        Dictionary<string, string> source,
        Dictionary<string, string> destination,
        string sourceKey,
        string destinationKey)
    {
        if (source.TryGetValue(sourceKey, out var value)
            && !string.IsNullOrWhiteSpace(value)
            && value != "-")
            destination[destinationKey] = value;
    }
}
