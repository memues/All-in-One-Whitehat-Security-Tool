// SPDX-License-Identifier: MIT
// Outbound TCP connection tracker. Replaces the Get-NetTCPConnection-based
// section of SecurityMonitor.ps1 (~line 6730 / line 5935). Uses iphlpapi
// GetExtendedTcpTable directly so the dependency on PowerShell cmdlets is
// gone — same data, ~10x faster, single allocation per scan.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using WhitehatSecurity.Core;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Engines;

public sealed class ConnectionEngine : IMonitorEngine
{
    public string Name => "Connections";

    /// <summary>
    /// Hard cap on the number of distinct connection keys we remember. On
    /// a server with high churn this set could otherwise grow to hundreds
    /// of MB over a few weeks. When the cap is reached we evict the
    /// oldest entries via the FIFO order tracked in _knownOrder.
    /// </summary>
    private const int MaxKnown = 10_000;

    /// <summary>"remoteIP|remotePort|pid" keys already observed.</summary>
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>FIFO insertion order, parallel to _known, for cheap eviction.</summary>
    private readonly Queue<string>   _knownOrder = new();

    public void Initialize()
    {
        foreach (var conn in EnumerateConnections())
            AddKnown(Key(conn));
    }

    public IEnumerable<Alert> Scan()
    {
        foreach (var conn in EnumerateConnections())
        {
            var key = Key(conn);
            if (AddKnown(key))
            {
                yield return new Alert(
                    Timestamp:   DateTime.Now,
                    Category:    "Connection",
                    Title:       "UNKNOWN CONNECTION",
                    Message:     $"{conn.ProcessName ?? "?"} -> {conn.RemoteIp}:{conn.RemotePort}",
                    Severity:    AlertSeverity.High,
                    ProcessName: conn.ProcessName,
                    ProcessId:   conn.Pid,
                    RemoteIp:    conn.RemoteIp,
                    RemotePort:  conn.RemotePort);
            }
        }
    }

    /// <summary>
    /// Add a key to the known set. Returns true if it was new (i.e. the
    /// caller should raise an alert). Evicts the oldest entry when the
    /// set hits MaxKnown so memory stays bounded.
    /// </summary>
    private bool AddKnown(string key)
    {
        if (!_known.Add(key)) return false;
        _knownOrder.Enqueue(key);
        while (_knownOrder.Count > MaxKnown)
        {
            var stale = _knownOrder.Dequeue();
            _known.Remove(stale);
        }
        return true;
    }

    // ------------------------------------------------------------------------
    // GetExtendedTcpTable enumeration
    // ------------------------------------------------------------------------

    private readonly record struct ConnectionRecord(
        string  RemoteIp,
        int     RemotePort,
        int     Pid,
        string? ProcessName);

    private static string Key(ConnectionRecord c)
        => $"{c.RemoteIp}|{c.RemotePort}|{c.Pid}";

    /// <summary>
    /// Established outbound connections in both address families. Until
    /// v7.4.8 only AF_INET was queried, so anything talking over IPv6 —
    /// which on a dual-stack machine is most of it — never raised an alert.
    /// </summary>
    private static IEnumerable<ConnectionRecord> EnumerateConnections()
    {
        foreach (var row in TcpTable.Query(TcpTableClass.OwnerPidConnections))
        {
            if (row.State != MibTcpState.Established) continue;
            if (TcpTable.IsLocalOnly(row.RemoteAddress)) continue;

            yield return new ConnectionRecord(
                RemoteIp:    row.RemoteAddress.ToString(),
                RemotePort:  row.RemotePort,
                Pid:         row.Pid,
                ProcessName: SafeProcessName(row.Pid));
        }
    }

    private static string? SafeProcessName(int pid)
    {
        // Wrap in `using` so the kernel handle Process.GetProcessById opens
        // is released on every call. Without this, every TCP table scan
        // (every few seconds) leaked one process handle per connection,
        // which on a busy system exhausted the handle table within a day
        // and caused subsequent GetProcessById calls to fail with
        // "Access denied" or eventually OOM the host.
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch { return null; }
    }
}
