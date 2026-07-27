// SPDX-License-Identifier: MIT
// New listening port detection. Mirrors the listener block in the PS port
// (~line 5950).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using WhitehatSecurity.Core;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Engines;

public sealed class ListenerEngine : IMonitorEngine
{
    public string Name => "Listeners";

    private readonly HashSet<string> _known = new();
    private readonly Queue<string> _knownOrder = new();
    private const int MaxKnown = 10_000;

    public void Initialize()
    {
        foreach (var l in EnumerateListeners())
            AddKnown(Key(l));
    }

    public IEnumerable<Alert> Scan()
    {
        foreach (var l in EnumerateListeners())
        {
            var key = Key(l);
            if (AddKnown(key))
            {
                yield return new Alert(
                    Timestamp:   DateTime.Now,
                    Category:    "Listener",
                    Title:       "NEW LISTENER",
                    Message:     $"{l.ProcessName ?? "?"} listening on {l.LocalIp}:{l.LocalPort}",
                    Severity:    AlertSeverity.Med,
                    ProcessName: l.ProcessName,
                    ProcessId:   l.Pid,
                    RemoteIp:    l.LocalIp,
                    RemotePort:  l.LocalPort);
            }
        }
    }

    private bool AddKnown(string key)
    {
        if (!_known.Add(key)) return false;
        _knownOrder.Enqueue(key);
        while (_knownOrder.Count > MaxKnown)
            _known.Remove(_knownOrder.Dequeue());
        return true;
    }

    private readonly record struct ListenerRecord(
        string  LocalIp,
        int     LocalPort,
        int     Pid,
        string? ProcessName);

    private static string Key(ListenerRecord r) => $"{r.LocalIp}:{r.LocalPort}|{r.Pid}";

    /// <summary>
    /// Listening sockets in both address families. Until v7.4.8 only AF_INET
    /// was queried, which missed every IPv6 listener — and because a
    /// dual-stack socket bound to :: appears only in the IPv6 table, that
    /// included most services that accept connections from the network.
    /// </summary>
    private static IEnumerable<ListenerRecord> EnumerateListeners()
    {
        foreach (var row in TcpTable.Query(TcpTableClass.OwnerPidListener))
        {
            // Loopback-only listeners are never remotely reachable. A
            // listener on 0.0.0.0 or :: is, so those are kept.
            if (IPAddress.IsLoopback(row.LocalAddress)) continue;

            yield return new ListenerRecord(
                LocalIp:     row.LocalAddress.ToString(),
                LocalPort:   row.LocalPort,
                Pid:         row.Pid,
                ProcessName: SafeProcessName(row.Pid));
        }
    }

    private static string? SafeProcessName(int pid)
    {
        // `using` releases the kernel handle Process.GetProcessById opens.
        // Same handle leak class as ConnectionEngine.SafeProcessName.
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch { return null; }
    }
}
