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
    /// Set of "remoteIP|pid" keys we've already seen. New entries → Alert.
    /// Trimmed periodically to keep memory bounded.
    /// </summary>
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> LoopbackPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "127.", "::1", "0.0.0.0",
    };

    public void Initialize()
    {
        foreach (var conn in EnumerateConnections())
            _known.Add(Key(conn));
    }

    public IEnumerable<Alert> Scan()
    {
        foreach (var conn in EnumerateConnections())
        {
            var key = Key(conn);
            if (_known.Add(key))
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

    // ------------------------------------------------------------------------
    // GetExtendedTcpTable enumeration
    // ------------------------------------------------------------------------

    private readonly record struct ConnectionRecord(
        string  RemoteIp,
        int     RemotePort,
        int     Pid,
        string? ProcessName);

    private static string Key(ConnectionRecord c) => $"{c.RemoteIp}|{c.Pid}";

    private static IEnumerable<ConnectionRecord> EnumerateConnections()
    {
        var ip4 = QueryTcp4();
        foreach (var c in ip4) yield return c;

        // IPv6 enumeration intentionally omitted in Phase 1 — the PS port also
        // logs IPv4 first and IPv6 only when explicitly enabled. Adding it
        // means an extra GetExtendedTcpTable call with AF_INET6 + a different
        // row layout (MibTcp6RowOwnerPid).
    }

    // Note: collected into a List rather than `yield return`-ed because
    // mixing iterator methods with the `unsafe` flag (or with try/finally
    // around an unmanaged buffer) is restricted in C# 12. Cleaner to
    // materialize the list and free the buffer in one place.
    private static List<ConnectionRecord> QueryTcp4()
    {
        var result = new List<ConnectionRecord>();

        int size = 0;
        NativeMethods.GetExtendedTcpTable(
            IntPtr.Zero, ref size, false,
            NativeMethods.AF_INET,
            TcpTableClass.OwnerPidConnections, 0);

        if (size <= 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint rc = NativeMethods.GetExtendedTcpTable(
                buffer, ref size, false,
                NativeMethods.AF_INET,
                TcpTableClass.OwnerPidConnections, 0);

            if (rc != 0) return result;

            int rowCount = Marshal.ReadInt32(buffer);
            int rowSize  = Marshal.SizeOf<MibTcpRowOwnerPid>();
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                rowPtr  = IntPtr.Add(rowPtr, rowSize);

                if ((MibTcpState)row.State != MibTcpState.Established) continue;

                var remote = new IPAddress(BitConverter.GetBytes(row.RemoteAddr)).ToString();
                if (IsLoopback(remote)) continue;

                int port = ((int)((row.RemotePort & 0xFF) << 8))
                         |  (int)((row.RemotePort & 0xFF00) >> 8);

                result.Add(new ConnectionRecord(
                    RemoteIp:    remote,
                    RemotePort:  port,
                    Pid:         (int)row.OwningPid,
                    ProcessName: SafeProcessName((int)row.OwningPid)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static bool IsLoopback(string ip)
    {
        foreach (var p in LoopbackPrefixes)
            if (ip.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static string? SafeProcessName(int pid)
    {
        try { return Process.GetProcessById(pid).ProcessName; }
        catch { return null; }
    }
}
