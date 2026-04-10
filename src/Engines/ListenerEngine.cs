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

    public void Initialize()
    {
        foreach (var l in EnumerateListeners())
            _known.Add(Key(l));
    }

    public IEnumerable<Alert> Scan()
    {
        foreach (var l in EnumerateListeners())
        {
            var key = Key(l);
            if (_known.Add(key))
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

    private readonly record struct ListenerRecord(
        string  LocalIp,
        int     LocalPort,
        int     Pid,
        string? ProcessName);

    private static string Key(ListenerRecord r) => $"{r.LocalIp}:{r.LocalPort}|{r.Pid}";

    private static IEnumerable<ListenerRecord> EnumerateListeners()
    {
        int size = 0;
        NativeMethods.GetExtendedTcpTable(
            IntPtr.Zero, ref size, false,
            NativeMethods.AF_INET,
            TcpTableClass.OwnerPidListener, 0);

        if (size <= 0) yield break;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint rc = NativeMethods.GetExtendedTcpTable(
                buffer, ref size, false,
                NativeMethods.AF_INET,
                TcpTableClass.OwnerPidListener, 0);

            if (rc != 0) yield break;

            int rowCount = Marshal.ReadInt32(buffer);
            int rowSize  = Marshal.SizeOf<MibTcpRowOwnerPid>();
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                rowPtr  = IntPtr.Add(rowPtr, rowSize);

                var local = new IPAddress(BitConverter.GetBytes(row.LocalAddr)).ToString();
                // Skip loopback-only listeners — they're never remotely reachable
                if (local.StartsWith("127.") || local == "::1") continue;

                int port = ((int)((row.LocalPort & 0xFF) << 8))
                         |  (int)((row.LocalPort & 0xFF00) >> 8);

                yield return new ListenerRecord(
                    LocalIp:     local,
                    LocalPort:   port,
                    Pid:         (int)row.OwningPid,
                    ProcessName: SafeProcessName((int)row.OwningPid));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string? SafeProcessName(int pid)
    {
        try { return Process.GetProcessById(pid).ProcessName; }
        catch { return null; }
    }
}
