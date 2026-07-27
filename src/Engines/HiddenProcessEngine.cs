// SPDX-License-Identifier: MIT
// Cross-references the kernel-side process list (NtQuerySystemInformation
// SystemProcessInformation, class 5) against the user-mode list returned by
// Process.GetProcesses(). Any PID that appears in only one of the two views
// is reported as a "hidden process" — a strong rootkit indicator.
//
// This is a defensive scanner only: it does not modify any process state,
// it only reads the system process list. The P/Invoke surface lives in
// NativeMethods.cs and is shared with future analysis engines.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using WhitehatSecurity.Core;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Engines;

public sealed class HiddenProcessEngine : IMonitorEngine
{
    public string Name => "HiddenProcess";

    /// <summary>
    /// Tracks PIDs we have already alerted on so we don't fire repeatedly
    /// for the same hidden process every scan cycle.
    /// </summary>
    private readonly HashSet<int> _alerted = new();
    private readonly HashSet<int> _pending = new();

    public void Initialize()
    {
        // No baseline phase — every scan compares the two live views.
    }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();

        var kernel = QueryKernelPids();
        if (kernel.Count == 0) return alerts;   // probe failed; bail quietly

        HashSet<int> userMode;
        try
        {
            var procs = Process.GetProcesses();
            try
            {
                userMode = procs.Select(p => p.Id).ToHashSet();
            }
            finally
            {
                foreach (var p in procs) p.Dispose();
            }
        }
        catch
        {
            return alerts;
        }

        var mismatches = kernel
            .Where(pid => pid > 4 && !userMode.Contains(pid))
            .ToHashSet();
        _alerted.IntersectWith(mismatches);
        _pending.IntersectWith(mismatches);

        // A mismatch must persist for two scans. Process exit races between
        // the kernel and user-mode snapshots otherwise create false alarms.
        foreach (var pid in mismatches)
        {
            if (_pending.Add(pid)) continue;
            if (!_alerted.Add(pid)) continue;

            alerts.Add(new Alert(
                Timestamp: DateTime.Now,
                Category:  "HiddenProcess",
                Title:     "HIDDEN PROCESS",
                Message:   $"PID {pid} is in the kernel process list but not visible to user mode",
                Severity:  AlertSeverity.High,
                ProcessId: pid));
        }

        return alerts;
    }

    /// <summary>
    /// Allocates a buffer for SystemProcessInformation, walks the linked list
    /// of SYSTEM_PROCESS_INFORMATION records, and returns the kernel-visible
    /// PID set. Returns an empty set on any error so callers can bail safely.
    /// </summary>
    private static HashSet<int> QueryKernelPids()
    {
        var pids = new HashSet<int>();
        const int statusInfoLengthMismatch = unchecked((int)0xC0000004);

        int bufferSize = 64 * 1024;
        IntPtr buffer  = IntPtr.Zero;

        try
        {
            for (int attempt = 0; attempt < 6; attempt++)
            {
                buffer = Marshal.AllocHGlobal(bufferSize);
                int rc = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SystemProcessInformation,
                    buffer,
                    bufferSize,
                    out int returnLength);

                if (rc == 0)
                {
                    WalkProcessList(buffer, pids);
                    return pids;
                }

                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                if (rc == statusInfoLengthMismatch)
                {
                    // Grow the buffer and try again. NtQuerySystemInformation
                    // races against new processes appearing, so we may need a
                    // few attempts on a busy system.
                    bufferSize = Math.Max(returnLength + 16 * 1024, bufferSize * 2);
                    continue;
                }

                return pids;   // unexpected status — bail without alerting
            }
        }
        catch
        {
            // any failure → return whatever we collected so the engine
            // never crashes the monitor host
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }

        return pids;
    }

    /// <summary>
    /// SYSTEM_PROCESS_INFORMATION layout (Windows 10+):
    ///   ULONG NextEntryOffset
    ///   ULONG NumberOfThreads
    ///   LARGE_INTEGER Reserved[3]    // 24 bytes
    ///   LARGE_INTEGER CreateTime
    ///   LARGE_INTEGER UserTime
    ///   LARGE_INTEGER KernelTime
    ///   UNICODE_STRING ImageName     // 16 bytes (Length + MaximumLength + Pointer)
    ///   ULONG BasePriority           // 4 bytes
    ///   HANDLE UniqueProcessId       // 8 bytes (the PID we want)
    ///   ...
    /// On x64, UniqueProcessId sits at offset 0x50 (80) from the start of
    /// each record after accounting for natural alignment.
    /// </summary>
    private static void WalkProcessList(IntPtr buffer, HashSet<int> pids)
    {
        IntPtr cursor = buffer;
        while (true)
        {
            int nextOffset = Marshal.ReadInt32(cursor, 0);
            // PID is at offset 0x50 on x64 builds
            IntPtr pidPtr = Marshal.ReadIntPtr(cursor, 0x50);
            int pid = pidPtr.ToInt32();
            if (pid >= 0) pids.Add(pid);

            if (nextOffset == 0) break;
            cursor = IntPtr.Add(cursor, nextOffset);
        }
    }
}
