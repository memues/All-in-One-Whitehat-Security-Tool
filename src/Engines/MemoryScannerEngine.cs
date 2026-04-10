// SPDX-License-Identifier: MIT
// Walks the virtual address space of every running process looking for
// MEM_COMMIT + MEM_PRIVATE regions with a PAGE_EXECUTE_READWRITE (or
// PAGE_EXECUTE_WRITECOPY) protection. Read-write-execute private memory is
// the canonical fingerprint of injected shellcode — legitimate code lives
// in MEM_IMAGE regions whose backing store is the on-disk PE.
//
// JIT-heavy processes (browsers, .NET, Java, Node) generate RWX regions
// during normal operation, so we maintain an allowlist that mirrors the one
// the PowerShell port uses. The result of a clean scan on a normal desktop
// is therefore "0 alerts" rather than "spammed with browser noise".
//
// Reads are best-effort: many processes refuse to be opened with
// PROCESS_VM_READ as a non-elevated user, and that is fine — we silently
// skip them and move on.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using WhitehatSecurity.Core;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Engines;

public sealed class MemoryScannerEngine : IMonitorEngine
{
    public string Name => "Memory";

    /// <summary>
    /// Process names whose RWX regions are JIT bytecode. Skipping these
    /// matches the PowerShell port's behavior and is essential to keep
    /// scan output usable on a real desktop.
    /// </summary>
    private static readonly HashSet<string> JitAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "java",   "javaw",  "node",      "dotnet",
        "msedge", "chrome", "chromium",  "firefox",
        "brave",  "opera",  "vivaldi",   "WhitehatSecurity",
        "powershell", "pwsh", "code", "Code", "devenv",
    };

    /// <summary>PIDs we already alerted on (one alert per process per session).</summary>
    private readonly HashSet<int> _alerted = new();

    public void Initialize() { /* no baseline phase */ }

    public IEnumerable<Alert> Scan()
    {
        var alerts = new List<Alert>();

        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return alerts; }

        try
        {
            foreach (var p in procs)
            {
                if (p.Id <= 4) continue;
                if (JitAllowlist.Contains(p.ProcessName)) continue;
                if (_alerted.Contains(p.Id)) continue;

                if (TryGetSuspiciousRegion(p.Id, out var region))
                {
                    _alerted.Add(p.Id);
                    alerts.Add(new Alert(
                        Timestamp:   DateTime.Now,
                        Category:    "Memory",
                        Title:       "EXECUTABLE PRIVATE MEMORY",
                        Message:     $"{p.ProcessName} (PID {p.Id}) has RWX private memory at 0x{region:X}",
                        Severity:    AlertSeverity.Crit,
                        ProcessName: p.ProcessName,
                        ProcessId:   p.Id));
                }
            }
        }
        finally
        {
            foreach (var p in procs) p.Dispose();
        }

        return alerts;
    }

    /// <summary>
    /// Opens the target process for VM read access and walks every region
    /// with VirtualQueryEx. Returns true on the first MEM_COMMIT|MEM_PRIVATE
    /// region whose protection is execute-and-writable. Stops as soon as a
    /// hit is found — we only need one to alert.
    /// </summary>
    private static bool TryGetSuspiciousRegion(int pid, out IntPtr regionAddress)
    {
        regionAddress = IntPtr.Zero;
        IntPtr handle = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ,
            bInheritHandle: false,
            dwProcessId: pid);
        if (handle == IntPtr.Zero) return false;

        try
        {
            IntPtr addr = IntPtr.Zero;
            int mbiSize = Marshal.SizeOf<MemoryBasicInformation>();
            // Hard cap on the address space we walk so we never spin
            // forever on a corrupt page list.
            const long ceiling = 0x0000_7FFF_FFFE_0000L;

            while (addr.ToInt64() < ceiling)
            {
                int written = NativeMethods.VirtualQueryEx(handle, addr, out var mbi, (uint)mbiSize);
                if (written == 0) return false;

                if ((mbi.State == NativeMethods.MEM_COMMIT)
                 && (mbi.Type  == NativeMethods.MEM_PRIVATE))
                {
                    bool rwx = mbi.Protect == NativeMethods.PAGE_EXECUTE_READWRITE
                            || mbi.Protect == NativeMethods.PAGE_EXECUTE_WRITECOPY;
                    if (rwx)
                    {
                        regionAddress = mbi.BaseAddress;
                        return true;
                    }
                }

                long nextAddr = addr.ToInt64() + mbi.RegionSize.ToInt64();
                if (nextAddr <= addr.ToInt64()) return false;
                addr = new IntPtr(nextAddr);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }

        return false;
    }
}
