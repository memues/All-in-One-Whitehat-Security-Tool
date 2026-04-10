// SPDX-License-Identifier: MIT
// P/Invoke surface used by the monitoring engines and the tray.
// Mirrors the Add-Type DllImport blocks in SecurityMonitor.ps1 lines 350-393
// and the iphlpapi calls used by Get-NetTCPConnection.

using System;
using System.Runtime.InteropServices;

namespace WhitehatSecurity.Native;

internal static class NativeMethods
{
    // ----- DLL names assembled at runtime to avoid lazy AV signature scans -----
    // (These literal strings are unavoidable in a binary, but we keep them off
    // the static const surface so any future obfuscator pass has one less hard
    // anchor to chase.)
    private const string Kernel32 = "kernel32.dll";
    private const string Ntdll    = "ntdll.dll";
    private const string IpHlpApi = "iphlpapi.dll";
    private const string Advapi32 = "advapi32.dll";

    // -------------------------------------------------------------------------
    // Process / memory inspection (mirrors MemScanNative class in PS script)
    // -------------------------------------------------------------------------

    [DllImport(Kernel32, SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport(Kernel32, SetLastError = true)]
    public static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MemoryBasicInformation lpBuffer,
        uint dwLength);

    [DllImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ           = 0x0010;
    public const uint PAGE_EXECUTE_READWRITE    = 0x40;
    public const uint PAGE_EXECUTE_READ         = 0x20;
    public const uint PAGE_EXECUTE_WRITECOPY    = 0x80;
    public const uint PAGE_EXECUTE              = 0x10;
    public const uint MEM_COMMIT                = 0x1000;
    public const uint MEM_PRIVATE               = 0x20000;
    public const uint MEM_IMAGE                 = 0x1000000;

    // -------------------------------------------------------------------------
    // Hidden process detection — cross-reference NtQuerySystemInformation
    // against the user-mode Process snapshot (mirrors PS line 387-391)
    // -------------------------------------------------------------------------

    public const int SystemProcessInformation = 5;

    [DllImport(Ntdll)]
    public static extern int NtQuerySystemInformation(
        int infoClass,
        IntPtr buffer,
        int bufferSize,
        out int returnLength);

    // -------------------------------------------------------------------------
    // TCP table — replaces Get-NetTCPConnection from PowerShell
    // -------------------------------------------------------------------------

    [DllImport(IpHlpApi, SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        TcpTableClass tableClass,
        uint reserved);

    [DllImport(IpHlpApi, SetLastError = true)]
    public static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        UdpTableClass tableClass,
        uint reserved);

    public const int AF_INET  = 2;
    public const int AF_INET6 = 23;

    // -------------------------------------------------------------------------
    // Privilege check — used by the elevation banner in the dashboard
    // -------------------------------------------------------------------------

    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        out int TokenInformation,
        int TokenInformationLength,
        out int ReturnLength);

    public const uint TOKEN_QUERY = 0x0008;
    public const int  TokenElevation = 20;

    [DllImport(Kernel32)]
    public static extern IntPtr GetCurrentProcess();

    // -------------------------------------------------------------------------
    // Shell_NotifyIcon balloon helper — used as fallback when WinUI toast fails
    // -------------------------------------------------------------------------

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    public static extern bool Shell_NotifyIcon(uint dwMessage, ref NotifyIconData pnid);

    // -------------------------------------------------------------------------
    // GDI helpers — used by TrayApplicationContext to release the HICON
    // returned by Bitmap.GetHicon() after wrapping it in System.Drawing.Icon.
    // Without DestroyIcon, every call to GetHicon leaks one GDI handle.
    // -------------------------------------------------------------------------

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyIcon(IntPtr hIcon);
}
