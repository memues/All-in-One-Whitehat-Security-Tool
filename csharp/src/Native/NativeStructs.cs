// SPDX-License-Identifier: MIT
// Native structure layouts used by NativeMethods.

using System;
using System.Runtime.InteropServices;

namespace WhitehatSecurity.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct MemoryBasicInformation
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint   AllocationProtect;
    public IntPtr RegionSize;
    public uint   State;
    public uint   Protect;
    public uint   Type;
}

internal enum TcpTableClass
{
    BasicListener,
    BasicConnections,
    BasicAll,
    OwnerPidListener,
    OwnerPidConnections,
    OwnerPidAll,
    OwnerModuleListener,
    OwnerModuleConnections,
    OwnerModuleAll,
}

internal enum UdpTableClass
{
    Basic,
    OwnerPid,
    OwnerModule,
}

[StructLayout(LayoutKind.Sequential)]
internal struct MibTcpRowOwnerPid
{
    public uint State;
    public uint LocalAddr;
    public uint LocalPort;     // big-endian, only low 16 bits valid
    public uint RemoteAddr;
    public uint RemotePort;    // big-endian, only low 16 bits valid
    public uint OwningPid;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MibTcp6RowOwnerPid
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] LocalAddr;
    public uint   LocalScopeId;
    public uint   LocalPort;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] RemoteAddr;
    public uint   RemoteScopeId;
    public uint   RemotePort;
    public uint   State;
    public uint   OwningPid;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MibTcpTableOwnerPid
{
    public uint dwNumEntries;
    // entries follow inline; we read them via pointer arithmetic in the engine
}

internal enum MibTcpState : uint
{
    Closed     = 1,
    Listen     = 2,
    SynSent    = 3,
    SynRcvd    = 4,
    Established = 5,
    FinWait1   = 6,
    FinWait2   = 7,
    CloseWait  = 8,
    Closing    = 9,
    LastAck    = 10,
    TimeWait   = 11,
    DeleteTcb  = 12,
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
internal struct NotifyIconData
{
    public int    cbSize;
    public IntPtr hWnd;
    public uint   uID;
    public uint   uFlags;
    public uint   uCallbackMessage;
    public IntPtr hIcon;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string szTip;
    public uint   dwState;
    public uint   dwStateMask;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string szInfo;
    public uint   uTimeoutOrVersion;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string szInfoTitle;
    public uint   dwInfoFlags;
    public Guid   guidItem;
    public IntPtr hBalloonIcon;
}
