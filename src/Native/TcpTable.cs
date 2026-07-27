// SPDX-License-Identifier: MIT
// Shared GetExtendedTcpTable reader covering BOTH address families.
//
// ConnectionEngine and ListenerEngine each used to carry their own copy of
// this P/Invoke dance, and both queried AF_INET only. Everything bound to an
// IPv6 socket was therefore invisible to the monitor — including every
// dual-stack service, because a socket bound to :: appears only in the IPv6
// table. For a tool whose job is to notice new listeners and unexpected
// outbound connections that was a large blind spot, so the enumeration lives
// here once and always asks for both families.

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace WhitehatSecurity.Native;

internal readonly record struct TcpEndpointRow(
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    MibTcpState State,
    int Pid);

internal static class TcpTable
{
    private const uint ErrorInsufficientBuffer = 122;

    /// <summary>
    /// Every row of the requested table, IPv4 first then IPv6. Returns an
    /// empty list rather than throwing when a family is unavailable, so a
    /// machine with IPv6 disabled still gets its IPv4 rows.
    /// </summary>
    internal static List<TcpEndpointRow> Query(TcpTableClass tableClass)
    {
        var rows = new List<TcpEndpointRow>();
        QueryFamily(rows, NativeMethods.AF_INET, tableClass);
        QueryFamily(rows, NativeMethods.AF_INET6, tableClass);
        return rows;
    }

    private static void QueryFamily(
        List<TcpEndpointRow> rows,
        int family,
        TcpTableClass tableClass)
    {
        int size = 0;
        var sizeRc = NativeMethods.GetExtendedTcpTable(
            IntPtr.Zero, ref size, false, family, tableClass, 0);
        if (sizeRc is not (0 or ErrorInsufficientBuffer)) return;
        if (size <= 0) return;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var rc = NativeMethods.GetExtendedTcpTable(
                buffer, ref size, false, family, tableClass, 0);
            if (rc != 0) return;

            var count = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = family == NativeMethods.AF_INET6
                ? Marshal.SizeOf<MibTcp6RowOwnerPid>()
                : Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (var i = 0; i < count; i++)
            {
                rows.Add(family == NativeMethods.AF_INET6
                    ? ReadIpv6Row(rowPtr)
                    : ReadIpv4Row(rowPtr));
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static TcpEndpointRow ReadIpv4Row(IntPtr rowPtr)
    {
        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
        return new TcpEndpointRow(
            new IPAddress(BitConverter.GetBytes(row.LocalAddr)),
            NetworkOrderPort(row.LocalPort),
            new IPAddress(BitConverter.GetBytes(row.RemoteAddr)),
            NetworkOrderPort(row.RemotePort),
            (MibTcpState)row.State,
            (int)row.OwningPid);
    }

    private static TcpEndpointRow ReadIpv6Row(IntPtr rowPtr)
    {
        var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
        // The scope id matters for link-local addresses: without it two
        // different interfaces' fe80:: sockets would collapse to one key.
        return new TcpEndpointRow(
            Normalize(new IPAddress(row.LocalAddr, row.LocalScopeId)),
            NetworkOrderPort(row.LocalPort),
            Normalize(new IPAddress(row.RemoteAddr, row.RemoteScopeId)),
            NetworkOrderPort(row.RemotePort),
            (MibTcpState)row.State,
            (int)row.OwningPid);
    }

    /// <summary>
    /// Collapses IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) to plain IPv4.
    /// A dual-stack socket talking to an IPv4 peer can surface in either
    /// table, so without this the same connection could be alerted twice
    /// under two spellings, and the alert would show the ::ffff: form the
    /// user cannot match against anything else on their machine.
    /// </summary>
    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>
    /// The table stores ports in network byte order in the low 16 bits.
    /// </summary>
    private static int NetworkOrderPort(uint raw) =>
        (int)((raw & 0xFF) << 8) | (int)((raw & 0xFF00) >> 8);

    /// <summary>
    /// True for addresses that can never represent a remotely reachable
    /// peer: loopback in either family, and the unspecified address.
    /// </summary>
    internal static bool IsLocalOnly(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return true;
        return address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any);
    }
}
