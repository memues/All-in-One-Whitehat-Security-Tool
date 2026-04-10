// SPDX-License-Identifier: MIT
// Reads the eight security posture indicators that the Status page shows
// (Defender / Firewall / UAC / RDP / SecureBoot / TPM / HVCI / BitLocker).
// Each query is independent and wrapped in try/catch — the dashboard never
// crashes because a posture probe failed; the worst case is that one dot
// stays Unknown.

using System;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;

namespace WhitehatSecurity.Core;

public enum PostureState
{
    Unknown,   // probe failed (treated as gray)
    Good,      // protection is on / posture is healthy
    Bad,       // protection is off
    NA,        // hardware feature not present (e.g. TPM on a VM without one)
}

public static class SecurityPosture
{
    // ----------------------------------------------------------------------
    //  Defender
    // ----------------------------------------------------------------------
    public static PostureState Defender()
    {
        try
        {
            // First-pass: WMI SecurityCenter2 product registration is the
            // canonical "is some real-time AV running" answer. Includes
            // third-party AVs registered as the active product.
            using var searcher = new ManagementObjectSearcher(
                @"root\SecurityCenter2",
                "SELECT productState FROM AntiVirusProduct");
            foreach (ManagementObject mo in searcher.Get())
            {
                // productState bit layout: bit 12 (=0x1000) = enabled
                if (int.TryParse(mo["productState"]?.ToString(), out int state))
                {
                    if ((state & 0x1000) != 0) return PostureState.Good;
                }
            }
        }
        catch { }

        // Fallback: WinDefend service start type
        try
        {
            using var sc = new ServiceController("WinDefend");
            return sc.Status == ServiceControllerStatus.Running
                ? PostureState.Good
                : PostureState.Bad;
        }
        catch { return PostureState.Unknown; }
    }

    // ----------------------------------------------------------------------
    //  Firewall
    // ----------------------------------------------------------------------
    public static PostureState Firewall()
    {
        try
        {
            // mpssvc is the Windows Firewall service. If it is running, the
            // firewall is at least administratively present. We further check
            // SecurityCenter2 for the registered product state.
            using var searcher = new ManagementObjectSearcher(
                @"root\SecurityCenter2",
                "SELECT productState FROM FirewallProduct");
            foreach (ManagementObject mo in searcher.Get())
            {
                if (int.TryParse(mo["productState"]?.ToString(), out int state))
                {
                    if ((state & 0x1000) != 0) return PostureState.Good;
                }
            }
        }
        catch { }

        try
        {
            using var sc = new ServiceController("mpssvc");
            return sc.Status == ServiceControllerStatus.Running
                ? PostureState.Good
                : PostureState.Bad;
        }
        catch { return PostureState.Unknown; }
    }

    // ----------------------------------------------------------------------
    //  UAC
    // ----------------------------------------------------------------------
    public static PostureState UAC()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key?.GetValue("EnableLUA") is int luaValue)
                return luaValue == 1 ? PostureState.Good : PostureState.Bad;
        }
        catch { }
        return PostureState.Unknown;
    }

    // ----------------------------------------------------------------------
    //  RDP — "Good" means RDP is OFF (the inverse of the others). The
    //  posture row label says "RDP off" so a green dot = the posture row
    //  expectation is met = RDP is disabled.
    // ----------------------------------------------------------------------
    public static PostureState RdpOff()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server");
            if (key?.GetValue("fDenyTSConnections") is int deny)
                return deny == 1 ? PostureState.Good : PostureState.Bad;
        }
        catch { }
        return PostureState.Unknown;
    }

    // ----------------------------------------------------------------------
    //  Secure Boot
    // ----------------------------------------------------------------------
    public static PostureState SecureBoot()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key?.GetValue("UEFISecureBootEnabled") is int sb)
                return sb == 1 ? PostureState.Good : PostureState.Bad;
        }
        catch { }
        return PostureState.Unknown;
    }

    // ----------------------------------------------------------------------
    //  TPM
    // ----------------------------------------------------------------------
    public static PostureState Tpm()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftTpm",
                "SELECT IsActivated_InitialValue, IsEnabled_InitialValue FROM Win32_Tpm");
            foreach (ManagementObject mo in searcher.Get())
            {
                bool activated = mo["IsActivated_InitialValue"] is bool a && a;
                bool enabled   = mo["IsEnabled_InitialValue"]   is bool e && e;
                return (activated && enabled) ? PostureState.Good : PostureState.Bad;
            }
            return PostureState.NA;     // no TPM at all
        }
        catch { return PostureState.Unknown; }
    }

    // ----------------------------------------------------------------------
    //  HVCI (Hypervisor-protected Code Integrity)
    // ----------------------------------------------------------------------
    public static PostureState Hvci()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\DeviceGuard",
                "SELECT SecurityServicesRunning FROM Win32_DeviceGuard");
            foreach (ManagementObject mo in searcher.Get())
            {
                if (mo["SecurityServicesRunning"] is uint[] running)
                    return running.Contains((uint)2) ? PostureState.Good : PostureState.Bad;
                // Newer builds return int[] instead of uint[]; try both.
                if (mo["SecurityServicesRunning"] is int[] runningInt)
                    return runningInt.Contains(2) ? PostureState.Good : PostureState.Bad;
            }
        }
        catch { }
        return PostureState.Unknown;
    }

    // ----------------------------------------------------------------------
    //  BitLocker on the system volume
    // ----------------------------------------------------------------------
    public static PostureState BitLocker()
    {
        try
        {
            string sysDrive = Environment.GetFolderPath(Environment.SpecialFolder.System)
                .Substring(0, 2);   // "C:"
            using var searcher = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='{sysDrive}'");
            foreach (ManagementObject mo in searcher.Get())
            {
                // ProtectionStatus: 0 = off, 1 = on, 2 = unknown
                var ps = Convert.ToInt32(mo["ProtectionStatus"] ?? 0);
                return ps == 1 ? PostureState.Good : PostureState.Bad;
            }
        }
        catch { }
        return PostureState.Unknown;
    }
}
