// SPDX-License-Identifier: MIT

using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WhitehatSecurity.Native;

/// <summary>
/// Validates embedded Authenticode signatures and Windows catalog signatures.
/// Microsoft inbox binaries are commonly catalog-signed, so an embedded-only
/// certificate check generates severe false positives.
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    public static bool IsTrusted(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        try
        {
            return VerifyEmbedded(path) || VerifyCatalog(path);
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyEmbedded(string path)
    {
        using var fileInfo = new WinTrustFileInfo(path);
        return Verify(WtdChoiceFile, fileInfo.Pointer);
    }

    private static bool VerifyCatalog(string path)
    {
        using var file = CreateFile(
            path,
            0x80000000,
            FileShare.Read | FileShare.Write | FileShare.Delete,
            IntPtr.Zero,
            FileMode.Open,
            0,
            IntPtr.Zero);
        if (file.IsInvalid)
            return false;

        if (!CryptCATAdminAcquireContext2(
                out var admin, IntPtr.Zero, null, IntPtr.Zero, 0))
            return false;

        try
        {
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(
                    admin, file, ref hashSize, null, 0) &&
                Marshal.GetLastPInvokeError() != 122)
                return false;
            if (hashSize == 0 || hashSize > 1024)
                return false;

            var hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(
                    admin, file, ref hashSize, hash, 0))
                return false;

            var previous = IntPtr.Zero;
            var catalog = CryptCATAdminEnumCatalogFromHash(
                admin, hash, hashSize, 0, ref previous);
            if (catalog == IntPtr.Zero)
                return false;

            try
            {
                var info = new CatalogInfo
                {
                    cbStruct = (uint)Marshal.SizeOf<CatalogInfo>(),
                    wszCatalogFile = string.Empty,
                };
                if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0))
                    return false;

                using var catalogInfo = new WinTrustCatalogInfo(
                    info.wszCatalogFile,
                    Convert.ToHexString(hash),
                    path,
                    file.DangerousGetHandle(),
                    hash,
                    admin);
                return Verify(WtdChoiceCatalog, catalogInfo.Pointer);
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    private static bool Verify(uint choice, IntPtr subjectInfo)
    {
        var data = new WinTrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
            dwUIChoice = WtdUiNone,
            dwUnionChoice = choice,
            pInfoStruct = subjectInfo,
            dwProvFlags = WtdCacheOnlyUrlRetrieval,
        };
        var action = GenericVerifyV2;
        return WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfoStruct;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfoNative
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    private sealed class WinTrustFileInfo : IDisposable
    {
        private readonly IntPtr _path;
        public IntPtr Pointer { get; }

        public WinTrustFileInfo(string path)
        {
            _path = Marshal.StringToCoTaskMemUni(path);
            var native = new WinTrustFileInfoNative
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfoNative>(),
                pcwszFilePath = _path,
            };
            Pointer = Marshal.AllocCoTaskMem(
                Marshal.SizeOf<WinTrustFileInfoNative>());
            Marshal.StructureToPtr(native, Pointer, false);
        }

        public void Dispose()
        {
            Marshal.FreeCoTaskMem(Pointer);
            Marshal.FreeCoTaskMem(_path);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfoNative
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    private sealed class WinTrustCatalogInfo : IDisposable
    {
        private readonly IntPtr _catalogPath;
        private readonly IntPtr _memberTag;
        private readonly IntPtr _memberPath;
        private readonly IntPtr _hash;
        public IntPtr Pointer { get; }

        public WinTrustCatalogInfo(
            string catalogPath,
            string memberTag,
            string memberPath,
            IntPtr file,
            byte[] hash,
            IntPtr admin)
        {
            _catalogPath = Marshal.StringToCoTaskMemUni(catalogPath);
            _memberTag = Marshal.StringToCoTaskMemUni(memberTag);
            _memberPath = Marshal.StringToCoTaskMemUni(memberPath);
            _hash = Marshal.AllocCoTaskMem(hash.Length);
            Marshal.Copy(hash, 0, _hash, hash.Length);

            var native = new WinTrustCatalogInfoNative
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfoNative>(),
                pcwszCatalogFilePath = _catalogPath,
                pcwszMemberTag = _memberTag,
                pcwszMemberFilePath = _memberPath,
                hMemberFile = file,
                pbCalculatedFileHash = _hash,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = admin,
            };
            Pointer = Marshal.AllocCoTaskMem(
                Marshal.SizeOf<WinTrustCatalogInfoNative>());
            Marshal.StructureToPtr(native, Pointer, false);
        }

        public void Dispose()
        {
            Marshal.FreeCoTaskMem(Pointer);
            Marshal.FreeCoTaskMem(_catalogPath);
            Marshal.FreeCoTaskMem(_memberTag);
            Marshal.FreeCoTaskMem(_memberPath);
            Marshal.FreeCoTaskMem(_hash);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        ref Guid actionId,
        ref WinTrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr catAdmin,
        IntPtr subsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catAdmin,
        SafeFileHandle file,
        ref uint hashSize,
        byte[]? hash,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catAdmin,
        byte[] hash,
        uint hashSize,
        uint flags,
        ref IntPtr previousCatalog);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr catalog,
        ref CatalogInfo catalogInfo,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr catAdmin,
        IntPtr catalog,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr catAdmin,
        uint flags);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);
}
