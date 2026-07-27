// SPDX-License-Identifier: MIT

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Core;

public sealed record FileInspection(
    string Path,
    bool Exists,
    long? Size,
    DateTime? LastWriteTimeUtc,
    string? Sha256,
    bool TrustedSignature,
    string? ProductName,
    string? CompanyName,
    string? FileVersion,
    string? Error)
{
    public string ToDisplayText()
    {
        if (!Exists)
            return $"File: {Path}{Environment.NewLine}State: Missing";
        if (Error is not null)
            return $"File: {Path}{Environment.NewLine}Inspection error: {Error}";

        return
            $"File:       {Path}{Environment.NewLine}" +
            $"Size:       {Size:N0} bytes{Environment.NewLine}" +
            $"Modified:   {LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC{Environment.NewLine}" +
            $"SHA-256:    {Sha256}{Environment.NewLine}" +
            $"Signature:  {(TrustedSignature ? "Trusted" : "Untrusted or unsigned")}{Environment.NewLine}" +
            $"Product:    {ProductName ?? "(unknown)"}{Environment.NewLine}" +
            $"Company:    {CompanyName ?? "(unknown)"}{Environment.NewLine}" +
            $"Version:    {FileVersion ?? "(unknown)"}";
    }
}

public static class FileInvestigator
{
    public static FileInspection Inspect(string rawPath)
    {
        var path = ThreatPath.Normalize(rawPath) ?? rawPath;
        if (!File.Exists(path))
            return new FileInspection(
                path, false, null, null, null, false,
                null, null, null, null);

        try
        {
            var info = new FileInfo(path);
            string sha256;
            using (var stream = new FileStream(
                       path, FileMode.Open, FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete))
            using (var hash = SHA256.Create())
                sha256 = Convert.ToHexString(hash.ComputeHash(stream));

            FileVersionInfo? version = null;
            try { version = FileVersionInfo.GetVersionInfo(path); }
            catch { }

            return new FileInspection(
                path,
                true,
                info.Length,
                info.LastWriteTimeUtc,
                sha256,
                AuthenticodeVerifier.IsTrusted(path),
                NullIfBlank(version?.ProductName),
                NullIfBlank(version?.CompanyName),
                NullIfBlank(version?.FileVersion),
                null);
        }
        catch (Exception ex)
        {
            return new FileInspection(
                path, true, null, null, null, false,
                null, null, null, ex.Message);
        }
    }

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value;
}
