// SPDX-License-Identifier: MIT
// Windows 11 hides new NotifyIcons in the overflow flyout by default until the
// underlying executable's entry under HKCU\Control Panel\NotifyIconSettings has
// IsPromoted = 1. This helper performs the same promotion the PowerShell port
// does in Initialize-TrayIcon (SecurityMonitor.ps1 line ~5325).

using Microsoft.Win32;

namespace WhitehatSecurity.Native;

internal static class NotifyIconPromote
{
    private const string NotifyRoot = @"Control Panel\NotifyIconSettings";

    /// <summary>
    /// Walks every NotifyIconSettings entry whose ExecutablePath references the
    /// current process executable name and forces IsPromoted = 1. Safe to call
    /// repeatedly. Returns the number of entries that were updated.
    /// </summary>
    /// <param name="exeNameHint">
    /// Substring to match against the entry's ExecutablePath value, e.g.
    /// "WhitehatSecurity" for the C# port. The Windows entry stores paths in
    /// the form `{1AC14E77-...}\Programs\WhitehatSecurity.exe`, so a partial
    /// match is enough and is more robust than a full path comparison.
    /// </param>
    public static int Promote(string exeNameHint)
    {
        int updated = 0;
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(NotifyRoot, writable: false);
            if (root is null) return 0;

            foreach (string subKeyName in root.GetSubKeyNames())
            {
                try
                {
                    using var sub = Registry.CurrentUser.OpenSubKey(
                        $@"{NotifyRoot}\{subKeyName}", writable: true);
                    if (sub is null) continue;

                    var path = sub.GetValue("ExecutablePath") as string;
                    if (string.IsNullOrEmpty(path)) continue;
                    if (path.IndexOf(exeNameHint, System.StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    var current = sub.GetValue("IsPromoted") as int?;
                    if (current != 1)
                    {
                        sub.SetValue("IsPromoted", 1, RegistryValueKind.DWord);
                        updated++;
                    }
                }
                catch
                {
                    // best effort — keep walking other entries
                }
            }
        }
        catch
        {
            // best effort — registry might be locked or absent on some SKUs
        }
        return updated;
    }
}
