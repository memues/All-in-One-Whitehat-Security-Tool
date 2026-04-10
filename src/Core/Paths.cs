// SPDX-License-Identifier: MIT
// Resolves the runtime data directory. When the .exe runs from a writable
// location (developer build, Downloads folder, USB stick, etc.) the program
// writes its config and logs next to itself, the way the PowerShell port did.
// When the .exe is installed under %ProgramFiles% it can no longer write
// next to itself because asInvoker has no write access there, so we redirect
// to %LOCALAPPDATA%\Whitehat Security\ — the standard location every modern
// Windows app uses for per-user state.
//
// This bug crashed v7.2.0 and v7.2.1 with UnauthorizedAccessException at
// Logger..ctor when launched from C:\Program Files. The crash was silent
// (no tray icon, no log file because logging itself was the failing step)
// which made it look like the install had not happened at all.

using System;
using System.IO;

namespace WhitehatSecurity.Core;

public static class Paths
{
    /// <summary>
    /// Directory the program reads/writes its config, logs and baselines
    /// from. Falls back to AppContext.BaseDirectory only when that path is
    /// actually writable; otherwise points at %LOCALAPPDATA%\Whitehat Security.
    /// </summary>
    public static string DataDir { get; } = ResolveDataDir();

    public static string ConfigPath  => Path.Combine(DataDir, "notification_config.json");
    public static string LogsDir     => Path.Combine(DataDir, "Logs");
    public static string BaselineDir => Path.Combine(DataDir, "Baselines");

    private static string ResolveDataDir()
    {
        var preferred = AppContext.BaseDirectory;
        if (IsWritable(preferred)) return preferred;

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appDir       = Path.Combine(localAppData, "Whitehat Security");
        try
        {
            Directory.CreateDirectory(appDir);
        }
        catch
        {
            // Last-ditch fallback: temp folder. Should be writable for any
            // user account that can run the .exe at all.
            appDir = Path.Combine(Path.GetTempPath(), "WhitehatSecurity");
            Directory.CreateDirectory(appDir);
        }
        return appDir;
    }

    /// <summary>
    /// Best-effort write test. We try to create a small probe file in the
    /// directory; if that throws (UnauthorizedAccessException, IOException,
    /// SecurityException, etc.) the directory is not writable for us and we
    /// will redirect runtime state elsewhere.
    /// </summary>
    private static bool IsWritable(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return false;
            var probe = Path.Combine(dir, $".whs_write_probe_{Guid.NewGuid():N}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
