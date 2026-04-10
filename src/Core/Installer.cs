// SPDX-License-Identifier: MIT
// Self-installer / self-uninstaller. The single .exe is its own setup
// program: when launched from outside Program Files it offers to install
// itself system-wide, when launched with --uninstall it cleans up.
//
// Install location: %ProgramFiles%\Whitehat Security\WhitehatSecurity.exe
// Add/Remove key:   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WhitehatSecurity
// Start menu link:  %ProgramData%\Microsoft\Windows\Start Menu\Programs\Whitehat Security.lnk
// Desktop link:     %PUBLIC%\Desktop\Whitehat Security.lnk
//
// All file copies and registry writes happen elevated. Self-deletion of the
// installed binary during uninstall uses the classic "spawn cmd that waits
// then deletes the file" trick because Windows will not let a running .exe
// remove itself.

using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace WhitehatSecurity.Core;

public static class Installer
{
    public const string ProductName    = "Whitehat Security";
    public const string ProductVersion = "7.3.3";
    public const string Publisher      = "Whitehat Security";
    public const string AppId          = "WhitehatSecurity";

    public const string UninstallKeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WhitehatSecurity";

    public static string DefaultInstallDir =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ProductName);

    public static string DefaultInstallExePath =>
        Path.Combine(DefaultInstallDir, "WhitehatSecurity.exe");

    public static string StartMenuShortcut =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            "Programs",
            ProductName + ".lnk");

    public static string PublicDesktopShortcut =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            ProductName + ".lnk");

    /// <summary>
    /// Path to the per-user Desktop shortcut. On systems with OneDrive
    /// "Known Folder Move" enabled, this resolves to the redirected
    /// OneDrive\Desktop folder, which is exactly the directory the user
    /// actually sees on their screen — the Public Desktop entry alone is
    /// invisible there. We create both to cover both setups.
    /// </summary>
    public static string UserDesktopShortcut =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            ProductName + ".lnk");

    /// <summary>
    /// Where Windows looks for system-wide auto-start entries. The installer
    /// writes a value here pointing at the installed exe with --silent so
    /// that the program comes up as a tray icon (no dashboard) at every
    /// logon. Same convention used by most installed Windows apps.
    /// </summary>
    public const string RunKeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string RunValueName = "WhitehatSecurity";

    /// <summary>
    /// Returns true when the running .exe lives inside the canonical install
    /// directory. The first-run flow uses this to decide whether to show the
    /// install prompt.
    /// </summary>
    public static bool IsRunningFromInstallDir()
    {
        var current = Environment.ProcessPath;
        if (string.IsNullOrEmpty(current)) return false;
        try
        {
            return string.Equals(
                Path.GetFullPath(current),
                Path.GetFullPath(DefaultInstallExePath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public static bool IsAlreadyInstalled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(UninstallKeyPath);
            return key is not null;
        }
        catch { return false; }
    }

    // ========================================================================
    //  INSTALL
    // ========================================================================

    /// <summary>
    /// Copies the running .exe to %ProgramFiles%\Whitehat Security\,
    /// registers in Add/Remove Programs, and creates Start Menu and Public
    /// Desktop shortcuts. Must be called from an elevated process.
    /// </summary>
    public static void InstallElevated(Logger? logger = null)
    {
        var src = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine current exe path");
        var dstDir = DefaultInstallDir;
        var dstExe = DefaultInstallExePath;

        Directory.CreateDirectory(dstDir);

        // Copy the binary to a temp name then atomically swap it into place.
        // We try plain Move first; if the destination is locked (the previous
        // version is still running), File.Replace handles the swap by routing
        // through a backup file.
        var tmp = dstExe + ".new";
        File.Copy(src, tmp, overwrite: true);

        if (!File.Exists(dstExe))
        {
            File.Move(tmp, dstExe);
        }
        else
        {
            try
            {
                File.Delete(dstExe);
                File.Move(tmp, dstExe);
            }
            catch (IOException)
            {
                // Locked — the .exe is in use. Use File.Replace to swap
                // through a backup, which works even when the target is open.
                var bak = dstExe + ".bak";
                try { File.Delete(bak); } catch { }
                File.Replace(tmp, dstExe, bak, ignoreMetadataErrors: true);
                try { File.Delete(bak); } catch { }
            }
        }
        logger?.Info($"Installed binary to {dstExe}");

        // Register in Add/Remove Programs
        WriteUninstallKey(dstExe, dstDir);
        logger?.Info("Registered in Add/Remove Programs");

        // Shortcuts — create on every plausible desktop location so it shows
        // up regardless of OneDrive Known Folder Move state. The installer
        // also drops one in the Common Desktop and the Common Start Menu so
        // every user on the machine sees it.
        try { CreateShortcut(StartMenuShortcut,     dstExe); } catch (Exception ex) { logger?.Warn($"Start menu shortcut: {ex.Message}"); }
        try { CreateShortcut(PublicDesktopShortcut, dstExe); } catch (Exception ex) { logger?.Warn($"Public desktop shortcut: {ex.Message}"); }
        try { CreateShortcut(UserDesktopShortcut,   dstExe); } catch (Exception ex) { logger?.Warn($"User desktop shortcut: {ex.Message}"); }

        // Auto-start at logon. The Run key is the standard mechanism for
        // installed Windows apps; the --silent flag keeps the dashboard
        // closed so it just shows up in the system tray, the way every
        // other security tool does.
        try
        {
            using var run = Registry.LocalMachine.CreateSubKey(RunKeyPath, writable: true);
            run?.SetValue(RunValueName, $"\"{dstExe}\" --silent", RegistryValueKind.String);
            logger?.Info("Auto-start at logon enabled (HKLM Run key)");
        }
        catch (Exception ex)
        {
            logger?.Warn($"Auto-start: {ex.Message}");
        }
    }

    private static void WriteUninstallKey(string installedExe, string installDir)
    {
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKeyPath, writable: true);
        if (key is null) throw new InvalidOperationException("Cannot create uninstall key");

        long sizeKb = 0;
        try { sizeKb = new FileInfo(installedExe).Length / 1024; } catch { }

        key.SetValue("DisplayName",     ProductName);
        key.SetValue("DisplayVersion",  ProductVersion);
        key.SetValue("Publisher",       Publisher);
        key.SetValue("DisplayIcon",     installedExe);
        key.SetValue("InstallLocation", installDir);
        key.SetValue("UninstallString", $"\"{installedExe}\" --uninstall");
        key.SetValue("QuietUninstallString", $"\"{installedExe}\" --uninstall --quiet");
        key.SetValue("InstallDate",     DateTime.Now.ToString("yyyyMMdd"));
        key.SetValue("EstimatedSize",   (int)sizeKb, RegistryValueKind.DWord);
        key.SetValue("NoModify",        1, RegistryValueKind.DWord);
        key.SetValue("NoRepair",        1, RegistryValueKind.DWord);
        key.SetValue("URLInfoAbout",    "https://github.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool");
    }

    private static void CreateShortcut(string lnkPath, string targetExe)
    {
        // Use the WScript.Shell COM object via reflection so we don't pull in
        // an extra package reference (Interop.Shell32 etc.). Same approach
        // the PowerShell port uses internally.
        var dir = Path.GetDirectoryName(lnkPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var t = Type.GetTypeFromProgID("WScript.Shell");
        if (t is null) throw new InvalidOperationException("WScript.Shell not registered");
        dynamic? shell = Activator.CreateInstance(t);
        if (shell is null) throw new InvalidOperationException("WScript.Shell instance is null");
        try
        {
            dynamic sc = shell.CreateShortcut(lnkPath);
            sc.TargetPath       = targetExe;
            sc.WorkingDirectory = Path.GetDirectoryName(targetExe) ?? "";
            sc.IconLocation     = targetExe + ",0";
            sc.Description      = ProductName;
            sc.Save();
        }
        finally
        {
            try { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell); } catch { }
        }
    }

    // ========================================================================
    //  UNINSTALL
    // ========================================================================

    /// <summary>
    /// Removes the installed copy, registry entry, and shortcuts. Must be
    /// called from an elevated process. Schedules a self-delete batch script
    /// because the running .exe (which lives at the install path) cannot
    /// delete itself.
    /// </summary>
    public static void UninstallElevated(Logger? logger = null)
    {
        // Step 0 — kill every running WhitehatSecurity.exe instance EXCEPT
        // ourselves (the uninstaller). The auto-start tray instance has the
        // installed .exe open, so File.Delete would fail without this. We
        // skip the current process so we can finish the uninstall script
        // and schedule our own self-delete.
        try
        {
            int self = Environment.ProcessId;
            var others = Process.GetProcessesByName("WhitehatSecurity");
            foreach (var p in others)
            {
                try
                {
                    if (p.Id == self) { p.Dispose(); continue; }
                    logger?.Info($"Stopping running instance PID {p.Id}");
                    p.Kill(entireProcessTree: false);
                    p.WaitForExit(3000);
                }
                catch (Exception ex)
                {
                    logger?.Warn($"Could not stop PID {p.Id}: {ex.Message}");
                }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }
        catch (Exception ex)
        {
            logger?.Warn($"Process enumeration failed: {ex.Message}");
        }

        // Best-effort: delete the registry entry first so the entry vanishes
        // from Apps & Features even if file removal fails for any reason.
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKeyPath, throwOnMissingSubKey: false);
            logger?.Info("Removed Add/Remove Programs entry");
        }
        catch (Exception ex) { logger?.Warn($"Registry delete: {ex.Message}"); }

        // Auto-start Run key
        try
        {
            using var run = Registry.LocalMachine.OpenSubKey(RunKeyPath, writable: true);
            if (run is not null && run.GetValue(RunValueName) is not null)
            {
                run.DeleteValue(RunValueName, throwOnMissingValue: false);
                logger?.Info("Removed auto-start Run key");
            }
        }
        catch (Exception ex) { logger?.Warn($"Run key delete: {ex.Message}"); }

        // Shortcuts
        TryDelete(StartMenuShortcut,     logger);
        TryDelete(PublicDesktopShortcut, logger);
        TryDelete(UserDesktopShortcut,   logger);

        // Per-user data dir under %LOCALAPPDATA% — config, logs, baselines.
        // v7.3.x left this behind on uninstall, which meant a reinstall
        // picked up the previous user's settings (notably toast on/off,
        // notification category state). Removing it makes a reinstall
        // start from a true fresh state with the v7.3.2+ defaults.
        try
        {
            if (Directory.Exists(Paths.UserDataDir))
            {
                Directory.Delete(Paths.UserDataDir, recursive: true);
                logger?.Info($"Removed user data dir {Paths.UserDataDir}");
            }
        }
        catch (Exception ex) { logger?.Warn($"User data dir delete: {ex.Message}"); }

        var installedExe = DefaultInstallExePath;
        var installDir   = DefaultInstallDir;

        // If we're not the installed exe, just delete the install dir directly
        var current = Environment.ProcessPath ?? "";
        bool selfIsInstalled = string.Equals(
            Path.GetFullPath(current),
            Path.GetFullPath(installedExe),
            StringComparison.OrdinalIgnoreCase);

        if (!selfIsInstalled)
        {
            try
            {
                if (Directory.Exists(installDir))
                {
                    Directory.Delete(installDir, recursive: true);
                    logger?.Info($"Removed {installDir}");
                }
            }
            catch (Exception ex) { logger?.Warn($"Install dir delete: {ex.Message}"); }
            return;
        }

        // We ARE the installed exe. We can't delete ourselves, so spawn a
        // detached cmd.exe that waits 2 seconds then deletes the install dir
        // and itself.
        var batPath = Path.Combine(Path.GetTempPath(), $"whs_uninst_{Guid.NewGuid():N}.bat");
        File.WriteAllText(batPath, BuildSelfDeleteBatch(installDir, batPath));
        logger?.Info("Scheduled self-delete; exiting");

        var psi = new ProcessStartInfo
        {
            FileName        = "cmd.exe",
            Arguments       = $"/c \"{batPath}\"",
            UseShellExecute = false,
            CreateNoWindow  = true,
            WindowStyle     = ProcessWindowStyle.Hidden,
        };
        Process.Start(psi);
        // The caller (Program.Main) returns immediately after this and the
        // process exits, freeing the file lock so the batch can delete us.
    }

    private static string BuildSelfDeleteBatch(string installDir, string batPath) => $@"
@echo off
ping 127.0.0.1 -n 3 > nul
rmdir /s /q ""{installDir}""
del ""{batPath}""
";

    private static void TryDelete(string path, Logger? logger)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
                logger?.Info($"Removed {path}");
            }
        }
        catch (Exception ex) { logger?.Warn($"Delete {path}: {ex.Message}"); }
    }
}
