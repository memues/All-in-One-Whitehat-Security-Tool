// SPDX-License-Identifier: MIT
// Application entry point. Three modes:
//
//   WhitehatSecurity.exe                normal run (tray + dashboard)
//   WhitehatSecurity.exe --silent       normal run, no dashboard auto-open
//   WhitehatSecurity.exe --install      copy self to Program Files, register
//                                       in Add/Remove Programs, exit
//   WhitehatSecurity.exe --uninstall    remove install dir / shortcuts /
//                                       registry, exit
//
// On first run from outside the install directory, the .exe shows a small
// dialog offering to install itself system-wide so it appears in the Windows
// "Apps & Features" list and can be uninstalled the normal way.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Ui;

namespace WhitehatSecurity;

internal static class Program
{
    private const string MutexName = "Global\\WhitehatSecurity-7.2-singleinstance";

    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        // ── Mode dispatch ───────────────────────────────────────────────
        bool silent    = HasFlag(args, "--silent",    "-Silent");
        bool install   = HasFlag(args, "--install",   "-Install");
        bool uninstall = HasFlag(args, "--uninstall", "-Uninstall");
        bool quiet     = HasFlag(args, "--quiet",     "-Quiet");

        if (install)   return RunInstall(quiet);
        if (uninstall) return RunUninstall(quiet);

        // ── Single-instance mutex (matches Start-Monitoring in PS port) ──
        using var mutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
        if (!createdNew)
        {
            // Another instance is already running - exit silently.
            return 0;
        }

        // ── First-run install prompt ────────────────────────────────────
        // Only when the user is running the .exe from outside the install
        // dir AND it isn't already installed.
        if (!silent
            && !Installer.IsRunningFromInstallDir()
            && !Installer.IsAlreadyInstalled())
        {
            var answer = MessageBox.Show(
                $"Install {Installer.ProductName} {Installer.ProductVersion} to:\n\n" +
                $"    {Installer.DefaultInstallDir}\n\n" +
                "This adds the program to Windows Apps & Features so it can\n" +
                "be uninstalled the normal way, and creates Start Menu and\n" +
                "Desktop shortcuts.\n\n" +
                "Click Yes to install, No to just run this copy once.",
                "Whitehat Security - Installer",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question);

            if (answer == DialogResult.Cancel) return 0;
            if (answer == DialogResult.Yes)
            {
                // Re-launch self elevated with --install. The elevated copy
                // will install and exit; we then launch the installed binary.
                var rc = LaunchSelfElevated("--install");
                if (rc == 0)
                {
                    var installed = Installer.DefaultInstallExePath;
                    if (File.Exists(installed))
                    {
                        Process.Start(new ProcessStartInfo(installed)
                        {
                            UseShellExecute = true,
                        });
                    }
                }
                return 0;
            }
            // No → fall through and run from current location
        }

        // ── Load config + logger ────────────────────────────────────────
        var baseDir    = AppContext.BaseDirectory;
        var configPath = Path.Combine(baseDir, "notification_config.json");
        var logsDir    = Path.Combine(baseDir, "Logs");

        var config       = NotifyConfig.LoadOrCreate(configPath);
        var logger       = new Logger(logsDir);
        var consoleSink  = new ConsoleSink();
        logger.Info($"=== WhitehatSecurity 7.2 (C# port) starting (silent={silent}) ===");
        logger.Info($"Config path: {configPath}");
        logger.Info($"Logs dir:    {logsDir}");
        consoleSink.WriteLine($"Whitehat Security 7.2 starting (silent={silent})");
        consoleSink.WriteLine($"Config: {configPath}");
        consoleSink.WriteLine($"Logs:   {logsDir}");

        // ── Build the monitor host with every engine ────────────────────
        var host = new MonitorHost(config, logger, TimeSpan.FromSeconds(10));
        host.Register(new ConnectionEngine());
        host.Register(new ListenerEngine());
        host.Register(new ProcessEngine());
        host.Register(new DriverEngine());
        host.Register(new ServiceEngine());
        host.Register(new RegistryEngine());
        host.Register(new HostsEngine());
        host.Register(new FirmwareEngine());

        // ── Tray context owns the message pump ──────────────────────────
        try
        {
            var ctx = new TrayApplicationContext(config, logger, host, consoleSink, configPath);
            if (!silent) ctx.OpenDashboard();
            Application.Run(ctx);
        }
        catch (Exception ex)
        {
            logger.Error($"Fatal: {ex}");
            return 1;
        }
        finally
        {
            host.Dispose();
            logger.Info("=== WhitehatSecurity stopped ===");
        }

        return 0;
    }

    // ------------------------------------------------------------------------

    private static int RunInstall(bool quiet)
    {
        try
        {
            var logger = new Logger(Path.GetTempPath());
            Installer.InstallElevated(logger);
            if (!quiet)
                MessageBox.Show(
                    $"Installed to:\n{Installer.DefaultInstallDir}\n\n" +
                    "You can now uninstall via Settings > Apps > Apps & Features.",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            if (!quiet)
                MessageBox.Show($"Install failed:\n{ex.Message}",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static int RunUninstall(bool quiet)
    {
        try
        {
            var logger = new Logger(Path.GetTempPath());
            Installer.UninstallElevated(logger);
            if (!quiet)
                MessageBox.Show(
                    $"{Installer.ProductName} has been removed.",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            if (!quiet)
                MessageBox.Show($"Uninstall failed:\n{ex.Message}",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static int LaunchSelfElevated(string arguments)
    {
        var self = Environment.ProcessPath
            ?? throw new InvalidOperationException("ProcessPath null");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName        = self,
                Arguments       = arguments,
                Verb            = "runas",   // UAC
                UseShellExecute = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return -1;
            p.WaitForExit(120_000);
            return p.ExitCode;
        }
        catch (Exception)
        {
            // User denied UAC
            return -2;
        }
    }

    private static bool HasFlag(string[] args, params string[] aliases)
    {
        foreach (var a in args)
            foreach (var f in aliases)
                if (a.Equals(f, StringComparison.OrdinalIgnoreCase))
                    return true;
        return false;
    }
}
