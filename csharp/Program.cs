// SPDX-License-Identifier: MIT
// Application entry point. Wires up the config, logger, monitor host, all
// engines, and the tray UI. Equivalent to the bottom of SecurityMonitor.ps1
// (~line 6996, the `try { Start-Monitoring } catch …` block).

using System;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Ui;

namespace WhitehatSecurity;

internal static class Program
{
    private const string MutexName = "Global\\WhitehatSecurity-7.1-singleinstance";

    [STAThread]
    private static int Main(string[] args)
    {
        // Single-instance mutex (matches Start-Monitoring in PS port).
        using var mutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
        if (!createdNew)
        {
            // Another instance is already running — don't show an error toast,
            // just exit silently. The PS port does the same.
            return 0;
        }

        bool silent = Array.Exists(args, a =>
            a.Equals("--silent", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("-Silent",  StringComparison.OrdinalIgnoreCase));

        ApplicationConfiguration.Initialize();

        // ── Load config + logger ──
        var baseDir = AppContext.BaseDirectory;
        var configPath = Path.Combine(baseDir, "notification_config.json");
        var logsDir    = Path.Combine(baseDir, "Logs");

        var config = NotifyConfig.LoadOrCreate(configPath);
        var logger = new Logger(logsDir);
        logger.Info($"=== WhitehatSecurity 7.1 (C# port) starting (silent={silent}) ===");
        logger.Info($"Config path: {configPath}");
        logger.Info($"Logs dir:    {logsDir}");

        // ── Build the monitor host with every engine ──
        var host = new MonitorHost(config, logger, TimeSpan.FromSeconds(10));
        host.Register(new ConnectionEngine());
        host.Register(new ListenerEngine());
        host.Register(new ProcessEngine());
        host.Register(new DriverEngine());
        host.Register(new ServiceEngine());
        host.Register(new RegistryEngine());
        host.Register(new HostsEngine());
        host.Register(new FirmwareEngine());

        // ── Tray context owns the message pump ──
        try
        {
            var ctx = new TrayApplicationContext(config, logger, host);
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
}
