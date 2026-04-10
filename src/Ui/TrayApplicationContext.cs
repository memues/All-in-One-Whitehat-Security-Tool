// SPDX-License-Identifier: MIT
// Tray-only ApplicationContext. Owns the NotifyIcon, the dashboard form
// (lazy-created), the MonitorHost, and the IsPromoted registry fix that
// makes the tray icon visible on Windows 11 by default.

using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Native;

namespace WhitehatSecurity.Ui;

public sealed class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon       _tray;
    private readonly NotifyConfig     _config;
    private readonly Logger           _logger;
    private readonly MonitorHost      _host;
    private readonly DashboardSink    _dashboardSink;
    private DashboardForm?            _dashboard;

    public TrayApplicationContext(
        NotifyConfig config,
        Logger       logger,
        MonitorHost  host)
    {
        _config = config;
        _logger = logger;
        _host   = host;

        _tray = new NotifyIcon
        {
            Icon            = BuildShieldIcon(),
            Text            = "Whitehat Security",
            Visible         = true,
            ContextMenuStrip = BuildContextMenu(),
        };
        _tray.DoubleClick += (_, _) => OpenDashboard();
        _tray.BalloonTipClicked += (_, _) => OpenDashboard();

        // Sink that forwards alerts into the dashboard's listview when it
        // exists. Always registered so alerts are buffered even before the
        // user opens the dashboard.
        _dashboardSink = new DashboardSink();
        host.AddSink(_dashboardSink);
        host.AddSink(new ToastNotifier(_tray, _config));

        host.Start();

        // Windows 11 IsPromoted fix — runs on a delay so Explorer has time to
        // create the registry entry after Visible = true.
        var promoteTimer = new System.Windows.Forms.Timer { Interval = 700 };
        int attempts = 0;
        promoteTimer.Tick += (_, _) =>
        {
            attempts++;
            int updated = NotifyIconPromote.Promote(GetExeNameHint());
            if (updated > 0)
            {
                _logger.Info($"Tray icon promoted in registry ({updated} entries)");
                // Toggle visibility once so Explorer re-evaluates promotion
                _tray.Visible = false;
                _tray.Visible = true;
                promoteTimer.Stop();
                promoteTimer.Dispose();
            }
            else if (attempts >= 10)
            {
                promoteTimer.Stop();
                promoteTimer.Dispose();
            }
        };
        promoteTimer.Start();
    }

    private static string GetExeNameHint()
    {
        // Environment.ProcessPath is single-file-safe; Assembly.Location returns
        // empty string for assemblies embedded inside a single-file bundle.
        var exe = Environment.ProcessPath ?? "WhitehatSecurity";
        return Path.GetFileNameWithoutExtension(exe);
    }

    public void OpenDashboard()
    {
        if (_dashboard is null || _dashboard.IsDisposed)
        {
            _dashboard = new DashboardForm(_config, _logger, _dashboardSink);
            _dashboard.FormClosed += (_, _) => _dashboard = null;
        }
        _dashboard.Show();
        _dashboard.WindowState = FormWindowState.Normal;
        _dashboard.BringToFront();
        _dashboard.Activate();
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Dashboard", null, (_, _) => OpenDashboard());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) =>
        {
            _host.Stop();
            _tray.Visible = false;
            _tray.Dispose();
            ExitThread();
        });
        return menu;
    }

    /// <summary>
    /// Draws the same blue shield-with-checkmark icon the PowerShell port
    /// generates in Initialize-TrayIcon (~line 5333).
    /// </summary>
    private static Icon BuildShieldIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            var shield = new[]
            {
                new Point(16, 2),
                new Point(28, 6),
                new Point(28, 16),
                new Point(16, 30),
                new Point(4, 16),
                new Point(4, 6),
            };
            using var shieldBrush = new SolidBrush(Color.FromArgb(0, 180, 255));
            g.FillPolygon(shieldBrush, shield);

            var inner = new[]
            {
                new Point(16, 6),
                new Point(24, 9),
                new Point(24, 15),
                new Point(16, 26),
                new Point(8, 15),
                new Point(8, 9),
            };
            using var innerBrush = new SolidBrush(Color.FromArgb(0, 120, 200));
            g.FillPolygon(innerBrush, inner);

            using var checkPen = new Pen(Color.White, 3);
            g.DrawLine(checkPen, 10, 16, 14, 21);
            g.DrawLine(checkPen, 14, 21, 22, 11);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }
}

/// <summary>
/// Buffers alerts in memory and exposes an event for the dashboard to wire
/// onto its ListView. Created here (not in DashboardForm) so the buffer
/// survives across dashboard open/close cycles.
/// </summary>
public sealed class DashboardSink : IAlertSink
{
    private readonly System.Collections.Generic.List<Alert> _buffer = new();
    public event Action<Alert>? AlertReceived;

    public System.Collections.Generic.IReadOnlyList<Alert> All => _buffer;

    public void Receive(Alert alert)
    {
        lock (_buffer) _buffer.Add(alert);
        try { AlertReceived?.Invoke(alert); } catch { }
    }
}
