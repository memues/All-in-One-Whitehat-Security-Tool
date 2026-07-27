// SPDX-License-Identifier: MIT
// Tray-only ApplicationContext. Owns the NotifyIcon, the dashboard form
// (lazy-created), the MonitorHost, and the IsPromoted registry fix that
// makes the tray icon visible on Windows 11 by default.

using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Threading;
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
    private readonly AlertHistoryStore _history;
    private readonly ConsoleSink      _consoleSink;
    private readonly string           _configPath;
    private readonly EventWaitHandle  _instanceSignal;
    private readonly System.Windows.Forms.Timer _instanceTimer;
    private readonly System.Windows.Forms.Timer _promoteTimer;
    private readonly Control _uiInvoker = new();
    private DashboardForm?            _dashboard;

    public TrayApplicationContext(
        NotifyConfig config,
        Logger       logger,
        MonitorHost  host,
        ConsoleSink  consoleSink,
        string       configPath,
        EventWaitHandle instanceSignal)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(consoleSink);
        ArgumentException.ThrowIfNullOrWhiteSpace(configPath);
        ArgumentNullException.ThrowIfNull(instanceSignal);
        _config      = config;
        _logger      = logger;
        _host        = host;
        _consoleSink = consoleSink;
        _configPath  = configPath;
        _instanceSignal = instanceSignal;
        _uiInvoker.CreateControl();

        _tray = new NotifyIcon
        {
            Icon             = ShieldIcon,
            Text             = "Whitehat Security",
            Visible          = true,
            ContextMenuStrip = BuildContextMenu(),
        };
        _tray.DoubleClick       += (_, _) => OpenDashboard();
        // BalloonTipClicked routes straight to the Alerts tab — that is the
        // only thing the user could possibly want to see right after a toast.
        _tray.BalloonTipClicked += (_, _) => OpenDashboard("Alerts");

        // Sink that forwards alerts into the dashboard's listview when it
        // exists. Always registered so alerts are buffered even before the
        // user opens the dashboard.
        _dashboardSink = new DashboardSink();
        // Replay saved history first so the Alerts page opens with what the
        // machine has actually seen, not just what happened since the last
        // restart. Seeding before Start() means the backlog is already in
        // place whenever the dashboard is opened.
        _history = new AlertHistoryStore(Paths.AlertHistoryPath);
        try { _dashboardSink.Seed(_history.Load()); }
        catch (Exception ex) { _logger.Warn($"Alert history: {ex.Message}"); }

        host.AddSink(_dashboardSink);
        host.AddSink(_consoleSink);
        host.AddSink(new AlertHistorySink(_history));
        host.AddSink(new ToastNotifier(_tray, _config, _uiInvoker));

        host.Start();

        // Windows 11 IsPromoted fix — runs on a delay so Explorer has time to
        // create the registry entry after Visible = true.
        _promoteTimer = new System.Windows.Forms.Timer { Interval = 700 };
        int attempts = 0;
        _promoteTimer.Tick += (_, _) =>
        {
            attempts++;
            int updated = NotifyIconPromote.Promote(GetExeNameHint());
            if (updated > 0)
            {
                _logger.Info($"Tray icon promoted in registry ({updated} entries)");
                // Toggle visibility once so Explorer re-evaluates promotion
                _tray.Visible = false;
                _tray.Visible = true;
                _promoteTimer.Stop();
            }
            else if (attempts >= 10)
            {
                _promoteTimer.Stop();
            }
        };
        _promoteTimer.Start();

        _instanceTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _instanceTimer.Tick += (_, _) =>
        {
            if (_instanceSignal.WaitOne(0))
                OpenDashboard();
        };
        _instanceTimer.Start();
    }

    private static string GetExeNameHint()
    {
        // Environment.ProcessPath is single-file-safe; Assembly.Location returns
        // empty string for assemblies embedded inside a single-file bundle.
        var exe = Environment.ProcessPath ?? "WhitehatSecurity";
        return Path.GetFileNameWithoutExtension(exe);
    }

    public void OpenDashboard(string? tab = null)
    {
        if (_dashboard is null || _dashboard.IsDisposed)
        {
            _dashboard = new DashboardForm(_config, _logger, _dashboardSink, _consoleSink, _configPath, _host);
            _dashboard.FormClosed += (_, _) => _dashboard = null;
        }
        _dashboard.Show();
        if (_dashboard.WindowState == FormWindowState.Minimized)
            _dashboard.WindowState = FormWindowState.Normal;
        _dashboard.BringToFront();
        _dashboard.Activate();
        if (tab is not null) _dashboard.OpenTab(tab);
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Dashboard", null, (_, _) => OpenDashboard());
        menu.Items.Add("Alerts",         null, (_, _) => OpenDashboard("Alerts"));
        menu.Items.Add("Settings",       null, (_, _) => OpenDashboard("Settings"));
        menu.Items.Add("Logs",           null, (_, _) => OpenDashboard("Logs"));
        menu.Items.Add("Console",        null, (_, _) => OpenDashboard("Console"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) =>
        {
            _host.Stop();
            _instanceTimer.Stop();
            _promoteTimer.Stop();
            _tray.Visible = false;
            ExitThread();
        });
        return menu;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _instanceTimer.Stop();
            _instanceTimer.Dispose();
            _promoteTimer.Stop();
            _promoteTimer.Dispose();
            _dashboard?.Dispose();
            _tray.ContextMenuStrip?.Dispose();
            _tray.Dispose();
            _uiInvoker.Dispose();
        }
        base.Dispose(disposing);
    }

    /// <summary>
    /// Cached blue shield-with-checkmark icon. Built once on first access
    /// instead of every time TrayApplicationContext is constructed; this
    /// also lets us free the source HICON properly via DestroyIcon (the
    /// previous code leaked the GDI handle every time it ran because
    /// Icon.FromHandle does not release the underlying icon).
    /// </summary>
    private static readonly Icon ShieldIcon = BuildShieldIcon();

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

        // Take a copy of the bitmap into a Win32 HICON, wrap it in
        // System.Drawing.Icon, then immediately destroy the HICON. The Icon
        // object holds its own copy internally, so destroying the source is
        // safe. Without DestroyIcon every call here leaks a GDI handle.
        var hicon = bmp.GetHicon();
        try
        {
            using var temp = Icon.FromHandle(hicon);
            // Clone the icon out so the HICON can be destroyed safely.
            return (Icon)temp.Clone();
        }
        finally
        {
            NativeMethods.DestroyIcon(hicon);
        }
    }
}

/// <summary>
/// Buffers alerts in memory and exposes an event for the dashboard to wire
/// onto its ListView. Created here (not in DashboardForm) so the buffer
/// survives across dashboard open/close cycles.
///
/// Threading contract:
///   * Receive() is called from the MonitorHost background thread.
///   * AlertReceived fires synchronously on the SAME background thread —
///     handlers must marshal to the UI thread themselves before touching
///     any WinForms control (DashboardForm.OnAlertReceived does this via
///     BeginInvoke).
///   * All / Count return a snapshot under the internal lock so the UI
///     can enumerate safely while Receive is mutating the buffer.
/// </summary>
public sealed class DashboardSink : IAlertSink
{
    private readonly System.Collections.Generic.List<Alert> _buffer = new();
    private readonly object _lock = new();
    public event Action<Alert>? AlertReceived;

    /// <summary>
    /// Returns a snapshot of every buffered alert. Safe to enumerate from
    /// any thread because the snapshot is taken under the lock.
    /// </summary>
    public System.Collections.Generic.IReadOnlyList<Alert> All
    {
        get { lock (_lock) return _buffer.ToArray(); }
    }

    /// <summary>Cheap thread-safe count, no allocation.</summary>
    public int Count
    {
        get { lock (_lock) return _buffer.Count; }
    }

    public void Receive(Alert alert)
    {
        lock (_lock)
        {
            _buffer.Add(alert);
            if (_buffer.Count > 5000)
                _buffer.RemoveRange(0, _buffer.Count - 5000);
        }
        try { AlertReceived?.Invoke(alert); } catch { }
    }

    /// <summary>
    /// Pre-loads history restored from disk. Does not raise AlertReceived:
    /// these are not new events, and re-notifying about them on every
    /// startup would be worse than not keeping history at all.
    /// </summary>
    public void Seed(System.Collections.Generic.IEnumerable<Alert> alerts)
    {
        ArgumentNullException.ThrowIfNull(alerts);
        lock (_lock)
        {
            _buffer.InsertRange(0, alerts);
            if (_buffer.Count > 5000)
                _buffer.RemoveRange(0, _buffer.Count - 5000);
        }
    }

    public void Clear()
    {
        lock (_lock) _buffer.Clear();
    }
}
