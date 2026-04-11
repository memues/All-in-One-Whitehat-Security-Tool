// SPDX-License-Identifier: MIT
// Main dashboard window — full sidebar + 6-page layout that mirrors the
// PowerShell SecurityMonitor.ps1 dashboard one-for-one. The Designer file
// builds the static layout; this code-behind file handles the dynamic bits:
// alert receive, settings persistence, button handlers.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Ui;

public sealed partial class DashboardForm : Form
{
    private readonly NotifyConfig  _config;
    private readonly Logger        _logger;
    private readonly DashboardSink _sink;
    private readonly ConsoleSink   _consoleSink;
    private readonly string        _configPath;
    /// <summary>
    /// Live MonitorHost instance — used by the AI Threats page so a Scan
    /// Now click reuses the engines that already hold a baseline (instead
    /// of creating fresh ones every click, which produced spurious
    /// "every running process is suspicious" floods in v7.3.4).
    /// </summary>
    private readonly MonitorHost   _host;

    // Static layout pieces from the Designer file --------------------------
    private readonly ListView _alertsList   = new();
    private readonly Panel    _alertDetail  = new();
    private readonly Label    _alertDetailTitle = new();
    private readonly TextBox  _alertDetailBody  = new();
    private readonly Button   _btnIpLookup     = new();
    private readonly Button   _btnOpenLog      = new();
    private readonly Button   _btnRegedit      = new();
    private readonly Button   _btnBlockIp      = new();
    private readonly Button   _btnKillProcess  = new();
    private readonly Button   _btnRestoreReg   = new();
    private readonly TextBox  _alertSearch     = new();
    private readonly ComboBox _alertSeverityFilter = new();
    private readonly ComboBox _alertCategoryFilter = new();
    private readonly Button   _btnExportCsv    = new();
    private readonly Button   _btnExportJson   = new();
    private readonly Button   _btnClearAlerts  = new();
    /// <summary>
    /// Master list of every alert ever received in this dashboard session.
    /// The visible ListView is rebuilt from this whenever a filter changes,
    /// so filtering is cheap and order-preserving.
    /// </summary>
    private readonly List<Alert> _allAlerts = new();
    /// <summary>Sort state for the alerts ListView column-click handler.</summary>
    private int  _alertsSortColumn = 0;
    private bool _alertsSortAsc    = false;
    private readonly RichTextBox _consoleBox = new();
    private readonly CheckBox    _consoleAutoScroll   = new();
    private readonly Label       _consoleDroppedLabel = new();
    private readonly ListView _recentList     = new();

    // Stat card value labels — assigned by BuildStatusPage in the Designer.
    private Label _alertCountValue = null!;
    private Label _connCountValue  = null!;
    private Label _procCountValue  = null!;
    private Label _uptimeValue     = null!;

    private readonly Dictionary<string, CheckBox> _settingsCheckboxes = new();
    private readonly Dictionary<string, Panel>    _navPages           = new();
    private readonly Dictionary<string, Label>    _postureLabels      = new();
    private readonly ListView _aiResultsList = new();
    private readonly Label    _aiStatusLabel = new();
    private Alert? _selectedAlert;

    /// <summary>
    /// Status-page refresh timer. Stored in a field so FormClosed can stop
    /// AND dispose it. Without dispose, every dashboard open/close cycle
    /// leaks one Timer + the underlying Win32 timer handle, and after ~20
    /// cycles the form gets noticeably laggy as the leaked timers fight
    /// for the UI thread.
    /// </summary>
    private System.Windows.Forms.Timer? _statusTimer;
    /// <summary>One-shot 500 ms timer that kicks the first posture refresh.</summary>
    private System.Windows.Forms.Timer? _firstPostureKick;

    public DashboardForm(
        NotifyConfig  config,
        Logger        logger,
        DashboardSink sink,
        ConsoleSink   consoleSink,
        string        configPath,
        MonitorHost   host)
    {
        _config      = config;
        _logger      = logger;
        _sink        = sink;
        _consoleSink = consoleSink;
        _configPath  = configPath;
        _host        = host;

        InitializeComponent();
        PopulateAlertsBacklog();

        _sink.AlertReceived         += OnAlertReceived;
        _consoleSink.LineAppended   += OnConsoleLineAppended;

        // Pre-fill console with whatever was already buffered
        foreach (var line in _consoleSink.Snapshot())
            AppendConsoleLine(line);

        FormClosed += (_, _) =>
        {
            _sink.AlertReceived       -= OnAlertReceived;
            _consoleSink.LineAppended -= OnConsoleLineAppended;
        };

        // Periodic refresher for the Status page. Two separate cadences:
        //
        //   * uptime + counts on every 2 s tick (cheap, all in-process)
        //   * posture WMI queries on a background Task every 5th tick
        //     (~10 s) so the eight WMI calls never block the UI thread.
        //
        // The first posture refresh kicks off ~500 ms after the dashboard
        // appears (still on a background thread) so the dots populate
        // shortly after open without blocking the form constructor.
        _statusTimer = new System.Windows.Forms.Timer { Interval = 2000 };
        int postureTickCounter = 0;
        _statusTimer.Tick += (_, _) =>
        {
            RefreshStatusPage();
            postureTickCounter++;
            if (postureTickCounter % 5 == 0)
                BeginRefreshPostureIndicators();
        };
        _statusTimer.Start();

        // First posture refresh — fires after ~500 ms on a background
        // thread so the dashboard appears immediately and the dots populate
        // on next paint instead of blocking the form constructor on 8 WMI
        // queries (each ~200-500 ms = ~3-4 s of total UI freeze in v7.3.0).
        _firstPostureKick = new System.Windows.Forms.Timer { Interval = 500 };
        _firstPostureKick.Tick += (_, _) =>
        {
            _firstPostureKick?.Stop();
            _firstPostureKick?.Dispose();
            _firstPostureKick = null;
            BeginRefreshPostureIndicators();
        };
        _firstPostureKick.Start();

        // Final cleanup — stop AND dispose both timers so the form releases
        // every Win32 timer handle on close. Stop alone leaves the timer
        // queued in the WinForms message pump which leaks across open/close
        // cycles.
        FormClosed += (_, _) =>
        {
            _statusTimer?.Stop();
            _statusTimer?.Dispose();
            _statusTimer = null;
            _firstPostureKick?.Stop();
            _firstPostureKick?.Dispose();
            _firstPostureKick = null;
        };
    }

    /// <summary>
    /// Posture is being refreshed by a background Task — used to coalesce
    /// concurrent timer ticks so we never have two WMI scans racing.
    /// </summary>
    private int _postureRefreshing = 0;

    /// <summary>
    /// Kicks off the eight posture queries on a background Task and posts
    /// the results back via BeginInvoke. Idempotent — concurrent calls
    /// while a refresh is in flight are no-ops.
    /// </summary>
    private void BeginRefreshPostureIndicators()
    {
        if (IsDisposed) return;
        if (System.Threading.Interlocked.CompareExchange(ref _postureRefreshing, 1, 0) != 0)
            return;

        System.Threading.Tasks.Task.Run(() =>
        {
            // Run the eight queries on the background thread. Each one is
            // already wrapped in try/catch inside SecurityPosture, so we
            // never propagate.
            var snapshot = new (string Key, PostureState State)[]
            {
                ("Defender",   SecurityPosture.Defender()),
                ("Firewall",   SecurityPosture.Firewall()),
                ("UAC",        SecurityPosture.UAC()),
                ("RDP",        SecurityPosture.RdpOff()),
                ("SecureBoot", SecurityPosture.SecureBoot()),
                ("TPM",        SecurityPosture.Tpm()),
                ("HVCI",       SecurityPosture.Hvci()),
                ("BitLocker",  SecurityPosture.BitLocker()),
            };

            // Marshal back to the UI thread to update the labels.
            try
            {
                if (!IsDisposed)
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (IsDisposed) return;
                        foreach (var (key, state) in snapshot)
                            SetPosture(key, state);
                    }));
                }
            }
            catch
            {
                // form closing — drop on the floor
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _postureRefreshing, 0);
            }
        });
    }

    private void SetPosture(string key, PostureState state)
    {
        if (!_postureLabels.TryGetValue(key, out var lbl) || lbl.IsDisposed) return;
        lbl.ForeColor = state switch
        {
            PostureState.Good => Theme.PostureGood,
            PostureState.Bad  => Theme.PostureBad,
            PostureState.NA   => Theme.PostureNa,
            _                 => Theme.PostureNa,
        };
    }

    // -----------------------------------------------------------------------
    //  Alerts page wiring
    // -----------------------------------------------------------------------

    private void PopulateAlertsBacklog()
    {
        // _sink.All already returns a snapshot under DashboardSink's
        // internal lock, so we can enumerate it directly without taking
        // an external lock on the sink.
        foreach (var a in _sink.All) AppendAlertRow(a);
    }

    /// <summary>
    /// Returns true if the alert passes the current Search/Severity/Category
    /// filter. Used by both the live append path and the full rebuild after
    /// the user changes a filter.
    /// </summary>
    private bool MatchesAlertFilters(Alert a)
    {
        var sev = _alertSeverityFilter?.SelectedItem?.ToString() ?? "All";
        if (sev != "All" && !string.Equals(sev, a.Severity.ToString(), StringComparison.OrdinalIgnoreCase))
            return false;

        var cat = _alertCategoryFilter?.SelectedItem?.ToString() ?? "All";
        if (cat != "All" && !string.Equals(cat, a.Category, StringComparison.OrdinalIgnoreCase))
            return false;

        var search = _alertSearch?.Text;
        if (!string.IsNullOrWhiteSpace(search))
        {
            if ((a.Title?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) < 0
             && (a.Message?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) < 0
             && (a.Category?.IndexOf(search, StringComparison.OrdinalIgnoreCase) ?? -1) < 0)
                return false;
        }
        return true;
    }

    /// <summary>
    /// Tear down the visible ListView and rebuild it from `_allAlerts`
    /// honoring the current filter state. Cheap because the ListView only
    /// holds at most 1000 items.
    /// </summary>
    private void RefilterAlertsList()
    {
        if (_alertsList is null || _alertsList.IsDisposed) return;
        _alertsList.BeginUpdate();
        try
        {
            _alertsList.Items.Clear();
            // Newest first
            for (int i = _allAlerts.Count - 1; i >= 0; i--)
            {
                var a = _allAlerts[i];
                if (MatchesAlertFilters(a))
                    _alertsList.Items.Add(MakeAlertItem(a));
            }
        }
        finally { _alertsList.EndUpdate(); }
    }

    private ListViewItem MakeAlertItem(Alert a)
    {
        var item = new ListViewItem(a.Timestamp.ToString("HH:mm:ss"));
        item.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
        item.SubItems.Add(a.Category);
        item.SubItems.Add(a.Title);
        item.SubItems.Add(a.Message);
        item.ForeColor = Theme.SeverityColor(a.Severity);
        item.Tag = a;
        return item;
    }

    private void OnAlertSearchChanged(object? sender, EventArgs e)  => RefilterAlertsList();
    private void OnAlertFilterChanged(object? sender, EventArgs e)  => RefilterAlertsList();

    /// <summary>
    /// Column-click sort. First click ascending, second click descending,
    /// keeps the previously-selected column on subsequent clicks.
    /// </summary>
    private void OnAlertColumnClick(object? sender, ColumnClickEventArgs e)
    {
        if (e.Column == _alertsSortColumn)
            _alertsSortAsc = !_alertsSortAsc;
        else
        {
            _alertsSortColumn = e.Column;
            _alertsSortAsc = true;
        }
        var items = _alertsList.Items.Cast<ListViewItem>().ToList();
        int sortCol = _alertsSortColumn;
        items.Sort((x, y) =>
        {
            // Bounds check — if either row has fewer subitems than the
            // requested column, treat its value as empty rather than
            // throwing IndexOutOfRangeException. Without this, clicking
            // a header before any rows are populated could crash the
            // dashboard the first time a user changes sort.
            string xs = sortCol < x.SubItems.Count ? x.SubItems[sortCol].Text : "";
            string ys = sortCol < y.SubItems.Count ? y.SubItems[sortCol].Text : "";
            int cmp = string.Compare(xs, ys, StringComparison.OrdinalIgnoreCase);
            return _alertsSortAsc ? cmp : -cmp;
        });
        _alertsList.BeginUpdate();
        try
        {
            _alertsList.Items.Clear();
            foreach (var it in items) _alertsList.Items.Add(it);
        }
        finally { _alertsList.EndUpdate(); }
    }

    private void OnExportCsvClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "CSV (*.csv)|*.csv|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Timestamp,Severity,Category,Title,Message,RemoteIp,RemotePort,ProcessName,ProcessId,Path");
            foreach (var a in _allAlerts)
            {
                if (!MatchesAlertFilters(a)) continue;
                sb.Append(CsvField(a.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))).Append(',');
                sb.Append(CsvField(a.Severity.ToString())).Append(',');
                sb.Append(CsvField(a.Category)).Append(',');
                sb.Append(CsvField(a.Title)).Append(',');
                sb.Append(CsvField(a.Message)).Append(',');
                sb.Append(CsvField(a.RemoteIp ?? "")).Append(',');
                sb.Append(CsvField(a.RemotePort?.ToString() ?? "")).Append(',');
                sb.Append(CsvField(a.ProcessName ?? "")).Append(',');
                sb.Append(CsvField(a.ProcessId?.ToString() ?? "")).Append(',');
                sb.Append(CsvField(a.Path ?? "")).AppendLine();
            }
            File.WriteAllText(dlg.FileName, sb.ToString());
        }
        catch (Exception ex) { _logger.Error($"Export CSV: {ex.Message}"); }
    }

    private static string CsvField(string s)
    {
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    private void OnClearAlertsClick(object? sender, EventArgs e)
    {
        if (_allAlerts.Count == 0) return;
        var ans = MessageBox.Show(
            $"Clear all {_allAlerts.Count} alerts from the dashboard?\n\n" +
            "This only empties the in-memory list — the daily alert log on\n" +
            "disk is not touched.",
            "Clear All Alerts",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (ans != DialogResult.Yes) return;

        _allAlerts.Clear();
        _alertsList.BeginUpdate();
        try { _alertsList.Items.Clear(); }
        finally { _alertsList.EndUpdate(); }
        _recentList.Items.Clear();
        ClearAlertDetail();
    }

    private void OnAlertContextMenuOpening(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // Hide every action item, then re-show the ones that apply to the
        // currently-selected alert. Cancel the menu entirely if nothing is
        // selected so the user doesn't see an empty popup.
        if (_alertsList.SelectedItems.Count == 0 || _alertsList.SelectedItems[0].Tag is not Alert a)
        {
            e.Cancel = true;
            return;
        }
        if (_alertContextMenu is null) { e.Cancel = true; return; }
        _ctxBlockIp.Visible    = a.RemoteIp is not null;
        _ctxIpLookup.Visible   = a.RemoteIp is not null;
        _ctxKill.Visible       = a.ProcessId is int pid && pid > 0;
        _ctxOpenLog.Visible    = a.Path is not null && File.Exists(a.Path);
        _ctxRegedit.Visible    = a.Category == "Registry";
    }

    private void OnAlertCopyRowClick(object? sender, EventArgs e)
    {
        if (_alertsList.SelectedItems.Count == 0) return;
        var item = _alertsList.SelectedItems[0];
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < item.SubItems.Count; i++)
        {
            if (i > 0) sb.Append('\t');
            sb.Append(item.SubItems[i].Text);
        }
        try { Clipboard.SetText(sb.ToString()); } catch { }
    }

    private void OnAlertCopyMessageClick(object? sender, EventArgs e)
    {
        if (_alertsList.SelectedItems.Count == 0) return;
        if (_alertsList.SelectedItems[0].Tag is Alert a)
        {
            try { Clipboard.SetText(a.Message ?? ""); } catch { }
        }
    }

    // Right-click context menu controls — built in the Designer file.
    private ContextMenuStrip? _alertContextMenu;
    private ToolStripMenuItem _ctxCopyRow     = new() { Text = "Copy row" };
    private ToolStripMenuItem _ctxCopyMessage = new() { Text = "Copy message" };
    private ToolStripMenuItem _ctxIpLookup    = new() { Text = "IP lookup" };
    private ToolStripMenuItem _ctxBlockIp     = new() { Text = "Block IP" };
    private ToolStripMenuItem _ctxKill        = new() { Text = "Kill process" };
    private ToolStripMenuItem _ctxOpenLog     = new() { Text = "Open log file" };
    private ToolStripMenuItem _ctxRegedit     = new() { Text = "Open in regedit" };

    private void OnExportJsonClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "JSON (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.json",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var rows = _allAlerts.Where(MatchesAlertFilters).Select(a => new
            {
                a.Timestamp, Severity = a.Severity.ToString(), a.Category,
                a.Title, a.Message, a.RemoteIp, a.RemotePort,
                a.ProcessName, a.ProcessId, a.Path,
            });
            var json = System.Text.Json.JsonSerializer.Serialize(rows,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dlg.FileName, json);
        }
        catch (Exception ex) { _logger.Error($"Export JSON: {ex.Message}"); }
    }

    /// <summary>
    /// Cancellation source for the in-flight AI scan, if any. Stored on
    /// the form so the Cancel button can fire it from the UI thread.
    /// </summary>
    private System.Threading.CancellationTokenSource? _aiScanCts;

    /// <summary>
    /// AI Threats "Scan Now" button. Runs the three on-demand engines via
    /// MonitorHost.RunOneShotAsync against the LIVE engine instances that
    /// already hold a baseline — this avoids the v7.3.4 bug where every
    /// click recreated MemoryScannerEngine without a baseline and flooded
    /// the dashboard with one alert per running RWX-using process.
    /// </summary>
    private async void OnAiScanClick(object? sender, EventArgs e)
    {
        // If a scan is already running, the click acts as Cancel.
        if (_aiScanCts is not null)
        {
            try { _aiScanCts.Cancel(); } catch { }
            return;
        }

        _aiResultsList.Items.Clear();
        _aiStatusLabel.Text      = "Scanning...";
        _aiStatusLabel.ForeColor = Theme.Orange;

        _aiScanCts = new System.Threading.CancellationTokenSource();
        var ct     = _aiScanCts.Token;

        try
        {
            // Reuse the live MonitorHost engines (HiddenProcess, Memory,
            // BYOVD) so the scan honours each engine's baseline.
            var results = await _host.RunOneShotAsync(
                new[] { "HiddenProcess", "Memory", "BYOVD" }, ct);

            if (ct.IsCancellationRequested)
            {
                _aiStatusLabel.Text      = "Scan cancelled.";
                _aiStatusLabel.ForeColor = Theme.TextDim;
                return;
            }

            foreach (var a in results)
            {
                var item = new ListViewItem(a.Category);
                item.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
                item.SubItems.Add(a.Title);
                item.SubItems.Add(a.Message);
                item.ForeColor = Theme.SeverityColor(a.Severity);
                _aiResultsList.Items.Add(item);
            }

            _aiStatusLabel.Text = results.Count == 0
                ? "Scan complete: 0 findings."
                : $"Scan complete: {results.Count} findings.";
            _aiStatusLabel.ForeColor = results.Count == 0 ? Theme.Green : Theme.Red;
        }
        catch (OperationCanceledException)
        {
            _aiStatusLabel.Text      = "Scan cancelled.";
            _aiStatusLabel.ForeColor = Theme.TextDim;
        }
        catch (Exception ex)
        {
            _logger.Error($"AI scan failed: {ex.Message}");
            _aiStatusLabel.Text      = $"Scan failed: {ex.Message}";
            _aiStatusLabel.ForeColor = Theme.Red;
        }
        finally
        {
            try { _aiScanCts?.Dispose(); } catch { }
            _aiScanCts = null;
        }
    }

    private void OnRestoreRegistryClick(object? sender, EventArgs e)
    {
        // Restoring the previous value requires the engine to capture it at
        // baseline time, which Phase 1 of the C# port does not do. The
        // button is in the UI for parity but the action is informational
        // until the RegistryEngine is extended to capture old values.
        if (_selectedAlert is null) return;
        MessageBox.Show(
            "Registry restore is not yet wired in the C# engine — open the entry\n" +
            "in regedit and edit the value manually if needed.\n\n" +
            $"Key: {_selectedAlert.Message}",
            "Restore Registry",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void OnAlertReceived(Alert alert)
    {
        if (IsDisposed) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action<Alert>(OnAlertReceived), alert); }
            catch { /* form disposing */ }
            return;
        }
        AppendAlertRow(alert);
        RefreshStatusPage();
    }

    private void AppendAlertRow(Alert a)
    {
        // Master list keeps everything; the visible list is filter-driven.
        _allAlerts.Add(a);
        while (_allAlerts.Count > 5000)
            _allAlerts.RemoveAt(0);

        // Live insert into the visible list only if the current filters allow.
        if (MatchesAlertFilters(a))
        {
            _alertsList.Items.Insert(0, MakeAlertItem(a));
            while (_alertsList.Items.Count > 1000)
                _alertsList.Items.RemoveAt(_alertsList.Items.Count - 1);
        }

        // Mirror the most recent 10 into the Status page "Recent Alerts" list
        var recent = new ListViewItem(a.Timestamp.ToString("HH:mm:ss"));
        recent.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
        recent.SubItems.Add(a.Category);
        recent.SubItems.Add(a.Title);
        recent.ForeColor = Theme.SeverityColor(a.Severity);
        _recentList.Items.Insert(0, recent);
        while (_recentList.Items.Count > 10)
            _recentList.Items.RemoveAt(_recentList.Items.Count - 1);
    }

    private void OnAlertSelected(object? sender, EventArgs e)
    {
        if (_alertsList.SelectedItems.Count == 0) { ClearAlertDetail(); return; }
        var item = _alertsList.SelectedItems[0];
        if (item.Tag is Alert a) ShowAlertDetail(a);
    }

    private void ClearAlertDetail()
    {
        _selectedAlert = null;
        _alertDetailTitle.Text = "Select an alert to view details";
        _alertDetailTitle.ForeColor = Theme.TextDim;
        _alertDetailBody.Text = "";
        _btnIpLookup.Visible    = false;
        _btnOpenLog.Visible     = false;
        _btnRegedit.Visible     = false;
        _btnRestoreReg.Visible  = false;
        _btnBlockIp.Visible     = false;
        _btnKillProcess.Visible = false;
    }

    private void ShowAlertDetail(Alert a)
    {
        _selectedAlert = a;
        _alertDetailTitle.Text = a.Title;
        _alertDetailTitle.ForeColor = a.Severity is AlertSeverity.Crit or AlertSeverity.High
            ? Theme.SevCrit
            : Theme.AccentBlue;

        // ShowThreatDetails: when off, the title is shown but the body and
        // action buttons are hidden. The user can re-enable details from
        // Settings without needing to restart.
        bool showFull = _config.ShowThreatDetails;
        _alertDetailBody.Visible = showFull;

        if (!showFull)
        {
            _btnIpLookup.Visible    = false;
            _btnBlockIp.Visible     = false;
            _btnOpenLog.Visible     = false;
            _btnRegedit.Visible     = false;
            _btnRestoreReg.Visible  = false;
            _btnKillProcess.Visible = false;
            return;
        }

        var body = new System.Text.StringBuilder();
        body.AppendLine($"Time:     {a.Timestamp:yyyy-MM-dd HH:mm:ss}");
        body.AppendLine($"Severity: {a.Severity}");
        body.AppendLine($"Category: {a.Category}");
        body.AppendLine();
        body.AppendLine(a.Message);
        if (a.ProcessName is not null)
            body.AppendLine($"\nProcess:  {a.ProcessName} (PID {a.ProcessId})");
        if (a.RemoteIp is not null)
            body.AppendLine($"Remote:   {a.RemoteIp}:{a.RemotePort}");
        if (a.Path is not null)
            body.AppendLine($"Path:     {a.Path}");
        if (a.Extra is not null)
            foreach (var kv in a.Extra)
                body.AppendLine($"{kv.Key,-10}{kv.Value}");
        _alertDetailBody.Text = body.ToString();

        // Action button visibility
        _btnIpLookup.Visible    = a.RemoteIp is not null;
        _btnBlockIp.Visible     = a.RemoteIp is not null;
        _btnOpenLog.Visible     = a.Path is not null && File.Exists(a.Path);
        _btnRegedit.Visible     = a.Category == "Registry";
        _btnRestoreReg.Visible  = a.Category == "Registry";
        if (a.ProcessId is int pid && pid > 0)
        {
            _btnKillProcess.Visible = true;
            _btnKillProcess.Text = $"Kill PID {pid}";
        }
        else
        {
            _btnKillProcess.Visible = false;
        }
    }

    // -----------------------------------------------------------------------
    //  Alert detail action handlers
    // -----------------------------------------------------------------------

    private void OnIpLookupClick(object? sender, EventArgs e)
    {
        if (_selectedAlert?.RemoteIp is not string ip) return;
        try
        {
            Process.Start(new ProcessStartInfo("https://ipinfo.io/" + ip)
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { _logger.Error($"IP lookup: {ex.Message}"); }
    }

    private void OnOpenLogClick(object? sender, EventArgs e)
    {
        if (_selectedAlert?.Path is not string p || !File.Exists(p)) return;
        try
        {
            Process.Start(new ProcessStartInfo("notepad.exe", '"' + p + '"')
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { _logger.Error($"Open log: {ex.Message}"); }
    }

    private void OnRegeditClick(object? sender, EventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("regedit.exe") { UseShellExecute = true });
        }
        catch (Exception ex) { _logger.Error($"Regedit: {ex.Message}"); }
    }

    private void OnBlockIpClick(object? sender, EventArgs e)
    {
        if (_selectedAlert?.RemoteIp is not string ip) return;
        var result = MessageBox.Show(
            $"Block IP address {ip}?\n\nThis creates two Windows Firewall rules\n(WHS_Block_{ip}_In and _Out).\n\nA UAC prompt will appear.",
            "Block IP - Confirm",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (result != DialogResult.Yes) return;

        int rc = ElevationHelper.BlockIpAddress(ip, _logger);
        MessageBox.Show(
            rc == 0 ? $"IP {ip} blocked." : $"Failed (exit {rc}).",
            "Block IP",
            MessageBoxButtons.OK,
            rc == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Error);
    }

    private void OnKillProcessClick(object? sender, EventArgs e)
    {
        if (_selectedAlert?.ProcessId is not int pid || pid <= 0) return;
        var result = MessageBox.Show(
            $"Terminate {_selectedAlert.ProcessName ?? "?"} (PID {pid})?\n\nA UAC prompt will appear if needed.",
            "Kill Process - Confirm",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (result != DialogResult.Yes) return;

        try
        {
            Process.GetProcessById(pid).Kill();
            MessageBox.Show("Process killed.", "Kill Process", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch
        {
            int rc = ElevationHelper.KillProcessElevated(pid, _logger);
            MessageBox.Show(
                rc == 0 ? "Process killed." : $"Failed (exit {rc}).",
                "Kill Process", MessageBoxButtons.OK,
                rc == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        }
    }

    // -----------------------------------------------------------------------
    //  Settings page wiring
    // -----------------------------------------------------------------------

    /// <summary>
    /// Single CheckedChanged handler for every checkbox on the Settings page.
    /// The Tag of each checkbox holds the JSON key name; we route on that.
    /// </summary>
    private void OnSettingsCheckChanged(object? sender, EventArgs e)
    {
        if (sender is not CheckBox cb || cb.Tag is not string key) return;

        switch (key)
        {
            case "Firmware":   _config.Firmware   = cb.Checked; break;
            case "Driver":     _config.Driver     = cb.Checked; break;
            case "Service":    _config.Service    = cb.Checked; break;
            case "Connection": _config.Connection = cb.Checked; break;
            case "Process":    _config.Process    = cb.Checked; break;
            case "Listener":   _config.Listener   = cb.Checked; break;
            case "Registry":   _config.Registry   = cb.Checked; break;
            case "Security":   _config.Security   = cb.Checked; break;
            case "RDP":        _config.RDP        = cb.Checked; break;
            case "Hosts":      _config.Hosts      = cb.Checked; break;

            case "ShowThreatDetails":        _config.ShowThreatDetails        = cb.Checked; break;
            case "EnableToastNotifications": _config.EnableToastNotifications = cb.Checked; break;
            case "BeepOnAlert":              _config.BeepOnAlert              = cb.Checked; break;

            case "FW_DomainProfile":  TogglePrivileged(cb, () => _config.FW_DomainProfile  = cb.Checked,
                () => ElevationHelper.SetFirewallProfile("Domain",  cb.Checked, _logger)); break;
            case "FW_PrivateProfile": TogglePrivileged(cb, () => _config.FW_PrivateProfile = cb.Checked,
                () => ElevationHelper.SetFirewallProfile("Private", cb.Checked, _logger)); break;
            case "FW_PublicProfile":  TogglePrivileged(cb, () => _config.FW_PublicProfile  = cb.Checked,
                () => ElevationHelper.SetFirewallProfile("Public",  cb.Checked, _logger)); break;

            case "FW_BlockInbound":   TogglePrivileged(cb, () => _config.FW_BlockInbound   = cb.Checked,
                () => ElevationHelper.SetBlockInboundRule(cb.Checked, _logger)); break;
            case "FW_BlockOutbound":
                if (cb.Checked && MessageBox.Show(
                    "WARNING: This blocks ALL outgoing traffic.\nApplications may stop working. Continue?",
                    "Block Outbound", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    cb.Checked = false; return;
                }
                TogglePrivileged(cb, () => _config.FW_BlockOutbound = cb.Checked,
                    () => ElevationHelper.SetBlockOutboundRule(cb.Checked, _logger));
                break;
            case "FW_BlockPing":      TogglePrivileged(cb, () => _config.FW_BlockPing      = cb.Checked,
                () => ElevationHelper.SetBlockPingRule(cb.Checked, _logger)); break;
            case "FW_BlockLAN":
                if (cb.Checked && MessageBox.Show(
                    "WARNING: This isolates this PC from your local network. Continue?",
                    "Block LAN", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    cb.Checked = false; return;
                }
                TogglePrivileged(cb, () => _config.FW_BlockLAN = cb.Checked,
                    () => ElevationHelper.SetBlockLanRule(cb.Checked, _logger));
                break;
            case "FW_BlockDevices":   TogglePrivileged(cb, () => _config.FW_BlockDevices = cb.Checked,
                () => ElevationHelper.SetBlockDevicesRule(cb.Checked, _logger)); break;

            case "PF_BlockTrackers":  TogglePrivileged(cb, () => _config.PF_BlockTrackers  = cb.Checked,
                () => ElevationHelper.SetHostsBlocklist("Trackers", cb.Checked, _logger)); break;
            case "PF_BlockMalware":   TogglePrivileged(cb, () => _config.PF_BlockMalware   = cb.Checked,
                () => ElevationHelper.SetHostsBlocklist("Malware", cb.Checked, _logger)); break;
            case "PF_BlockTelemetry": TogglePrivileged(cb, () => _config.PF_BlockTelemetry = cb.Checked,
                () => ElevationHelper.SetHostsBlocklist("Telemetry", cb.Checked, _logger)); break;
            case "PF_BlockDNSBypass": TogglePrivileged(cb, () => _config.PF_BlockDNSBypass = cb.Checked,
                () => ElevationHelper.SetDnsBypassBlock(cb.Checked, _logger)); break;

            case "DNS_DoH": TogglePrivileged(cb, () => _config.DNS_DoH = cb.Checked,
                () => ElevationHelper.SetDnsOverHttps(cb.Checked, _config.DNS_Provider, _logger)); break;
        }

        SaveConfigSafe();
    }

    private void OnDnsProviderChanged(object? sender, EventArgs e)
    {
        if (sender is not ComboBox cmb) return;
        var picked = cmb.SelectedItem?.ToString() ?? "None";
        if (picked == _config.DNS_Provider) return;

        int rc = ElevationHelper.SetDnsProvider(picked, _logger);
        if (rc == 0)
        {
            _config.DNS_Provider = picked;
            SaveConfigSafe();
            // If DoH was enabled, re-apply with the new provider's DoH endpoint.
            if (_config.DNS_DoH)
                ElevationHelper.SetDnsOverHttps(true, picked, _logger);
        }
        else
        {
            // Revert the dropdown to the previously-applied provider so the
            // visible state matches what is actually configured on the system.
            cmb.SelectedIndexChanged -= OnDnsProviderChanged;
            cmb.SelectedItem = _config.DNS_Provider;
            cmb.SelectedIndexChanged += OnDnsProviderChanged;
        }
    }

    /// <summary>
    /// Helper that runs a privileged action via UAC, then either persists the
    /// new value or reverts the checkbox state if elevation failed.
    /// </summary>
    private void TogglePrivileged(CheckBox cb, Action persist, Func<int> action)
    {
        int rc = action();
        if (rc == 0)
        {
            persist();
            SaveConfigSafe();
        }
        else
        {
            // Revert visual state — user denied UAC, the helper failed,
            // or the elevated script returned non-zero.
            cb.CheckedChanged -= OnSettingsCheckChanged;
            cb.Checked = !cb.Checked;
            cb.CheckedChanged += OnSettingsCheckChanged;

            // Surface the failure so the user understands why the toggle
            // bounced back. Previous versions reverted silently, which made
            // it look like the checkbox was simply broken.
            string reason = rc switch
            {
                -2 => "the elevated PowerShell timed out (30 s limit).",
                -3 => "the elevation request failed (UAC declined or system error).",
                -4 => "the input value was empty or invalid.",
                -5 => "the input value was rejected as unsafe.",
                _  => $"the elevated script exited with code {rc}.",
            };
            MessageBox.Show(
                $"Could not apply '{cb.Tag}': {reason}\n\nThe checkbox has been reverted.",
                "Whitehat Security",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    // -----------------------------------------------------------------------
    //  Settings page action buttons (Reset / Export / Import)
    // -----------------------------------------------------------------------

    private void OnResetSettingsClick(object? sender, EventArgs e)
    {
        var ans = MessageBox.Show(
            "Reset every setting to its default value?\n\n" +
            "This only updates the local config file — privileged actions\n" +
            "(firewall rules, hosts blocklists, DoH endpoints) keep their\n" +
            "current state until you toggle them again.",
            "Reset Settings",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (ans != DialogResult.Yes) return;

        var fresh = NotifyConfig.Defaults();
        // Mutate _config in place so every other UI element that holds a
        // reference (the toast notifier, the alert gate via MonitorHost)
        // observes the new values immediately.
        CopyConfig(fresh, _config);
        SaveConfigSafe();
        ApplyConfigToSettingsCheckboxes();
    }

    private void OnExportSettingsClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "JSON (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Config_{DateTime.Now:yyyyMMdd_HHmmss}.json",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            _config.Save(dlg.FileName);
            MessageBox.Show("Settings exported.", "Export",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { _logger.Error($"Export settings: {ex.Message}"); }
    }

    private void OnImportSettingsClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new OpenFileDialog
            {
                Filter = "JSON (*.json)|*.json|All files (*.*)|*.*",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var loaded = NotifyConfig.LoadOrCreate(dlg.FileName);
            CopyConfig(loaded, _config);
            SaveConfigSafe();
            ApplyConfigToSettingsCheckboxes();
            MessageBox.Show("Settings imported.", "Import",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            _logger.Error($"Import settings: {ex.Message}");
            MessageBox.Show($"Import failed: {ex.Message}", "Import",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    /// <summary>
    /// Copy every settable property from <paramref name="src"/> into
    /// <paramref name="dst"/>. Used by the Reset / Import paths so the
    /// existing _config reference (held by sinks, gates, etc.) is updated
    /// in place rather than replaced.
    /// </summary>
    private static void CopyConfig(NotifyConfig src, NotifyConfig dst)
    {
        dst.SchemaVersion            = src.SchemaVersion;
        dst.Firmware                 = src.Firmware;
        dst.Driver                   = src.Driver;
        dst.Service                  = src.Service;
        dst.Connection               = src.Connection;
        dst.Process                  = src.Process;
        dst.Listener                 = src.Listener;
        dst.Registry                 = src.Registry;
        dst.Security                 = src.Security;
        dst.RDP                      = src.RDP;
        dst.Hosts                    = src.Hosts;
        dst.ShowThreatDetails        = src.ShowThreatDetails;
        dst.EnableToastNotifications = src.EnableToastNotifications;
        dst.BeepOnAlert              = src.BeepOnAlert;
        dst.FW_DomainProfile         = src.FW_DomainProfile;
        dst.FW_PrivateProfile        = src.FW_PrivateProfile;
        dst.FW_PublicProfile         = src.FW_PublicProfile;
        dst.FW_BlockInbound          = src.FW_BlockInbound;
        dst.FW_BlockOutbound         = src.FW_BlockOutbound;
        dst.FW_BlockPing             = src.FW_BlockPing;
        dst.FW_BlockLAN              = src.FW_BlockLAN;
        dst.FW_BlockDevices          = src.FW_BlockDevices;
        dst.PF_BlockTrackers         = src.PF_BlockTrackers;
        dst.PF_BlockMalware          = src.PF_BlockMalware;
        dst.PF_BlockTelemetry        = src.PF_BlockTelemetry;
        dst.PF_BlockDNSBypass        = src.PF_BlockDNSBypass;
        dst.DNS_Provider             = src.DNS_Provider;
        dst.DNS_DoH                  = src.DNS_DoH;
    }

    /// <summary>
    /// Re-sync every Settings checkbox from the live _config object.
    /// Used after Reset / Import so the visible state reflects the new
    /// values without needing to rebuild the page.
    /// </summary>
    private void ApplyConfigToSettingsCheckboxes()
    {
        foreach (var (key, cb) in _settingsCheckboxes)
        {
            // Detach + reattach so the assignment doesn't fire the change
            // handler (which would try to re-run any privileged side effect).
            cb.CheckedChanged -= OnSettingsCheckChanged;
            cb.Checked = key switch
            {
                "Firmware"                 => _config.Firmware,
                "Driver"                   => _config.Driver,
                "Service"                  => _config.Service,
                "Connection"               => _config.Connection,
                "Process"                  => _config.Process,
                "Listener"                 => _config.Listener,
                "Registry"                 => _config.Registry,
                "Security"                 => _config.Security,
                "RDP"                      => _config.RDP,
                "Hosts"                    => _config.Hosts,
                "ShowThreatDetails"        => _config.ShowThreatDetails,
                "EnableToastNotifications" => _config.EnableToastNotifications,
                "BeepOnAlert"              => _config.BeepOnAlert,
                "FW_DomainProfile"         => _config.FW_DomainProfile,
                "FW_PrivateProfile"        => _config.FW_PrivateProfile,
                "FW_PublicProfile"         => _config.FW_PublicProfile,
                "FW_BlockInbound"          => _config.FW_BlockInbound,
                "FW_BlockOutbound"         => _config.FW_BlockOutbound,
                "FW_BlockPing"             => _config.FW_BlockPing,
                "FW_BlockLAN"              => _config.FW_BlockLAN,
                "FW_BlockDevices"          => _config.FW_BlockDevices,
                "PF_BlockTrackers"         => _config.PF_BlockTrackers,
                "PF_BlockMalware"          => _config.PF_BlockMalware,
                "PF_BlockTelemetry"        => _config.PF_BlockTelemetry,
                "PF_BlockDNSBypass"        => _config.PF_BlockDNSBypass,
                "DNS_DoH"                  => _config.DNS_DoH,
                _                          => cb.Checked,
            };
            cb.CheckedChanged += OnSettingsCheckChanged;
        }
    }

    private void SaveConfigSafe()
    {
        try { _config.Save(_configPath); }
        catch (Exception ex) { _logger.Error($"Save config: {ex.Message}"); }
    }

    // -----------------------------------------------------------------------
    //  Status page refresh
    // -----------------------------------------------------------------------

    /// <summary>
    /// Cached process count, refreshed every ~6 s by RefreshStatusPage.
    /// Process.GetProcesses() allocates a Process object per kernel handle
    /// (~500 objects on a typical desktop) and cannot be made cheap, so we
    /// throttle it independently from the rest of the cards.
    /// </summary>
    private int _cachedProcessCount = 0;
    private long _lastProcessCountTick = 0;

    /// <summary>
    /// Same throttle for the active TCP connection count — IPGlobalProperties
    /// pivots through GetTcpTable which can be slow when the system has
    /// thousands of half-closed sockets.
    /// </summary>
    private int _cachedConnCount = 0;
    private long _lastConnCountTick = 0;

    private void RefreshStatusPage()
    {
        try
        {
            // _sink.Count is O(1) and lock-cheap; _sink.All would allocate
            // a snapshot array on every status refresh.
            _alertCountValue.Text = _sink.Count.ToString();

            // Only re-query the heavy counters every ~6 s. The 2 s timer
            // tick still updates uptime + alert count cheaply.
            long now = Environment.TickCount64;
            if (now - _lastConnCountTick > 6000)
            {
                try
                {
                    _cachedConnCount = System.Net.NetworkInformation.IPGlobalProperties
                        .GetIPGlobalProperties()
                        .GetActiveTcpConnections().Length;
                }
                catch { /* leave previous value */ }
                _lastConnCountTick = now;
            }
            _connCountValue.Text = _cachedConnCount.ToString();

            if (now - _lastProcessCountTick > 6000)
            {
                try
                {
                    var ps = Process.GetProcesses();
                    _cachedProcessCount = ps.Length;
                    foreach (var p in ps) p.Dispose();   // release the handles
                }
                catch { /* leave previous value */ }
                _lastProcessCountTick = now;
            }
            _procCountValue.Text = _cachedProcessCount.ToString();

            // Uptime is "time since this WhitehatSecurity process started",
            // not "time since boot". Environment.TickCount64 was wrong; use
            // the captured start time so the value matches the Started:
            // line in the info row.
            var up = DateTime.Now - Program.StartedAt;
            _uptimeValue.Text = $"{(int)up.TotalHours:D2}:{up.Minutes:D2}";
        }
        catch
        {
            // Status panel failures are cosmetic — never let them throw
        }
    }

    // -----------------------------------------------------------------------
    //  Console page refresh
    // -----------------------------------------------------------------------

    private void OnConsoleLineAppended(string line)
    {
        if (IsDisposed) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action<string>(OnConsoleLineAppended), line); }
            catch { }
            return;
        }
        AppendConsoleLine(line);
    }

    private void AppendConsoleLine(string line)
    {
        // Pick a colour based on the level marker so the user can scan
        // for warnings / errors / alerts visually instead of reading
        // every line.
        var colour = _consoleBox.ForeColor;
        if      (line.Contains("[ERROR]")) colour = Theme.Red;
        else if (line.Contains("[WARN]"))  colour = Theme.Orange;
        else if (line.Contains("[ALERT]")) colour = Theme.SevCrit;
        else if (line.Contains("[INFO]"))  colour = Theme.Green;

        int selStartBefore = _consoleBox.SelectionStart;
        int selLenBefore   = _consoleBox.SelectionLength;

        _consoleBox.SelectionStart  = _consoleBox.TextLength;
        _consoleBox.SelectionLength = 0;
        _consoleBox.SelectionColor  = colour;
        _consoleBox.AppendText(line + Environment.NewLine);
        _consoleBox.SelectionColor  = _consoleBox.ForeColor;

        if (_consoleAutoScroll.Checked)
        {
            _consoleBox.SelectionStart = _consoleBox.TextLength;
            _consoleBox.ScrollToCaret();
        }
        else
        {
            // Restore the user's caret position so the view doesn't yank.
            _consoleBox.SelectionStart  = selStartBefore;
            _consoleBox.SelectionLength = selLenBefore;
        }

        // Update the dropped-line counter so the user can see when the
        // ring buffer started evicting older lines.
        try
        {
            int dropped = _consoleSink.LinesDropped;
            _consoleDroppedLabel.Text = dropped > 0
                ? $"({dropped} line{(dropped == 1 ? "" : "s")} dropped — buffer full)"
                : "";
        }
        catch { }
    }

    private void OnClearConsoleClick(object? sender, EventArgs e)
    {
        _consoleBox.Clear();
        _consoleDroppedLabel.Text = "";
    }

    private void OnSaveConsoleClick(object? sender, EventArgs e)
    {
        try
        {
            using var dlg = new SaveFileDialog
            {
                Filter   = "Text (*.txt)|*.txt|All files (*.*)|*.*",
                FileName = $"WhitehatSecurity_Console_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            File.WriteAllText(dlg.FileName, _consoleBox.Text);
        }
        catch (Exception ex) { _logger.Error($"Save console: {ex.Message}"); }
    }

    // -----------------------------------------------------------------------
    //  Logs page file-card click handlers
    // -----------------------------------------------------------------------

    private void OnOpenFileClick(object? sender, EventArgs e)
    {
        if (sender is not Control ctl || ctl.Tag is not string path) return;
        try
        {
            if (File.Exists(path))
                Process.Start(new ProcessStartInfo("notepad.exe", '"' + path + '"') { UseShellExecute = true });
            else
                MessageBox.Show($"Not yet created:\n{path}", "Logs", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { _logger.Error($"Open log: {ex.Message}"); }
    }
}
