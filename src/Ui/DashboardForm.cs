// SPDX-License-Identifier: MIT
// Main dashboard window. Three tabs: Alerts (live ListView), Logs (read-only
// text box of the day's monitor log), Settings (per-category checkboxes).
// Built entirely in code — no .resx, no .Designer.cs file needed.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Ui;

public sealed partial class DashboardForm : Form
{
    private readonly NotifyConfig  _config;
    private readonly Logger        _logger;
    private readonly DashboardSink _sink;

    private readonly ListView _alertsList = new();
    private readonly TextBox  _logViewer  = new();
    private readonly Dictionary<string, CheckBox> _settingsCheckboxes = new();

    public DashboardForm(NotifyConfig config, Logger logger, DashboardSink sink)
    {
        _config = config;
        _logger = logger;
        _sink   = sink;

        InitializeComponent();
        PopulateAlertsBacklog();
        _sink.AlertReceived += OnAlertReceived;

        FormClosed += (_, _) => _sink.AlertReceived -= OnAlertReceived;
    }

    private void PopulateAlertsBacklog()
    {
        lock (_sink)
        {
            foreach (var a in _sink.All) AppendAlertRow(a);
        }
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
    }

    private void AppendAlertRow(Alert a)
    {
        var item = new ListViewItem(a.Timestamp.ToString("HH:mm:ss"));
        item.SubItems.Add(a.Severity.ToString());
        item.SubItems.Add(a.Category);
        item.SubItems.Add(a.Title);
        item.SubItems.Add(a.Message);

        item.ForeColor = a.Severity switch
        {
            AlertSeverity.Crit => Color.FromArgb(255, 80, 90),
            AlertSeverity.High => Color.FromArgb(255, 170, 80),
            AlertSeverity.Med  => Color.FromArgb(120, 190, 255),
            _                  => Color.FromArgb(180, 180, 200),
        };

        _alertsList.Items.Insert(0, item);

        // Keep the list bounded so we don't leak memory on long sessions.
        while (_alertsList.Items.Count > 1000)
            _alertsList.Items.RemoveAt(_alertsList.Items.Count - 1);
    }

    private void RefreshLogViewer(object? sender, EventArgs e)
    {
        try
        {
            var logFile = Path.Combine(
                AppContext.BaseDirectory, "Logs",
                $"monitor_{DateTime.Now:yyyy-MM-dd}.log");

            _logViewer.Text = File.Exists(logFile)
                ? File.ReadAllText(logFile)
                : "(no log file yet — first scan still in progress)";
        }
        catch (Exception ex)
        {
            _logViewer.Text = $"Error reading log: {ex.Message}";
        }
    }
}
