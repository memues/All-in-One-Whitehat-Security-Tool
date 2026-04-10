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
    private readonly RichTextBox _consoleBox = new();
    private readonly ListView _recentList     = new();

    // Stat card value labels — assigned by BuildStatusPage in the Designer.
    private Label _alertCountValue = null!;
    private Label _connCountValue  = null!;
    private Label _procCountValue  = null!;
    private Label _uptimeValue     = null!;

    private readonly Dictionary<string, CheckBox> _settingsCheckboxes = new();
    private readonly Dictionary<string, Panel>    _navPages           = new();
    private Alert? _selectedAlert;

    public DashboardForm(
        NotifyConfig  config,
        Logger        logger,
        DashboardSink sink,
        ConsoleSink   consoleSink,
        string        configPath)
    {
        _config      = config;
        _logger      = logger;
        _sink        = sink;
        _consoleSink = consoleSink;
        _configPath  = configPath;

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

        // Periodic refresher for the Status page (uptime + counts)
        var statusTimer = new System.Windows.Forms.Timer { Interval = 2000 };
        statusTimer.Tick += (_, _) => RefreshStatusPage();
        statusTimer.Start();
        FormClosed += (_, _) => statusTimer.Stop();
    }

    // -----------------------------------------------------------------------
    //  Alerts page wiring
    // -----------------------------------------------------------------------

    private void PopulateAlertsBacklog()
    {
        lock (_sink)
            foreach (var a in _sink.All) AppendAlertRow(a);
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
        var item = new ListViewItem(a.Timestamp.ToString("HH:mm:ss"));
        item.SubItems.Add(a.Severity.ToString().ToUpperInvariant());
        item.SubItems.Add(a.Category);
        item.SubItems.Add(a.Title);
        item.SubItems.Add(a.Message);
        item.ForeColor = Theme.SeverityColor(a.Severity);
        item.Tag = a;

        _alertsList.Items.Insert(0, item);
        while (_alertsList.Items.Count > 1000)
            _alertsList.Items.RemoveAt(_alertsList.Items.Count - 1);

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
        _btnIpLookup.Visible = false;
        _btnOpenLog.Visible  = false;
        _btnRegedit.Visible  = false;
        _btnBlockIp.Visible  = false;
        _btnKillProcess.Visible = false;
    }

    private void ShowAlertDetail(Alert a)
    {
        _selectedAlert = a;
        _alertDetailTitle.Text = a.Title;
        _alertDetailTitle.ForeColor = a.Severity is AlertSeverity.Crit or AlertSeverity.High
            ? Theme.SevCrit
            : Theme.AccentBlue;

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
        _btnIpLookup.Visible = a.RemoteIp is not null;
        _btnBlockIp.Visible  = a.RemoteIp is not null;
        _btnOpenLog.Visible  = a.Path is not null && File.Exists(a.Path);
        _btnRegedit.Visible  = a.Category == "Registry";
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
                _config.FW_BlockLAN = cb.Checked; break;
            case "FW_BlockDevices":   _config.FW_BlockDevices   = cb.Checked; break;

            case "PF_BlockTrackers":  _config.PF_BlockTrackers  = cb.Checked; break;
            case "PF_BlockMalware":   _config.PF_BlockMalware   = cb.Checked; break;
            case "PF_BlockTelemetry": _config.PF_BlockTelemetry = cb.Checked; break;
            case "PF_BlockDNSBypass": _config.PF_BlockDNSBypass = cb.Checked; break;

            case "DNS_DoH":           _config.DNS_DoH           = cb.Checked; break;
        }

        SaveConfigSafe();
    }

    private void OnDnsProviderChanged(object? sender, EventArgs e)
    {
        if (sender is not ComboBox cmb) return;
        _config.DNS_Provider = cmb.SelectedItem?.ToString() ?? "None";
        // Best-effort apply through elevation
        ElevationHelper.SetDnsProvider(_config.DNS_Provider, _logger);
        SaveConfigSafe();
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
            // revert visual state
            cb.CheckedChanged -= OnSettingsCheckChanged;
            cb.Checked = !cb.Checked;
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

    private void RefreshStatusPage()
    {
        try
        {
            _alertCountValue.Text = _sink.All.Count.ToString();
            _connCountValue.Text  = System.Net.NetworkInformation.IPGlobalProperties
                .GetIPGlobalProperties()
                .GetActiveTcpConnections().Length.ToString();
            _procCountValue.Text  = Process.GetProcesses().Length.ToString();
            var up = TimeSpan.FromMilliseconds(Environment.TickCount64);
            _uptimeValue.Text     = $"{(int)up.TotalHours:D2}:{up.Minutes:D2}";
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
        _consoleBox.AppendText(line + Environment.NewLine);
        _consoleBox.SelectionStart = _consoleBox.TextLength;
        _consoleBox.ScrollToCaret();
    }

    private void OnClearConsoleClick(object? sender, EventArgs e)
        => _consoleBox.Clear();

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
