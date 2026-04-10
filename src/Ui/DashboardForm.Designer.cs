// SPDX-License-Identifier: MIT
// Hand-written designer file (no .resx, no Visual Studio designer).
// Builds the three-tab dashboard layout in code.

using System;
using System.Drawing;
using System.Windows.Forms;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Ui;

public sealed partial class DashboardForm
{
    private TabControl?  _tabs;
    private TabPage?     _tabAlerts;
    private TabPage?     _tabLogs;
    private TabPage?     _tabSettings;

    private static readonly Color BgDark    = Color.FromArgb(20,  20, 30);
    private static readonly Color BgPanel   = Color.FromArgb(35,  35, 50);
    private static readonly Color BgCard    = Color.FromArgb(45,  45, 65);
    private static readonly Color FgMain    = Color.White;
    private static readonly Color FgDim     = Color.FromArgb(180, 180, 200);
    private static readonly Color Accent    = Color.FromArgb(0,   180, 255);

    private void InitializeComponent()
    {
        SuspendLayout();

        // ── Form ──
        Text          = "Whitehat Security — Dashboard";
        Size          = new Size(1000, 640);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor     = BgDark;
        ForeColor     = FgMain;
        Font          = new Font("Segoe UI", 9.5f);
        MinimumSize   = new Size(720, 480);

        // ── Header banner ──
        var header = new Label
        {
            Text       = "All-in-One Whitehat Security",
            Dock       = DockStyle.Top,
            Height     = 50,
            Font       = new Font("Segoe UI", 16, FontStyle.Bold),
            ForeColor  = Accent,
            BackColor  = BgPanel,
            Padding    = new Padding(20, 10, 0, 0),
            TextAlign  = ContentAlignment.MiddleLeft,
        };
        Controls.Add(header);

        // ── TabControl ──
        _tabs = new TabControl
        {
            Dock      = DockStyle.Fill,
            BackColor = BgDark,
            ForeColor = FgMain,
            Font      = new Font("Segoe UI", 10),
            Padding   = new Point(15, 6),
        };

        _tabAlerts   = BuildAlertsTab();
        _tabLogs     = BuildLogsTab();
        _tabSettings = BuildSettingsTab();

        _tabs.TabPages.Add(_tabAlerts);
        _tabs.TabPages.Add(_tabLogs);
        _tabs.TabPages.Add(_tabSettings);
        Controls.Add(_tabs);

        ResumeLayout(false);
    }

    // ----- Alerts tab -----

    private TabPage BuildAlertsTab()
    {
        var page = new TabPage("Alerts") { BackColor = BgDark };

        _alertsList.Dock        = DockStyle.Fill;
        _alertsList.View        = View.Details;
        _alertsList.FullRowSelect = true;
        _alertsList.GridLines   = false;
        _alertsList.BackColor   = BgPanel;
        _alertsList.ForeColor   = FgMain;
        _alertsList.Font        = new Font("Consolas", 9);
        _alertsList.HeaderStyle = ColumnHeaderStyle.Nonclickable;

        _alertsList.Columns.Add("Time",     90);
        _alertsList.Columns.Add("Severity", 70);
        _alertsList.Columns.Add("Category", 110);
        _alertsList.Columns.Add("Title",    250);
        _alertsList.Columns.Add("Message",  450);

        page.Controls.Add(_alertsList);
        return page;
    }

    // ----- Logs tab -----

    private TabPage BuildLogsTab()
    {
        var page = new TabPage("Logs") { BackColor = BgDark };

        _logViewer.Dock        = DockStyle.Fill;
        _logViewer.Multiline   = true;
        _logViewer.ReadOnly    = true;
        _logViewer.ScrollBars  = ScrollBars.Vertical;
        _logViewer.BackColor   = BgPanel;
        _logViewer.ForeColor   = FgMain;
        _logViewer.Font        = new Font("Consolas", 9);
        _logViewer.WordWrap    = false;
        _logViewer.Text        = "(loading…)";

        var refreshBtn = new Button
        {
            Text       = "Refresh",
            Dock       = DockStyle.Top,
            Height     = 30,
            BackColor  = BgCard,
            ForeColor  = FgMain,
            FlatStyle  = FlatStyle.Flat,
        };
        refreshBtn.Click += RefreshLogViewer;

        page.Controls.Add(_logViewer);
        page.Controls.Add(refreshBtn);

        // Auto-refresh once when the tab is selected
        _tabs!.SelectedIndexChanged += (_, _) =>
        {
            if (_tabs.SelectedTab == page) RefreshLogViewer(null, EventArgs.Empty);
        };

        return page;
    }

    // ----- Settings tab -----

    private TabPage BuildSettingsTab()
    {
        var page = new TabPage("Settings") { BackColor = BgDark, AutoScroll = true };

        var title = new Label
        {
            Text      = "Notification Categories",
            Location  = new Point(20, 18),
            AutoSize  = true,
            Font      = new Font("Segoe UI", 12, FontStyle.Bold),
            ForeColor = Accent,
        };
        page.Controls.Add(title);

        var subtitle = new Label
        {
            Text      = "Toggle which findings raise toast notifications. Changes save instantly.",
            Location  = new Point(20, 46),
            AutoSize  = true,
            Font      = new Font("Segoe UI", 9),
            ForeColor = FgDim,
        };
        page.Controls.Add(subtitle);

        var categories = new (string Key, string Label, string Desc)[]
        {
            ("Firmware",   "Firmware Integrity Changes",   "Driver/firmware file hash modifications, deletions, new files"),
            ("Driver",     "Driver Changes",               "New drivers loaded or existing drivers removed"),
            ("Service",    "New Services",                 "Newly installed or registered Windows services"),
            ("Connection", "Unknown Network Connections",  "Outbound connections from unrecognized processes (off by default — noisy)"),
            ("Process",    "Unsigned Processes",           "New processes running without a valid digital signature"),
            ("Listener",   "New Listening Ports",          "New ports opened for incoming connections"),
            ("Registry",   "Registry Startup Key Changes", "Modifications to Run/RunOnce and tamper-protection keys"),
            ("Security",   "Security Events",              "Remote logons, failed logins, new accounts"),
            ("RDP",        "Remote Desktop (RDP) Status",  "Alert when Remote Desktop is enabled"),
            ("Hosts",      "Hosts File Modifications",     "Changes to the hosts file that could redirect DNS"),
        };

        int y = 80;
        foreach (var cat in categories)
        {
            var card = new Panel
            {
                Location = new Point(20, y),
                Size     = new Size(900, 48),
                BackColor = BgCard,
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
            };

            var cb = new CheckBox
            {
                Text      = cat.Label,
                Location  = new Point(15, 6),
                Size      = new Size(400, 20),
                Font      = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = FgMain,
                BackColor = BgCard,
                Tag       = cat.Key,
                Checked   = _config.IsCategoryEnabled(cat.Key),
            };
            cb.CheckedChanged += OnSettingsCheckChanged;
            card.Controls.Add(cb);
            _settingsCheckboxes[cat.Key] = cb;

            var desc = new Label
            {
                Text      = cat.Desc,
                Location  = new Point(35, 26),
                Size      = new Size(850, 18),
                Font      = new Font("Segoe UI", 8),
                ForeColor = FgDim,
                BackColor = BgCard,
            };
            card.Controls.Add(desc);

            page.Controls.Add(card);
            y += 56;
        }

        return page;
    }

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
        }

        try
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "notification_config.json");
            _config.Save(configPath);
        }
        catch
        {
            // ignore — settings still apply for the running session
        }
    }
}
