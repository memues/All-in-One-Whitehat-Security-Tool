// SPDX-License-Identifier: MIT
// Wraps NotifyIcon balloon notifications. The PowerShell port also tries the
// real WinRT toast API; we keep things simple in Phase 1 and use the legacy
// balloon path which is universally supported back to Windows 7.

using System;
using System.Windows.Forms;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Ui;

public sealed class ToastNotifier : IAlertSink
{
    private readonly NotifyIcon   _trayIcon;
    private readonly NotifyConfig _config;

    public ToastNotifier(NotifyIcon trayIcon, NotifyConfig config)
    {
        _trayIcon = trayIcon;
        _config   = config;
    }

    public void Receive(Alert alert)
    {
        if (!_config.EnableToastNotifications) return;

        try
        {
            _trayIcon.BalloonTipIcon  = alert.Severity switch
            {
                AlertSeverity.Crit or AlertSeverity.High => ToolTipIcon.Warning,
                AlertSeverity.Med                        => ToolTipIcon.Info,
                _                                        => ToolTipIcon.None,
            };
            _trayIcon.BalloonTipTitle = $"[{alert.Severity}] {alert.Title}";
            _trayIcon.BalloonTipText  = alert.Message.Length > 200
                ? alert.Message[..200] + "…"
                : alert.Message;
            _trayIcon.ShowBalloonTip(8000);
        }
        catch
        {
            // tray might be gone if the form is closing — ignore
        }
    }
}
