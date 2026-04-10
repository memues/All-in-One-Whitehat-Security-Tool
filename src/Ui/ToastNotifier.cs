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
        // Audible notification — runs even if toasts are disabled, since
        // some users want a beep without the visual popup. Severity-mapped
        // beep counts match the PowerShell port.
        if (_config.BeepOnAlert)
        {
            int beeps = alert.Severity switch
            {
                AlertSeverity.Crit => 3,
                AlertSeverity.High => 2,
                AlertSeverity.Med  => 1,
                _                  => 0,
            };
            try
            {
                for (int i = 0; i < beeps; i++)
                {
                    System.Media.SystemSounds.Beep.Play();
                    if (i < beeps - 1) System.Threading.Thread.Sleep(180);
                }
            }
            catch
            {
                // SystemSounds.Beep should always be available on a desktop
                // OS, but never let an audio failure crash the alert path.
            }
        }

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
