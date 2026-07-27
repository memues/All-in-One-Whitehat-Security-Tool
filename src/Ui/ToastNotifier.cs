// SPDX-License-Identifier: MIT

using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Ui;

public sealed class ToastNotifier : IAlertSink
{
    private readonly NotifyIcon _trayIcon;
    private readonly NotifyConfig _config;
    private readonly Control _uiInvoker;

    public ToastNotifier(
        NotifyIcon trayIcon, NotifyConfig config, Control uiInvoker)
    {
        ArgumentNullException.ThrowIfNull(trayIcon);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(uiInvoker);
        _trayIcon = trayIcon;
        _config = config;
        _uiInvoker = uiInvoker;
    }

    public void Receive(Alert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        if (_config.BeepOnAlert)
        {
            var beeps = alert.Severity switch
            {
                AlertSeverity.Crit => 3,
                AlertSeverity.High => 2,
                AlertSeverity.Med  => 1,
                _                  => 0,
            };
            _ = Task.Run(() =>
            {
                try
                {
                    for (var i = 0; i < beeps; i++)
                    {
                        System.Media.SystemSounds.Beep.Play();
                        if (i < beeps - 1)
                            System.Threading.Thread.Sleep(180);
                    }
                }
                catch { }
            });
        }

        if (!_config.EnableToastNotifications || _uiInvoker.IsDisposed)
            return;

        try
        {
            _uiInvoker.BeginInvoke(new Action(() =>
            {
                if (_uiInvoker.IsDisposed) return;
                _trayIcon.BalloonTipIcon = alert.Severity switch
                {
                    AlertSeverity.Crit or AlertSeverity.High =>
                        ToolTipIcon.Warning,
                    AlertSeverity.Med => ToolTipIcon.Info,
                    _ => ToolTipIcon.None,
                };
                _trayIcon.BalloonTipTitle =
                    $"[{alert.Severity}] {alert.Title}";
                _trayIcon.BalloonTipText = alert.Message.Length > 200
                    ? alert.Message[..200] + "…"
                    : alert.Message;
                _trayIcon.ShowBalloonTip(8000);
            }));
        }
        catch
        {
            // The UI message pump may be shutting down.
        }
    }
}
