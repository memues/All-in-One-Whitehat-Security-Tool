// SPDX-License-Identifier: MIT
// Alert record + the gate that decides whether an engine's finding becomes a
// user-visible notification. Mirrors Send-Alert / Test-NotifyEnabled in
// SecurityMonitor.ps1.

using System;
using System.Collections.Generic;

namespace WhitehatSecurity.Core;

public enum AlertSeverity
{
    Info,
    Low,
    Med,
    High,
    Crit,
}

/// <summary>
/// Single finding from a monitor engine. Engines should populate every field
/// they have data for; the dashboard uses RemoteIp / Path for the
/// "click-to-look-up" actions.
/// </summary>
public sealed record Alert(
    DateTime         Timestamp,
    string           Category,    // "Connection", "Process", "Driver", etc.
    string           Title,
    string           Message,
    AlertSeverity    Severity,
    string?          ProcessName  = null,
    int?             ProcessId    = null,
    string?          RemoteIp     = null,
    int?             RemotePort   = null,
    string?          Path         = null,
    Dictionary<string, string>? Extra = null);

/// <summary>
/// Stateless gate consulted before an engine alert is dispatched.
/// </summary>
public sealed class AlertGate
{
    private readonly NotifyConfig _config;
    public AlertGate(NotifyConfig config) => _config = config;

    public bool ShouldRaise(Alert alert) => _config.IsCategoryEnabled(alert.Category);
}

/// <summary>
/// Anything that wants to receive alerts (UI list, tray balloon, log file)
/// implements this. The MonitorHost fans out each Alert to every registered
/// sink so adding a new output is one line.
/// </summary>
public interface IAlertSink
{
    void Receive(Alert alert);
}
