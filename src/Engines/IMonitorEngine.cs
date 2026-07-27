// SPDX-License-Identifier: MIT
// Contract for a single monitoring engine. The MonitorHost calls Initialize()
// once at startup to build the baseline, then Scan() on every tick to diff the
// current state against that baseline. Engines are stateful by design — each
// one owns its own snapshot of "what the system looked like last time".
//
// Threading contract:
//   * Initialize() and Scan() are always called from the MonitorHost
//     background thread (never the UI thread).
//   * Scan() should return reasonably quickly (under ~5 s). MonitorHost
//     wraps each Scan call in a bounded Task so a stuck engine cannot
//     wedge the entire scan loop, but a long-running engine still wastes
//     a thread-pool slot until it finishes naturally.
//   * Engines must be reentrant-safe across Initialize → Scan → Scan,
//     but never observe two concurrent Scan calls on the same instance.

using System.Collections.Generic;
using WhitehatSecurity.Core;

namespace WhitehatSecurity.Engines;

public interface IMonitorEngine
{
    /// <summary>Display name for logs and the dashboard.</summary>
    string Name { get; }

    /// <summary>
    /// Build the initial baseline. Called once before the scan loop starts.
    /// Allowed to take a few seconds (driver enumeration is slow).
    /// </summary>
    void Initialize();

    /// <summary>
    /// Compare current state to the cached baseline. Returns one Alert per
    /// finding. Should be fast — runs on every tick.
    /// </summary>
    IEnumerable<Alert> Scan();
}

/// <summary>
/// Optional contract for engines whose background Scan suppresses duplicate
/// alerts. On-demand scans use this to report findings that are present now,
/// even when the background loop already raised them.
/// </summary>
public interface ICurrentStateScanner
{
    IEnumerable<Alert> ScanCurrent();
}
