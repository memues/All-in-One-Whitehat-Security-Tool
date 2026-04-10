// SPDX-License-Identifier: MIT
// Contract for a single monitoring engine. The MonitorHost calls Initialize()
// once at startup to build the baseline, then Scan() on every tick to diff the
// current state against that baseline. Engines are stateful by design — each
// one owns its own snapshot of "what the system looked like last time".

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
