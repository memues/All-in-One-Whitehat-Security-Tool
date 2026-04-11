// SPDX-License-Identifier: MIT
// Sliding-window per-category alert rate limiter. Sits between AlertGate
// and the sink fan-out so a 1000-alert burst from a single engine cannot
// flood the dashboard, the toast surface, and the alert log all at once.
//
// The limiter is intentionally small and per-process — it does not
// persist counts across restarts. Each category gets its own bucket of
// timestamps; alerts older than the window are evicted lazily on every
// Allow() call.

using System;
using System.Collections.Generic;

namespace WhitehatSecurity.Core;

public sealed class AlertThrottle
{
    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<DateTime>> _buckets =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Window length over which AllowedPerWindow applies.</summary>
    public TimeSpan Window { get; }
    /// <summary>Maximum alerts per category per window.</summary>
    public int      AllowedPerWindow { get; }

    /// <summary>How many alerts have been silently dropped since startup.</summary>
    public int      DroppedCount { get; private set; }

    public AlertThrottle()
        : this(TimeSpan.FromMinutes(1), 60) { }

    public AlertThrottle(TimeSpan window, int allowedPerWindow)
    {
        Window           = window;
        AllowedPerWindow = allowedPerWindow;
    }

    /// <summary>
    /// Returns true if the category is still under the per-window cap.
    /// Returns false (and increments DroppedCount) if the cap is exceeded.
    /// </summary>
    public bool Allow(string category)
    {
        if (string.IsNullOrEmpty(category)) return true;

        lock (_lock)
        {
            if (!_buckets.TryGetValue(category, out var bucket))
            {
                bucket = new Queue<DateTime>();
                _buckets[category] = bucket;
            }

            var now    = DateTime.UtcNow;
            var cutoff = now - Window;

            // Evict expired timestamps. Cheap because the queue is FIFO.
            while (bucket.Count > 0 && bucket.Peek() < cutoff)
                bucket.Dequeue();

            if (bucket.Count >= AllowedPerWindow)
            {
                DroppedCount++;
                return false;
            }

            bucket.Enqueue(now);
            return true;
        }
    }
}
