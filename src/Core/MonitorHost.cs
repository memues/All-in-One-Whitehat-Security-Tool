// SPDX-License-Identifier: MIT
// Background runner that owns the monitoring loop, the engines list, and the
// alert dispatch fan-out. Equivalent to the Start-Monitoring + background I/O
// runspace section of SecurityMonitor.ps1 (line ~6649 onward).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WhitehatSecurity.Engines;

namespace WhitehatSecurity.Core;

public sealed class MonitorHost : IDisposable
{
    private readonly List<IMonitorEngine> _engines = new();
    private readonly List<IAlertSink>     _sinks   = new();
    private readonly AlertGate            _gate;
    private readonly Logger               _logger;
    private readonly TimeSpan             _interval;
    private readonly AlertThrottle        _throttle = new();

    /// <summary>
    /// Per-engine soft timeout. A Scan that runs longer than this is left
    /// to finish in the background while the host moves on to the next
    /// engine, so a single hung WMI query cannot wedge the loop.
    /// </summary>
    private static readonly TimeSpan ScanBudget = TimeSpan.FromSeconds(8);

    private CancellationTokenSource? _cts;
    private Task?                    _loopTask;

    public MonitorHost(NotifyConfig config, Logger logger, TimeSpan interval)
    {
        _gate     = new AlertGate(config);
        _logger   = logger;
        _interval = interval;
    }

    public void Register(IMonitorEngine engine) => _engines.Add(engine);
    public void AddSink (IAlertSink sink)       => _sinks.Add(sink);

    /// <summary>
    /// Live engine instances — exposed so the AI Threats page can re-scan
    /// the same instances that already hold a baseline (instead of creating
    /// fresh ones every click, which was the v7.3.4 source of the "AI scan
    /// floods the dashboard with hundreds of false positives" bug).
    /// </summary>
    public IReadOnlyList<IMonitorEngine> Engines => _engines;

    public bool IsRunning => _loopTask is { IsCompleted: false };

    public void Start()
    {
        if (IsRunning) return;
        _cts      = new CancellationTokenSource();
        _loopTask = Task.Run(() => RunLoopAsync(_cts.Token));
        _logger.Info($"Monitor host started: {_engines.Count} engines, interval {_interval.TotalSeconds:F0}s");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        // Increased from 2 s → 5 s so a Scan that's mid-WMI-query has time
        // to actually finish before the host returns. The shorter wait was
        // racing the engine state and occasionally throwing
        // ObjectDisposedException on shutdown.
        try { _loopTask?.Wait(5000); } catch { }
        _logger.Info("Monitor host stopped");
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        foreach (var e in _engines)
            if (e is IDisposable d) d.Dispose();
    }

    /// <summary>
    /// Initialize-then-tick loop. On the first tick each engine builds its
    /// baseline; on every subsequent tick it diffs the live state against the
    /// baseline and yields Alert records.
    /// </summary>
    private async Task RunLoopAsync(CancellationToken ct)
    {
        // Phase 1: build baselines once
        foreach (var engine in _engines)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                engine.Initialize();
                _logger.Info($"  baseline: {engine.Name}");
            }
            catch (Exception ex)
            {
                _logger.Error($"  baseline FAILED for {engine.Name}: {ex.Message}");
            }
        }

        _logger.Info("Baselines built. Entering monitoring loop.");

        // Phase 2: scan loop
        while (!ct.IsCancellationRequested)
        {
            foreach (var engine in _engines)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    // Run the engine on the thread pool with a soft budget.
                    // If the Task does not complete in time, we log a warn
                    // and move on; the Task is left to finish in the
                    // background so the engine never observes a half-state.
                    var scanTask = Task.Run(() => engine.Scan().ToList());
                    if (scanTask.Wait(ScanBudget))
                    {
                        foreach (var alert in scanTask.Result)
                            Dispatch(alert);
                    }
                    else
                    {
                        _logger.Warn($"  scan exceeded {ScanBudget.TotalSeconds:F0}s budget for {engine.Name} — skipping this tick");
                    }
                }
                catch (AggregateException aex) when (aex.InnerException is not null)
                {
                    _logger.Error($"  scan FAILED for {engine.Name}: {aex.InnerException.Message}");
                }
                catch (Exception ex)
                {
                    _logger.Error($"  scan FAILED for {engine.Name}: {ex.Message}");
                }
            }

            try { await Task.Delay(_interval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// On-demand scan for the AI Threats page. Runs the named engines from
    /// the live engine list (so they reuse their existing baseline) and
    /// returns every alert produced. Dispatch is bypassed: the AI page
    /// shows results in its own list view, not via the alert pipeline.
    /// </summary>
    public Task<IReadOnlyList<Alert>> RunOneShotAsync(
        IEnumerable<string> engineNames,
        CancellationToken   ct = default)
    {
        var wanted = new HashSet<string>(engineNames, StringComparer.OrdinalIgnoreCase);
        return Task.Run<IReadOnlyList<Alert>>(() =>
        {
            var results = new List<Alert>();
            foreach (var engine in _engines)
            {
                if (ct.IsCancellationRequested) break;
                if (!wanted.Contains(engine.Name)) continue;
                try
                {
                    results.AddRange(engine.Scan());
                }
                catch (Exception ex)
                {
                    _logger.Error($"  on-demand scan FAILED for {engine.Name}: {ex.Message}");
                }
            }
            return results;
        }, ct);
    }

    private void Dispatch(Alert alert)
    {
        if (!_gate.ShouldRaise(alert)) return;

        // Per-category throttle — caps each category at N alerts per minute
        // so a flood from a single engine cannot drown out everything else.
        if (!_throttle.Allow(alert.Category))
        {
            // Drop silently. The throttle counts the drop so the Console
            // page can surface "X alerts throttled" if the user wants to
            // know why bursts went quiet.
            return;
        }

        _logger.Alert($"{alert.Title}: {alert.Message}");

        foreach (var sink in _sinks)
        {
            try { sink.Receive(alert); }
            catch (Exception ex)
            {
                _logger.Error($"  sink failed: {ex.Message}");
            }
        }
    }

    public int ThrottledCount => _throttle.DroppedCount;
}
