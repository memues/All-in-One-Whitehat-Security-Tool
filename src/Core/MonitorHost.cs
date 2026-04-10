// SPDX-License-Identifier: MIT
// Background runner that owns the monitoring loop, the engines list, and the
// alert dispatch fan-out. Equivalent to the Start-Monitoring + background I/O
// runspace section of SecurityMonitor.ps1 (line ~6649 onward).

using System;
using System.Collections.Generic;
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
        try { _loopTask?.Wait(2000); } catch { }
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
                    foreach (var alert in engine.Scan())
                        Dispatch(alert);
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

    private void Dispatch(Alert alert)
    {
        if (!_gate.ShouldRaise(alert)) return;

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
}
