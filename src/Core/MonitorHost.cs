// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WhitehatSecurity.Engines;

namespace WhitehatSecurity.Core;

/// <summary>
/// Owns engine baselines, the periodic scan loop, per-engine serialization,
/// throttling, and alert dispatch.
/// </summary>
public sealed class MonitorHost : IDisposable
{
    private readonly List<IMonitorEngine> _engines = new();
    private readonly List<IAlertSink> _sinks = new();
    private readonly Dictionary<IMonitorEngine, SemaphoreSlim> _engineLocks = new();
    private readonly AlertGate _gate;
    private readonly Logger _logger;
    private readonly TimeSpan _interval;
    private readonly AlertThrottle _throttle = new();
    private static readonly TimeSpan ScanBudget = TimeSpan.FromSeconds(8);

    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    public MonitorHost(NotifyConfig config, Logger logger, TimeSpan interval)
    {
        _gate = new AlertGate(config);
        _logger = logger;
        _interval = interval;
    }

    public IReadOnlyList<IMonitorEngine> Engines => _engines;
    public bool IsRunning => _loopTask is { IsCompleted: false };
    public int ThrottledCount => _throttle.DroppedCount;

    public void Register(IMonitorEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
        if (IsRunning)
            throw new InvalidOperationException(
                "Engines cannot be registered after monitoring starts.");
        _engines.Add(engine);
        _engineLocks.Add(engine, new SemaphoreSlim(1, 1));
    }

    public void AddSink(IAlertSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        _sinks.Add(sink);
    }

    public void Start()
    {
        if (IsRunning) return;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => RunLoopAsync(_cts.Token));
        _logger.Info(
            $"Monitor host started: {_engines.Count} engines, interval {_interval.TotalSeconds:F0}s");
    }

    public void Stop()
    {
        var wasRunning = IsRunning;
        try { _cts?.Cancel(); } catch { }
        try { _loopTask?.Wait(5000); } catch { }
        if (wasRunning)
            _logger.Info("Monitor host stopped");
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        foreach (var engine in _engines)
            if (engine is IDisposable disposable)
                disposable.Dispose();
        // A scan that exceeded its soft budget may still release its
        // semaphore after shutdown. Keep these tiny managed objects alive
        // until process exit rather than racing Release with Dispose.
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        foreach (var engine in _engines)
        {
            ct.ThrowIfCancellationRequested();
            var engineLock = _engineLocks[engine];
            await engineLock.WaitAsync(ct);
            try
            {
                await Task.Run(engine.Initialize, ct);
                _logger.Info($"  baseline: {engine.Name}");
            }
            catch (Exception ex)
            {
                _logger.Error(
                    $"  baseline FAILED for {engine.Name}: {ex.Message}");
            }
            finally
            {
                engineLock.Release();
            }
        }

        _logger.Info("Baselines built. Entering monitoring loop.");

        while (!ct.IsCancellationRequested)
        {
            foreach (var engine in _engines)
            {
                if (ct.IsCancellationRequested) break;
                await ScanEngineAsync(engine, ct);
            }

            try { await Task.Delay(_interval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanEngineAsync(IMonitorEngine engine, CancellationToken ct)
    {
        var engineLock = _engineLocks[engine];
        if (!await engineLock.WaitAsync(0, ct))
        {
            _logger.Warn(
                $"  previous scan still running for {engine.Name} — skipping this tick");
            return;
        }

        Task<List<Alert>> scanTask;
        try
        {
            scanTask = Task.Run(() =>
            {
                try { return engine.Scan().ToList(); }
                finally { engineLock.Release(); }
            });
        }
        catch
        {
            engineLock.Release();
            throw;
        }

        try
        {
            var budgetTask = Task.Delay(ScanBudget, ct);
            if (await Task.WhenAny(scanTask, budgetTask) == scanTask)
            {
                foreach (var alert in await scanTask)
                    Dispatch(alert);
                return;
            }

            if (!ct.IsCancellationRequested)
            {
                _logger.Warn(
                    $"  scan exceeded {ScanBudget.TotalSeconds:F0}s budget for {engine.Name} — skipping this tick");
                _ = scanTask.ContinueWith(
                    task => _logger.Error(
                        $"  late scan FAILED for {engine.Name}: {task.Exception?.GetBaseException().Message}"),
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted,
                    TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _logger.Error($"  scan FAILED for {engine.Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Runs selected live engine instances without dispatching their findings.
    /// Stateful engines can implement ICurrentStateScanner to include findings
    /// already reported by the background loop.
    /// </summary>
    public async Task<IReadOnlyList<Alert>> RunOneShotAsync(
        IEnumerable<string> engineNames,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(engineNames);
        var wanted = new HashSet<string>(
            engineNames, StringComparer.OrdinalIgnoreCase);
        var results = new List<Alert>();

        foreach (var engine in _engines)
        {
            ct.ThrowIfCancellationRequested();
            if (!wanted.Contains(engine.Name)) continue;

            var engineLock = _engineLocks[engine];
            await engineLock.WaitAsync(ct);
            try
            {
                var found = await Task.Run(
                    () => engine is ICurrentStateScanner current
                        ? current.ScanCurrent().ToList()
                        : engine.Scan().ToList(),
                    ct);
                results.AddRange(found);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.Error(
                    $"  on-demand scan FAILED for {engine.Name}: {ex.Message}");
            }
            finally
            {
                engineLock.Release();
            }
        }

        return results;
    }

    private void Dispatch(Alert alert)
    {
        if (!_gate.ShouldRaise(alert)) return;
        if (!_throttle.Allow(alert.Category)) return;

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
