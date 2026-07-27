// SPDX-License-Identifier: MIT

using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Native;

var failures = new List<string>();

Run("ConsoleSink remains bounded and clears state", () =>
{
    var sink = new ConsoleSink();
    for (var i = 0; i < 2100; i++)
        sink.WriteLine($"line {i}");
    Equal(2000, sink.Snapshot().Count);
    Equal(100, sink.LinesDropped);
    sink.Clear();
    Equal(0, sink.Snapshot().Count);
    Equal(0, sink.LinesDropped);
});

Run("AlertThrottle validates limits", () =>
{
    Throws(() => new AlertThrottle(TimeSpan.Zero, 1));
    Throws(() => new AlertThrottle(TimeSpan.FromSeconds(1), 0));
});

Run("NotifyConfig strict loader rejects malformed JSON", () =>
{
    var path = Path.Combine(Path.GetTempPath(), $"whs-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(path, "{not-json");
        Throws(() => NotifyConfig.LoadStrict(path));
        Equal("{not-json", File.ReadAllText(path));
    }
    finally
    {
        File.Delete(path);
    }
});

Run("NotifyConfig strict loader validates DNS provider", () =>
{
    var path = Path.Combine(Path.GetTempPath(), $"whs-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(path, """{"SchemaVersion":1,"DNS_Provider":"invalid"}""");
        Throws(() => NotifyConfig.LoadStrict(path));
    }
    finally
    {
        File.Delete(path);
    }
});

Run("Catalog-signed Windows executables are trusted", () =>
{
    var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    foreach (var name in new[] { "notepad.exe", "conhost.exe" })
    {
        var path = Path.Combine(system32, name);
        if (File.Exists(path) && !AuthenticodeVerifier.IsTrusted(path))
            throw new InvalidOperationException($"{path} was reported untrusted.");
    }
});

Run("CSV export neutralizes spreadsheet formulas", () =>
{
    Equal("'=cmd|calc", CsvSafety.Escape("=cmd|calc"));
    Equal("\"safe,value\"", CsvSafety.Escape("safe,value"));
});

Run("BYOVD current scan does not suppress persistent findings", () =>
{
    var engine = new ByovdEngine();
    engine.Initialize();
    var first = engine.Scan().ToList();
    var current = engine.ScanCurrent().ToList();
    if (first.Count > 0 && current.Count == 0)
        throw new InvalidOperationException(
            "Current-state scan suppressed an existing finding.");
});

Run("RDP and Security event engines scan without throwing", () =>
{
    IMonitorEngine[] engines =
    {
        new RdpEngine(),
        new SecurityEventEngine(),
    };
    foreach (var engine in engines)
    {
        engine.Initialize();
        _ = engine.Scan().ToList();
    }
});

if (failures.Count > 0)
{
    Console.Error.WriteLine($"{failures.Count} smoke test(s) failed:");
    foreach (var failure in failures)
        Console.Error.WriteLine($"  - {failure}");
    return 1;
}

Console.WriteLine("All Whitehat Security smoke tests passed.");
return 0;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception ex)
    {
        failures.Add($"{name}: {ex.Message}");
    }
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException(
            $"Expected '{expected}', got '{actual}'.");
}

static void Throws(Action action)
{
    try
    {
        action();
    }
    catch
    {
        return;
    }
    throw new InvalidOperationException("Expected an exception.");
}
