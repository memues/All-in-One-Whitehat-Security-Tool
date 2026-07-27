// SPDX-License-Identifier: MIT

using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Native;
using WhitehatSecurity.Ui;
using Microsoft.Win32;
using System.Diagnostics;
using System.Reflection;
using System.Windows.Forms;

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

Run("DNS provider catalog preserves both resolver addresses", () =>
{
    Equal(
        true,
        DnsConfiguration.TryGetProvider(
            "Google", out var google));
    Equal("8.8.8.8", google?.PrimaryIpv4);
    Equal("8.8.4.4", google?.SecondaryIpv4);
    Equal(
        "https://dns.google/dns-query",
        google?.DohTemplate);
    Equal(
        false,
        DnsConfiguration.TryGetProvider(
            "NotAProvider", out _));
});

Run("DNS scripts target routed adapters and roll back failures", () =>
{
    var apply = DnsConfiguration.BuildProviderScript("Google");
    Contains(
        "Get-NetRoute -AddressFamily IPv4", apply);
    Contains(
        "Restore-WhsDnsSnapshot -Snapshot $beforeApply", apply);
    Contains(
        "-ServerAddresses @('8.8.8.8','8.8.4.4')", apply);
    DoesNotContain(
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object",
        apply);

    var reset = DnsConfiguration.BuildProviderScript("None");
    Contains("-ResetServerAddresses", reset);
    Contains("Assert-WhsDnsAutomatic", reset);

    AssertPowerShellParses(apply);
    AssertPowerShellParses(reset);
});

Run("Secure DNS configures both resolvers without destructive disable", () =>
{
    var enable = DnsConfiguration.BuildDohScript(
        true, "Cloudflare");
    Contains(
        "$addresses = @('1.1.1.1','1.0.0.1')", enable);
    Contains("-AutoUpgrade $true", enable);
    Contains("DoH verification failed", enable);

    var disable = DnsConfiguration.BuildDohScript(
        false, "Cloudflare");
    Contains("-AutoUpgrade $false", disable);
    DoesNotContain(
        "Remove-DnsClientDohServerAddress", disable);

    AssertPowerShellParses(enable);
    AssertPowerShellParses(disable);
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

Run("Threat paths normalize WMI driver formats", () =>
{
    var windows = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows);
    var expected = Path.Combine(
        windows, "System32", "drivers", "example.sys");
    Equal(
        Path.GetFullPath(expected),
        ThreatPath.Normalize(
            @"\SystemRoot\System32\drivers\example.sys"));
    Equal(
        Path.GetFullPath(expected),
        ThreatPath.Normalize(
            "\"\\??\\" + expected + "\" -argument"));
    Equal<string?>(null, ThreatPath.Normalize(
        @"\Device\HarddiskVolume1\example.sys"));
});

Run("File inspection reports SHA-256 and quarantine is reversible", () =>
{
    var directory = Path.Combine(
        Path.GetTempPath(), $"whs-quarantine-test-{Guid.NewGuid():N}");
    var path = Path.Combine(directory, "sample.bin");
    Directory.CreateDirectory(directory);
    try
    {
        File.WriteAllText(path, "whitehat-quarantine-test");
        var inspection = FileInvestigator.Inspect(path);
        Equal(true, inspection.Exists);
        Equal(64, inspection.Sha256?.Length ?? 0);

        var quarantined = QuarantineManager.Quarantine(path);
        Equal(true, quarantined.Success);
        if (quarantined.Record is null)
            throw new InvalidOperationException(
                "Quarantine did not return a record.");
        Equal(false, File.Exists(path));
        Equal(true, File.Exists(
            quarantined.Record.QuarantinePath));

        var restored = QuarantineManager.Restore(
            quarantined.Record);
        Equal(true, restored.Success);
        Equal(true, File.Exists(path));
        Equal("whitehat-quarantine-test", File.ReadAllText(path));

        var quarantinedAgain =
            QuarantineManager.Quarantine(path);
        Equal(true, quarantinedAgain.Success);
        if (quarantinedAgain.Record is null)
            throw new InvalidOperationException(
                "Second quarantine did not return a record.");
        var deleted = QuarantineManager.DeletePermanently(
            quarantinedAgain.Record);
        Equal(true, deleted.Success);
        Equal(false, File.Exists(path));
        Equal(false, File.Exists(
            quarantinedAgain.Record.QuarantinePath));
    }
    finally
    {
        try { File.Delete(path); } catch { }
        try { Directory.Delete(directory); } catch { }
    }
});

Run("Registry rollback preserves value kind and rejects stale alerts", () =>
{
    var testKeyPath =
        $@"Software\WhitehatSecurity\SmokeTests\{Guid.NewGuid():N}";
    try
    {
        using var key = Registry.CurrentUser.CreateSubKey(
            testKeyPath, writable: true)
            ?? throw new InvalidOperationException(
                "Could not create HKCU test key.");
        key.SetValue("Value", 7, RegistryValueKind.DWord);
        var before = RegistryValueSnapshot.Capture(key, "Value");
        key.SetValue("Value", 9, RegistryValueKind.DWord);
        var after = RegistryValueSnapshot.Capture(key, "Value");
        var payload = new RegistryChangePayload(
            RegistryHive.CurrentUser,
            RegistryView.Registry64,
            testKeyPath,
            "Value",
            "changed",
            before,
            after);

        Equal(0, RegistryRollbackService.ApplyEncoded(
            payload.Encode()));
        Equal(7, Convert.ToInt32(key.GetValue("Value")));
        Equal(
            RegistryValueKind.DWord,
            key.GetValueKind("Value"));

        key.SetValue("Value", 11, RegistryValueKind.DWord);
        Equal(
            RegistryRollbackService.ExitConflict,
            RegistryRollbackService.ApplyEncoded(
                payload.Encode()));
        Equal(11, Convert.ToInt32(key.GetValue("Value")));

        key.SetValue("Added", "detected", RegistryValueKind.String);
        var addedAfter =
            RegistryValueSnapshot.Capture(key, "Added");
        var addedPayload = new RegistryChangePayload(
            RegistryHive.CurrentUser,
            RegistryView.Registry64,
            testKeyPath,
            "Added",
            "added",
            RegistryValueSnapshot.Missing,
            addedAfter);
        Equal(
            0,
            RegistryRollbackService.ApplyEncoded(
                addedPayload.Encode()));
        Equal(
            false,
            key.GetValueNames().Contains(
                "Added", StringComparer.OrdinalIgnoreCase));
    }
    finally
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                testKeyPath, throwOnMissingSubKey: false);
        }
        catch { }
    }
});

Run("Registry snapshots preserve binary and multi-string data", () =>
{
    var testKeyPath =
        $@"Software\WhitehatSecurity\SmokeTests\{Guid.NewGuid():N}";
    try
    {
        using var key = Registry.CurrentUser.CreateSubKey(
            testKeyPath, writable: true)
            ?? throw new InvalidOperationException(
                "Could not create HKCU test key.");
        var binary = new byte[] { 0, 1, 2, 127, 255 };
        var multi = new[] { "first", "second" };
        key.SetValue("Binary", binary, RegistryValueKind.Binary);
        key.SetValue(
            "Multi", multi, RegistryValueKind.MultiString);
        var binarySnapshot =
            RegistryValueSnapshot.Capture(key, "Binary");
        var multiSnapshot =
            RegistryValueSnapshot.Capture(key, "Multi");
        Equal(
            Convert.ToBase64String(binary),
            binarySnapshot.Data);
        Equal(
            string.Join("|", multi),
            string.Join("|", (string[])multiSnapshot.ToRegistryValue()));
    }
    finally
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                testKeyPath, throwOnMissingSubKey: false);
        }
        catch { }
    }
});

Run("Service remediation payload validation rejects path injection", () =>
{
    Equal(false, ServiceStatePayload.IsValidServiceName(
        @"service\..\other"));
    Equal(true, ServiceStatePayload.IsValidServiceName(
        "Example Service"));
    var encoded = new ServiceStatePayload(
        "Example Service", 3, true,
        @"C:\Program Files\Example\service.exe").Encode();
    Equal(true, ServiceStatePayload.TryDecode(
        encoded, out var decoded));
    Equal(3, decoded?.StartMode ?? -1);
});

Run("Alerts response controls fit the minimum dashboard size", () =>
{
    RunSta(() =>
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"whs-ui-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var filePath = Path.Combine(directory, "finding.bin");
        File.WriteAllText(filePath, "ui-layout-test");
        var logger = new Logger(directory);
        var config = NotifyConfig.Defaults();
        config.ShowThreatDetails = true;
        var sink = new DashboardSink();
        var console = new ConsoleSink();
        using var host = new MonitorHost(
            config, logger, TimeSpan.FromMinutes(1));
        using var form = new DashboardForm(
            config, logger, sink, console,
            Path.Combine(directory, "config.json"), host)
        {
            Size = new System.Drawing.Size(960, 600),
            ShowInTaskbar = false,
            Opacity = 0.01,
        };
        try
        {
            InvokePrivate(form, "ShowPage", "Alerts");
            form.Show();
            Application.DoEvents();

            var fileAlert = new Alert(
                DateTime.Now,
                "Memory",
                "TEST FILE FINDING",
                "Synthetic layout-only finding",
                AlertSeverity.High,
                Path: filePath);
            InvokePrivate(form, "ShowAlertDetail", fileAlert);
            Application.DoEvents();

            var detail = GetPrivateField<Panel>(
                form, "_alertDetail");
            var inspect = GetPrivateField<Button>(
                form, "_btnInspectThreat");
            var open = GetPrivateField<Button>(
                form, "_btnOpenLog");
            var remediate = GetPrivateField<Button>(
                form, "_btnRemediate");
            Equal(true, inspect.Visible);
            Equal(true, open.Visible);
            Equal(true, remediate.Visible);
            AssertInside(detail, inspect);
            AssertInside(detail, open);
            AssertInside(detail, remediate);

            var payload = new RegistryChangePayload(
                RegistryHive.CurrentUser,
                RegistryView.Registry64,
                @"Software\WhitehatSecurity\SmokeTests",
                "Value",
                "changed",
                new RegistryValueSnapshot(
                    true, RegistryValueKind.DWord, "0"),
                new RegistryValueSnapshot(
                    true, RegistryValueKind.DWord, "1"));
            var registryAlert = new Alert(
                DateTime.Now,
                "Registry",
                "TEST REGISTRY FINDING",
                "Synthetic layout-only finding",
                AlertSeverity.Med,
                Extra: new Dictionary<string, string>
                {
                    ["RegistryPath"] =
                        @"HKEY_CURRENT_USER\Software\WhitehatSecurity\SmokeTests",
                    [RegistryRollbackService.PayloadMetadataKey] =
                        payload.Encode(),
                });
            InvokePrivate(
                form, "ShowAlertDetail", registryAlert);
            Application.DoEvents();
            var regedit = GetPrivateField<Button>(
                form, "_btnRegedit");
            Equal(true, regedit.Visible);
            Equal("Undo Registry Change", remediate.Text);
            AssertInside(detail, regedit);
            AssertInside(detail, remediate);

            InvokePrivate(form, "ShowPage", "Settings");
            Application.DoEvents();
            var pages =
                GetPrivateField<Dictionary<string, Panel>>(
                    form, "_navPages");
            var dnsApply = GetPrivateField<Button>(
                form, "_dnsApplyButton");
            var dnsStatus = GetPrivateField<Label>(
                form, "_dnsStatusLabel");
            Equal("Apply / Repair", dnsApply.Text);
            AssertFitsWidth(pages["Settings"], dnsApply);
            AssertFitsWidth(pages["Settings"], dnsStatus);
        }
        finally
        {
            form.Close();
            try { File.Delete(filePath); } catch { }
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch { }
        }
    });
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

static void Contains(string expected, string actual)
{
    if (!actual.Contains(expected, StringComparison.Ordinal))
        throw new InvalidOperationException(
            $"Expected script to contain '{expected}'.");
}

static void DoesNotContain(string unexpected, string actual)
{
    if (actual.Contains(unexpected, StringComparison.Ordinal))
        throw new InvalidOperationException(
            $"Script unexpectedly contains '{unexpected}'.");
}

static void AssertPowerShellParses(string script)
{
    var path = Path.Combine(
        Path.GetTempPath(),
        $"whs-dns-script-{Guid.NewGuid():N}.ps1");
    try
    {
        File.WriteAllText(path, script);
        var quotedPath = path.Replace("'", "''");
        var command =
            "$path='" + quotedPath + "';" +
            "$tokens=$null;$errors=$null;" +
            "[System.Management.Automation.Language.Parser]::" +
            "ParseFile($path,[ref]$tokens,[ref]$errors)|Out-Null;" +
            "if($errors.Count){$errors|ForEach-Object{" +
            "[Console]::Error.WriteLine($_.Message)};exit 1}";
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            ArgumentList =
            {
                "-NoProfile",
                "-Command",
                command,
            },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException(
            "Could not start the PowerShell parser.");
        if (!process.WaitForExit(10_000))
        {
            try { process.Kill(); } catch { }
            throw new TimeoutException(
                "PowerShell syntax check timed out.");
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                process.StandardError.ReadToEnd());
    }
    finally
    {
        try { File.Delete(path); } catch { }
    }
}

static void RunSta(Action action)
{
    Exception? failure = null;
    var thread = new Thread(() =>
    {
        try { action(); }
        catch (Exception ex) { failure = ex; }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    if (!thread.Join(TimeSpan.FromSeconds(20)))
        throw new TimeoutException("STA UI test timed out.");
    if (failure is not null)
        throw new InvalidOperationException(
            failure.Message, failure);
}

static void InvokePrivate(
    object instance, string methodName, params object[] args)
{
    var method = instance.GetType().GetMethod(
        methodName,
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(methodName);
    try { method.Invoke(instance, args); }
    catch (TargetInvocationException ex)
    {
        throw ex.InnerException ?? ex;
    }
}

static T GetPrivateField<T>(object instance, string fieldName)
    where T : class
{
    var field = instance.GetType().GetField(
        fieldName,
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(fieldName);
    return field.GetValue(instance) as T
        ?? throw new InvalidOperationException(
            $"Field {fieldName} is not {typeof(T).Name}.");
}

static void AssertInside(Control parent, Control child)
{
    if (child.Left < 0
        || child.Top < 0
        || child.Right > parent.ClientSize.Width
        || child.Bottom > parent.ClientSize.Height)
        throw new InvalidOperationException(
            $"{child.Name}/{child.Text} is outside its parent: " +
            $"child={child.Bounds}, parent={parent.ClientSize}.");
}

static void AssertFitsWidth(Control parent, Control child)
{
    if (child.Left < 0 || child.Right > parent.ClientSize.Width)
        throw new InvalidOperationException(
            $"{child.Name}/{child.Text} exceeds its parent width: " +
            $"child={child.Bounds}, parent={parent.ClientSize}.");
}
