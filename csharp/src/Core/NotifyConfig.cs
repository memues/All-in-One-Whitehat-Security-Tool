// SPDX-License-Identifier: MIT
// JSON-backed notification preferences. Mirrors notification_config.json
// produced by SecurityMonitor.ps1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WhitehatSecurity.Core;

/// <summary>
/// Per-category notification toggles plus a few global flags. Round-trips
/// to/from notification_config.json with the same field names as the
/// PowerShell version so the C# port and the PS port can share a config file
/// when they live next to each other.
/// </summary>
public sealed class NotifyConfig
{
    // Notification categories ------------------------------------------------

    [JsonPropertyName("Firmware")]   public bool Firmware   { get; set; }
    [JsonPropertyName("Driver")]     public bool Driver     { get; set; }
    [JsonPropertyName("Service")]    public bool Service    { get; set; }
    /// <summary>
    /// "Unknown Network Connections". Opt-in by default — this is the
    /// noisiest category and a single browser session generates dozens of
    /// alerts. Matches the PowerShell behavior change in Edit 1 of the
    /// hidden-juggling-puffin plan.
    /// </summary>
    [JsonPropertyName("Connection")] public bool Connection { get; set; }
    [JsonPropertyName("Process")]    public bool Process    { get; set; }
    [JsonPropertyName("Listener")]   public bool Listener   { get; set; }
    [JsonPropertyName("Registry")]   public bool Registry   { get; set; }
    [JsonPropertyName("Security")]   public bool Security   { get; set; }
    [JsonPropertyName("RDP")]        public bool RDP        { get; set; }
    [JsonPropertyName("Hosts")]      public bool Hosts      { get; set; }

    // Global toggles ---------------------------------------------------------

    [JsonPropertyName("ShowThreatDetails")]
    public bool ShowThreatDetails { get; set; }

    [JsonPropertyName("EnableToastNotifications")]
    public bool EnableToastNotifications { get; set; }

    /// <summary>
    /// Build the same default config that SecurityMonitor.ps1 writes on first
    /// run, with Connection = false (opt-in).
    /// </summary>
    public static NotifyConfig Defaults() => new()
    {
        Firmware                 = true,
        Driver                   = true,
        Service                  = true,
        Connection               = false,   // opt-in: too noisy out of the box
        Process                  = true,
        Listener                 = true,
        Registry                 = true,
        Security                 = true,
        RDP                      = true,
        Hosts                    = true,
        ShowThreatDetails        = false,
        EnableToastNotifications = true,
    };

    /// <summary>
    /// Look up a category by its PowerShell key name. Returns the same
    /// "missing → default" value Test-NotifyEnabled returns in the PS port:
    /// false for "Connection", true for everything else.
    /// </summary>
    public bool IsCategoryEnabled(string category)
    {
        return category switch
        {
            "Firmware"   => Firmware,
            "Driver"     => Driver,
            "Service"    => Service,
            "Connection" => Connection,
            "Process"    => Process,
            "Listener"   => Listener,
            "Registry"   => Registry,
            "Security"   => Security,
            "RDP"        => RDP,
            "Hosts"      => Hosts,
            _            => true,   // unknown categories default ON, except…
        };
    }

    /// <summary>
    /// The default value to use for a category when its key is missing from
    /// the JSON file. Mirrors the per-key fallback in Edit 4 of the
    /// hidden-juggling-puffin plan.
    /// </summary>
    public static bool DefaultForCategory(string category)
        => category != "Connection";

    // ------------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------------

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented        = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public static NotifyConfig LoadOrCreate(string path)
    {
        if (File.Exists(path))
        {
            try
            {
                var raw = File.ReadAllText(path);
                var loaded = JsonSerializer.Deserialize<NotifyConfig>(raw, JsonOpts);
                if (loaded is not null) return loaded;
            }
            catch
            {
                // fall through to defaults if the file is corrupt
            }
        }

        var fresh = Defaults();
        try { fresh.Save(path); } catch { /* best effort */ }
        return fresh;
    }

    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(this, JsonOpts);
        File.WriteAllText(path, json);
    }
}
