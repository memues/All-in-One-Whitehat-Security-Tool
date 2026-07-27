// SPDX-License-Identifier: MIT
// JSON-backed preferences. Mirrors notification_config.json from the legacy
// PowerShell port (SecurityMonitor.ps1, lines ~22-200, plus the firewall and
// DNS sections at lines ~3563-4500). Same field names so config files written
// by either implementation are interchangeable.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WhitehatSecurity.Core;

/// <summary>
/// All 27 settings the dashboard exposes. Field names match the JSON keys
/// used by the PowerShell port one-for-one so users can carry their existing
/// configuration over.
/// </summary>
public sealed class NotifyConfig
{
    /// <summary>
    /// Schema version of the on-disk JSON. Bumped whenever a field is
    /// added/removed/renamed so a future migration step can recognise an
    /// old layout. Currently always 1; the LoadOrCreate path tolerates a
    /// missing field (treated as 1) for back-compat with v7.3.x configs
    /// that did not write this key.
    /// </summary>
    [JsonPropertyName("SchemaVersion")]
    public int SchemaVersion { get; set; } = 1;

    // ---------------- Notification categories (10) ----------------

    [JsonPropertyName("Firmware")]   public bool Firmware   { get; set; }
    [JsonPropertyName("Driver")]     public bool Driver     { get; set; }
    [JsonPropertyName("Service")]    public bool Service    { get; set; }
    /// <summary>
    /// "Unknown Network Connections". Opt-in by default — easily the noisiest
    /// category. Same default as the PS port after the hidden-juggling-puffin
    /// plan landed.
    /// </summary>
    [JsonPropertyName("Connection")] public bool Connection { get; set; }
    [JsonPropertyName("Process")]    public bool Process    { get; set; }
    [JsonPropertyName("Listener")]   public bool Listener   { get; set; }
    [JsonPropertyName("Registry")]   public bool Registry   { get; set; }
    [JsonPropertyName("Security")]   public bool Security   { get; set; }
    [JsonPropertyName("RDP")]        public bool RDP        { get; set; }
    [JsonPropertyName("Hosts")]      public bool Hosts      { get; set; }

    // ---------------- Display / behavior (3) ----------------

    [JsonPropertyName("ShowThreatDetails")]
    public bool ShowThreatDetails { get; set; }

    [JsonPropertyName("EnableToastNotifications")]
    public bool EnableToastNotifications { get; set; }

    /// <summary>System beeps on alert (3 for CRIT, 2 for HIGH, 1 for MED).</summary>
    [JsonPropertyName("BeepOnAlert")]
    public bool BeepOnAlert { get; set; }

    // ---------------- Firewall profiles (3) ----------------

    [JsonPropertyName("FW_DomainProfile")]  public bool FW_DomainProfile  { get; set; } = true;
    [JsonPropertyName("FW_PrivateProfile")] public bool FW_PrivateProfile { get; set; } = true;
    [JsonPropertyName("FW_PublicProfile")]  public bool FW_PublicProfile  { get; set; } = true;

    // ---------------- Firewall block rules (5) ----------------

    [JsonPropertyName("FW_BlockInbound")]  public bool FW_BlockInbound  { get; set; }
    [JsonPropertyName("FW_BlockOutbound")] public bool FW_BlockOutbound { get; set; }
    [JsonPropertyName("FW_BlockPing")]     public bool FW_BlockPing     { get; set; }
    [JsonPropertyName("FW_BlockLAN")]      public bool FW_BlockLAN      { get; set; }
    [JsonPropertyName("FW_BlockDevices")]  public bool FW_BlockDevices  { get; set; }

    // ---------------- Host-based protection (4) ----------------

    [JsonPropertyName("PF_BlockTrackers")]  public bool PF_BlockTrackers  { get; set; }
    [JsonPropertyName("PF_BlockMalware")]   public bool PF_BlockMalware   { get; set; }
    [JsonPropertyName("PF_BlockTelemetry")] public bool PF_BlockTelemetry { get; set; }
    [JsonPropertyName("PF_BlockDNSBypass")] public bool PF_BlockDNSBypass { get; set; }

    // ---------------- DNS (2) ----------------

    /// <summary>One of: "None", "Cloudflare", "Quad9", "Google", "OpenDNS", "AdGuard".</summary>
    [JsonPropertyName("DNS_Provider")]
    public string DNS_Provider { get; set; } = "None";

    [JsonPropertyName("DNS_DoH")]
    public bool DNS_DoH { get; set; }

    // ============================================================================
    // Defaults / lookup helpers
    // ============================================================================

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
        // Toasts are opt-in: a fresh install should be quiet. The user can
        // enable them from Settings whenever they want the popups back.
        EnableToastNotifications = false,
        BeepOnAlert              = false,
        FW_DomainProfile         = true,
        FW_PrivateProfile        = true,
        FW_PublicProfile         = true,
        FW_BlockInbound          = false,
        FW_BlockOutbound         = false,
        FW_BlockPing             = false,
        FW_BlockLAN              = false,
        FW_BlockDevices          = false,
        PF_BlockTrackers         = false,
        PF_BlockMalware          = false,
        PF_BlockTelemetry        = false,
        PF_BlockDNSBypass        = false,
        DNS_Provider             = "None",
        DNS_DoH                  = false,
    };

    /// <summary>
    /// Look up a notification category by its PowerShell key name. Returns
    /// the same "missing → default" value Test-NotifyEnabled returns in the
    /// PS port: false for "Connection", true for everything else.
    /// </summary>
    public bool IsCategoryEnabled(string category) => category switch
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
        _            => true,
    };

    public static bool DefaultForCategory(string category)
        => category != "Connection";

    // ============================================================================
    // Persistence
    // ============================================================================

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented          = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public static NotifyConfig LoadOrCreate(string path)
    {
        if (File.Exists(path))
        {
            try
            {
                var raw = File.ReadAllText(path);
                return LoadStrictJson(raw);
            }
            catch
            {
                // Malformed JSON — preserve the corrupt file as a timestamped
                // backup so the user can recover hand-edited fields, then
                // fall through to defaults. Without this the user silently
                // loses every customised setting on the next launch.
                try
                {
                    var bak = path + $".bak.{DateTime.Now:yyyyMMdd_HHmmss}";
                    File.Copy(path, bak, overwrite: true);
                }
                catch { }
            }
        }

        var fresh = Defaults();
        try { fresh.Save(path); } catch { /* best effort */ }
        return fresh;
    }

    /// <summary>
    /// Loads a configuration without modifying the source file. Import uses
    /// this path so malformed or future-schema files are never replaced with
    /// defaults and then reported as a successful import.
    /// </summary>
    public static NotifyConfig LoadStrict(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return LoadStrictJson(File.ReadAllText(path));
    }

    /// <summary>
    /// Same validation as <see cref="LoadStrict"/> but against JSON text.
    /// </summary>
    public static NotifyConfig LoadStrictJson(string raw)
    {
        var loaded = JsonSerializer.Deserialize<NotifyConfig>(raw, JsonOpts)
            ?? throw new InvalidDataException("The configuration is empty.");

        if (loaded.SchemaVersion == 0)
            loaded.SchemaVersion = 1;
        if (loaded.SchemaVersion != 1)
            throw new InvalidDataException(
                $"Unsupported configuration schema {loaded.SchemaVersion}.");
        if (!DnsConfiguration.TryNormalizeProviderName(
                loaded.DNS_Provider, out var provider))
            throw new InvalidDataException(
                $"Unknown DNS provider '{loaded.DNS_Provider}'.");
        // Store the canonical spelling so the settings combo can select it
        // and ElevationHelper can look it up.
        loaded.DNS_Provider = provider;
        if (!DnsConfiguration.SupportsDoh(provider))
            loaded.DNS_DoH = false;

        return loaded;
    }

    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // Atomic write: serialise to a .tmp sibling first, then
        // File.Move-replace into place. Without this, a crash midway
        // through File.WriteAllText would leave a half-written JSON file
        // that the next LoadOrCreate would treat as corrupt and replace
        // with defaults — losing every user setting.
        var json = JsonSerializer.Serialize(this, JsonOpts);
        var tmp  = path + ".tmp";
        File.WriteAllText(tmp, json);
        try
        {
            // .NET 8 File.Move(overwrite: true) is atomic on NTFS.
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            // Fallback for the rare filesystem where atomic Move fails:
            // fall back to a plain copy + delete. Slightly less safe but
            // still better than the original WriteAllText.
            File.Copy(tmp, path, overwrite: true);
            File.Delete(tmp);
        }
    }
}
