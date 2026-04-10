// SPDX-License-Identifier: MIT
// JSON-backed preferences. Mirrors notification_config.json from the legacy
// PowerShell port (SecurityMonitor.ps1, lines ~22-200, plus the firewall and
// DNS sections at lines ~3563-4500). Same field names so config files written
// by either implementation are interchangeable.

using System;
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
        EnableToastNotifications = true,
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
