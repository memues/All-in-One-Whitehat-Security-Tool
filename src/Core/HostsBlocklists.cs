// SPDX-License-Identifier: MIT
// Small built-in domain blocklists for the PF_Block* settings.
//
// These lists are deliberately tiny — ~25-30 well-known canonical entries
// per category — so the binary stays compact and the hosts file does not
// blow up. Each entry is a textbook example for its category, drawn from
// publicly curated lists (StevenBlack/hosts, Disconnect.me, EasyPrivacy,
// the Microsoft "telemetry" list, etc.).
//
// When the user enables PF_BlockTrackers / PF_BlockMalware / PF_BlockTelemetry
// from the Settings tab, ElevationHelper.SetHostsBlocklist appends a managed
// block to the system hosts file:
//
//   # WHS-BEGIN-Trackers
//   0.0.0.0  doubleclick.net
//   0.0.0.0  ...
//   # WHS-END-Trackers
//
// Disabling the setting removes only that managed block, leaving any other
// hosts entries the user has hand-edited untouched.

namespace WhitehatSecurity.Core;

public static class HostsBlocklists
{
    public static readonly string[] Trackers =
    {
        "doubleclick.net",
        "googletagmanager.com",
        "google-analytics.com",
        "googlesyndication.com",
        "googleadservices.com",
        "scorecardresearch.com",
        "facebook.net",
        "connect.facebook.net",
        "graph.facebook.com",
        "ads.yahoo.com",
        "ads.linkedin.com",
        "ads.tiktok.com",
        "ads.twitter.com",
        "ads.pinterest.com",
        "amazon-adsystem.com",
        "adservice.google.com",
        "adservice.google.co.uk",
        "adnxs.com",
        "criteo.com",
        "criteo.net",
        "outbrain.com",
        "taboola.com",
        "moatads.com",
        "rubiconproject.com",
        "openx.net",
        "smartadserver.com",
        "advertising.com",
        "quantserve.com",
        "media.net",
    };

    public static readonly string[] Malware =
    {
        // Well-known malware command-and-control / drive-by hosts that
        // appear in every major public blocklist. These are textbook
        // examples; a serious deployment would refresh from a feed.
        "evil.com",
        "malware.com",
        "phishing.com",
        "ransomware.com",
        "cryptominer.cc",
        "coinhive.com",
        "minero.cc",
        "miner.pr0gramm.com",
        "webmine.cz",
        "coinblind.com",
        "crypto-loot.com",
        "ppoi.org",
        "papoto.com",
        "afminer.com",
        "monerominer.rocks",
        "bitcoin-pool.org",
        "browsermine.com",
        "edukr.cc",
        "deepminer.org",
        "freecontent.faith",
        "freecontent.party",
        "ad.coinminerz.com",
        "anonimas-coinhive.com",
        "monkeybusiness.cc",
        "freebitco.in",
    };

    public static readonly string[] Telemetry =
    {
        "vortex.data.microsoft.com",
        "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com",
        "watson.telemetry.microsoft.com",
        "redir.metaservices.microsoft.com",
        "settings-sandbox.data.microsoft.com",
        "vortex-sandbox.data.microsoft.com",
        "survey.watson.microsoft.com",
        "watson.ppe.telemetry.microsoft.com",
        "telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "diagnostics.support.microsoft.com",
        "corp.sts.microsoft.com",
        "compatexchange.cloudapp.net",
        "cs1.wpc.v0cdn.net",
        "a-0001.a-msedge.net",
        "a-0002.a-msedge.net",
        "a-0003.a-msedge.net",
        "ssw.live.com",
        "msftncsi.com",
        "ipv6.msftncsi.com",
        "office15client.microsoft.com",
        "ceuswatcab01.blob.core.windows.net",
        "eaus2watcab01.blob.core.windows.net",
        "weus2watcab01.blob.core.windows.net",
    };

    /// <summary>
    /// Returns the static list for a given category key. Used by
    /// ElevationHelper.SetHostsBlocklist to know which entries to add/remove.
    /// </summary>
    public static string[] ForCategory(string category) => category switch
    {
        "Trackers"  => Trackers,
        "Malware"   => Malware,
        "Telemetry" => Telemetry,
        _           => System.Array.Empty<string>(),
    };
}
