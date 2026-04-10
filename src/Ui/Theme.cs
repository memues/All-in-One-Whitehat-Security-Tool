// SPDX-License-Identifier: MIT
// Centralised dark-theme constants. Every ARGB value here is a 1:1 copy of
// the colors used in SecurityMonitor.ps1's dashboard (~lines 1430-2000 and
// 3300-4750). Keep them in sync if you ever tweak the visual identity.

using System.Drawing;

namespace WhitehatSecurity.Ui;

internal static class Theme
{
    // Background scale --------------------------------------------------------
    public static readonly Color Bg          = Color.FromArgb(18,  18,  28);  // main form bg
    public static readonly Color Sidebar     = Color.FromArgb(24,  24,  38);  // left rail
    public static readonly Color Card        = Color.FromArgb(30,  30,  48);  // cards / panels
    public static readonly Color CardHover   = Color.FromArgb(42,  42,  62);  // card hover state
    public static readonly Color BtnHover    = Color.FromArgb(40,  40,  65);  // button hover

    // Text scale --------------------------------------------------------------
    public static readonly Color TextMain    = Color.White;
    public static readonly Color TextDim     = Color.FromArgb(140, 140, 160);
    public static readonly Color BodyText    = Color.FromArgb(180, 180, 200);

    // Accents -----------------------------------------------------------------
    public static readonly Color Accent      = Color.FromArgb(0,   150, 255); // primary cyan
    public static readonly Color AccentDim   = Color.FromArgb(0,   90,  160);
    public static readonly Color AccentBlue  = Color.FromArgb(100, 160, 255); // listview header text
    public static readonly Color Purple      = Color.FromArgb(180, 120, 255); // AI threats accent

    // Status -----------------------------------------------------------------
    public static readonly Color Green       = Color.FromArgb(0,   200, 100);
    public static readonly Color Red         = Color.FromArgb(220, 50,  60);
    public static readonly Color Orange      = Color.FromArgb(255, 160, 40);
    public static readonly Color Yellow      = Color.FromArgb(255, 220, 100);

    // Severity colors (used in alert lists / detail panels) ------------------
    public static readonly Color SevCrit     = Color.FromArgb(255, 80,  90);
    public static readonly Color SevHigh     = Color.FromArgb(255, 170, 80);
    public static readonly Color SevMed      = Color.FromArgb(120, 190, 255);
    public static readonly Color SevInfo     = Color.FromArgb(140, 140, 160);

    // ListView painting colors -----------------------------------------------
    public static readonly Color ListHeaderBg = Color.FromArgb(22, 22, 36);
    public static readonly Color ListHeaderFg = Color.FromArgb(100, 160, 255);
    public static readonly Color ListSelBg    = Color.FromArgb(20, 60, 110);
    public static readonly Color RowBg1       = Color.FromArgb(26, 26, 42);
    public static readonly Color RowBg2       = Color.FromArgb(32, 32, 50);
    public static readonly Color Separator    = Color.FromArgb(40, 40, 60);

    // Console panel ----------------------------------------------------------
    public static readonly Color ConsoleBg    = Color.FromArgb(12, 12, 20);
    public static readonly Color ConsoleText  = Color.FromArgb(200, 200, 220);

    // Posture indicator dot colors -------------------------------------------
    public static readonly Color PostureGood  = Color.FromArgb(0, 200, 100);
    public static readonly Color PostureBad   = Color.FromArgb(220, 50, 60);
    public static readonly Color PostureNa    = Color.FromArgb(80, 80, 80);

    // Fonts ------------------------------------------------------------------
    public static Font Body(float size = 9.5f, FontStyle style = FontStyle.Regular)
        => new("Segoe UI", size, style);

    public static Font Mono(float size = 9f, FontStyle style = FontStyle.Regular)
        => new("Consolas", size, style);

    public static Font PageTitle()      => new("Segoe UI", 15, FontStyle.Bold);
    public static Font SectionTitle()   => new("Segoe UI", 11, FontStyle.Bold);
    public static Font CardLabel()      => new("Segoe UI", 7.5f, FontStyle.Bold);
    public static Font CardValue()      => new("Segoe UI", 22, FontStyle.Bold);
    public static Font NavBtn()         => new("Segoe UI", 10, FontStyle.Bold);

    // Color helper for alert severity ----------------------------------------
    public static Color SeverityColor(Core.AlertSeverity sev) => sev switch
    {
        Core.AlertSeverity.Crit => SevCrit,
        Core.AlertSeverity.High => SevHigh,
        Core.AlertSeverity.Med  => SevMed,
        _                       => SevInfo,
    };
}
