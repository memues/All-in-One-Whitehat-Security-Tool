// SPDX-License-Identifier: MIT

namespace WhitehatSecurity.Core;

public static class CsvSafety
{
    /// <summary>
    /// Escapes a CSV cell and neutralizes spreadsheet formula prefixes.
    /// Alert fields can contain attacker-controlled paths, names, or text.
    /// </summary>
    public static string Escape(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > 0 && (value[0] is '=' or '+' or '-' or '@'
            || value[0] is '\t' or '\r'))
            value = "'" + value;
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }
}
