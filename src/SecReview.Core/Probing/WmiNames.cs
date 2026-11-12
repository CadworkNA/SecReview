namespace SecReview.Probing;

/// <summary>
/// Validates the names that go into a WMI query. They become part of the query text, and a
/// namespace can name another computer, so only plain local names are accepted.
/// </summary>
internal static class WmiNames
{
    /// <summary>
    /// A namespace on this PC: "ROOT" followed by plain segments. A leading "\\computer\" would
    /// make WMI connect to another machine with the caller's credentials.
    /// </summary>
    public static bool IsLocalNamespace(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        string[] segments = text.Split('\\');
        return segments[0].Equals("ROOT", StringComparison.OrdinalIgnoreCase) && segments.All(IsIdentifier);
    }

    /// <summary>A class or property name: letters, digits and underscores only.</summary>
    public static bool IsIdentifier(string? text) =>
        !string.IsNullOrEmpty(text) && text.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
}
