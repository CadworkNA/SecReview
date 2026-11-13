namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// One firewall rule as Windows stores it: a version, then "Name=Value" fields separated by
/// "|". A field may come more than once (several ports, for example). Only what the
/// checks need is read; the rule's description and other free text are never shown.
/// </summary>
internal sealed class FirewallRuleText
{
    /// <summary>The longest stored rule read. Longer ones are not rules a person or a program wrote.</summary>
    public const int MaximumLength = 16 * 1024;

    private readonly Dictionary<string, List<string>> _fields = new(StringComparer.OrdinalIgnoreCase);

    private FirewallRuleText()
    {
    }

    /// <summary>Whether the rule is switched on.</summary>
    public bool Active => Is("Active", "TRUE");

    /// <summary>Whether it is about connections coming in.</summary>
    public bool Inbound => Is("Dir", "In");

    /// <summary>Whether it lets them through.</summary>
    public bool Allows => Is("Action", "Allow");

    /// <summary>The program the rule is for; null when it is for any program, a service or a Store app.</summary>
    public string? Program => First("App") is { Length: > 0 } app && !app.Equals("System", StringComparison.OrdinalIgnoreCase) ? app : null;

    /// <summary>The rule's name; null when Windows keeps it elsewhere ("@file,-number").</summary>
    public string? Name => First("Name") is { Length: > 0 } name && name[0] != '@' ? name : null;

    /// <summary>The rule, or null when the text is not one.</summary>
    public static FirewallRuleText? Parse(string? text)
    {
        if (text is null || text.Length > MaximumLength || text.Length < 2 || text[0] is not ('v' or 'V') || !char.IsAsciiDigit(text[1]))
        {
            return null;
        }

        var rule = new FirewallRuleText();
        foreach (string field in text.Split('|').Skip(1))
        {
            int equals = field.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            string name = field[..equals].Trim();
            if (!rule._fields.TryGetValue(name, out List<string>? values))
            {
                rule._fields[name] = values = [];
            }

            values.Add(field[(equals + 1)..].Trim());
        }

        // Every rule says which way and what to do; text without those is something else.
        return rule._fields.ContainsKey("Action") && rule._fields.ContainsKey("Dir") ? rule : null;
    }

    private string? First(string name) => _fields.TryGetValue(name, out List<string>? values) ? values[0] : null;

    private bool Is(string name, string value) => value.Equals(First(name), StringComparison.OrdinalIgnoreCase);
}
