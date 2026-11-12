namespace SecReview.Checks;

/// <summary>Small helpers for writing result sentences.</summary>
public static class Wording
{
    /// <summary>"A", "A and B", "A, B and C".</summary>
    public static string JoinWithAnd(IReadOnlyList<string> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        return items.Count switch
        {
            0 => string.Empty,
            1 => items[0],
            2 => $"{items[0]} and {items[1]}",
            _ => $"{string.Join(", ", items.Take(items.Count - 1))} and {items[^1]}",
        };
    }

    /// <summary>"is" for one, "are" for several.</summary>
    public static string IsOrAre(int count) => count == 1 ? "is" : "are";

    /// <summary>"" for one, "s" for several.</summary>
    public static string Plural(int count) => count == 1 ? string.Empty : "s";

    /// <summary>
    /// A length of time in its two largest units, never rounded up or to a neighbour: "45 s",
    /// "15 min", "15 min 20 s", "8 h 13 min", "14 days 6 h". A time just over a limit therefore
    /// never reads as the limit itself.
    /// </summary>
    public static string Duration(TimeSpan time)
    {
        if (time < TimeSpan.Zero)
        {
            time = TimeSpan.Zero;
        }

        long days = (long)Math.Floor(time.TotalDays);
        (long Value, string Unit)[] units =
        [
            (days, days == 1 ? "day" : "days"),
            (time.Hours, "h"),
            (time.Minutes, "min"),
            (time.Seconds, "s"),
        ];

        // The largest unit that is not zero, and the next one down that is not zero either.
        string[] shown = [.. units.Where(u => u.Value > 0).Take(2).Select(u => $"{u.Value} {u.Unit}")];
        return shown.Length == 0 ? "0 s" : string.Join(' ', shown);
    }

    /// <summary>Names that keep their capital in the middle of a sentence.</summary>
    private static readonly string[] Names = ["Python", "Scoop", "Yarn", "Poetry", "Bun", "Windows", "Defender", "Microsoft"];

    /// <summary>
    /// The text with a small first letter, for use in the middle of a sentence. Left alone when
    /// its first word is an abbreviation ("TLS checks"), a name ("Python", "PyPy") or too short
    /// to tell.
    /// </summary>
    public static string LowerFirst(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        int end = 0;
        while (end < text.Length && char.IsLetterOrDigit(text[end]))
        {
            end++;
        }

        // An ordinary word has one capital, at the start; anything else is written as it must be.
        ReadOnlySpan<char> word = text.AsSpan(0, end);
        if (word.Length < 2 || !char.IsUpper(word[0]) || word[1..].ContainsAnyInRange('A', 'Z') ||
            Names.Any(name => text.AsSpan(0, end).SequenceEqual(name)))
        {
            return text;
        }

        return char.ToLowerInvariant(text[0]) + text[1..];
    }

    /// <summary>A date the same way everywhere: "12 October 2027".</summary>
    public static string Date(DateOnly date) =>
        date.ToString("d MMMM yyyy", System.Globalization.CultureInfo.InvariantCulture);
}
