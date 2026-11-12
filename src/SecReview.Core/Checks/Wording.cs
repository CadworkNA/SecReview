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

    /// <summary>A length of time in the largest unit that fits: "45 s", "15 min", "2 h", "3 days".</summary>
    public static string Duration(TimeSpan time)
    {
        if (time < TimeSpan.FromMinutes(1))
        {
            return $"{(long)time.TotalSeconds} s";
        }

        if (time < TimeSpan.FromHours(2))
        {
            return $"{(long)Math.Round(time.TotalMinutes)} min";
        }

        if (time < TimeSpan.FromDays(2))
        {
            return $"{(long)Math.Round(time.TotalHours)} h";
        }

        return $"{(long)Math.Floor(time.TotalDays)} days";
    }

    /// <summary>A date the same way everywhere: "12 October 2027".</summary>
    public static string Date(DateOnly date) =>
        date.ToString("d MMMM yyyy", System.Globalization.CultureInfo.InvariantCulture);
}
