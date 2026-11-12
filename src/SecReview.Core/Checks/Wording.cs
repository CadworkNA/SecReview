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
}
