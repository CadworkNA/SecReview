using System.Globalization;
using System.Text.RegularExpressions;

namespace SecReview.SupplyChain;

/// <summary>How a "do not install anything newer than" setting was written.</summary>
public enum CooldownKind
{
    /// <summary>Not a value the tool would understand.</summary>
    Invalid = 0,

    /// <summary>A length of time before now ("7 days"): it moves with the calendar, which is what a cooldown needs.</summary>
    Relative,

    /// <summary>A fixed date: it protects today and goes stale tomorrow.</summary>
    AbsoluteDate,

    /// <summary>Explicitly switched off.</summary>
    Disabled,
}

/// <summary>A cooldown setting, read.</summary>
/// <param name="Kind">How it was written.</param>
/// <param name="Length">The length of time, for <see cref="CooldownKind.Relative"/>.</param>
public readonly record struct Cooldown(CooldownKind Kind, TimeSpan Length = default)
{
    public static Cooldown Invalid => new(CooldownKind.Invalid);
}

/// <summary>
/// Reads the lengths of time that package managers accept for their release cooldown. Each
/// tool has its own notation; a value the tool itself would refuse reads as invalid here too.
/// </summary>
public static partial class Durations
{
    /// <summary>The cooldown every check asks for.</summary>
    public static readonly TimeSpan Week = TimeSpan.FromDays(7);

    /// <summary>
    /// uv's <c>exclude-newer</c>: a "friendly" length ("7 days", "1 week", "24 hours", "3d"), an
    /// ISO 8601 length ("P7D", "PT48H"), a date or date with time (absolute), or false. Months
    /// and years are not accepted by uv, because their length varies.
    /// </summary>
    public static Cooldown ParseUv(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return Cooldown.Invalid;
        }

        string value = text.Trim();
        if (value.Equals("false", StringComparison.OrdinalIgnoreCase))
        {
            return new Cooldown(CooldownKind.Disabled);
        }

        if (AbsoluteDate().IsMatch(value))
        {
            return new Cooldown(CooldownKind.AbsoluteDate);
        }

        return ParseIso8601(value) ?? ParseFriendly(value) ?? Cooldown.Invalid;
    }

    /// <summary>pip's <c>uploaded-prior-to</c>: an ISO 8601 length in days ("P7D"), or a date (absolute).</summary>
    public static Cooldown ParsePip(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return Cooldown.Invalid;
        }

        string value = text.Trim();
        return AbsoluteDate().IsMatch(value)
            ? new Cooldown(CooldownKind.AbsoluteDate)
            : ParseIso8601(value) ?? Cooldown.Invalid;
    }

    /// <summary>
    /// A number with an optional unit letter, as Yarn ("7d", "168h"; a bare number is minutes)
    /// and PDM ("7d") write it.
    /// </summary>
    /// <param name="text">The value.</param>
    /// <param name="bareNumberUnit">What a number without a unit means; null if the tool does not accept one.</param>
    public static Cooldown ParseShort(string? text, TimeSpan? bareNumberUnit)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return Cooldown.Invalid;
        }

        Match match = ShortForm().Match(text.Trim());
        if (!match.Success || !TryNumber(match.Groups["n"].Value, out double number))
        {
            return Cooldown.Invalid;
        }

        TimeSpan? unit = match.Groups["u"].Value.ToLowerInvariant() switch
        {
            "" => bareNumberUnit,
            "ms" => TimeSpan.FromMilliseconds(1),
            "s" => TimeSpan.FromSeconds(1),
            "m" => TimeSpan.FromMinutes(1),
            "h" => TimeSpan.FromHours(1),
            "d" => TimeSpan.FromDays(1),
            "w" => TimeSpan.FromDays(7),
            _ => null,
        };

        return unit is { } one ? Relative(number, one) : Cooldown.Invalid;
    }

    /// <summary>A plain number in a fixed unit, as npm (days), pnpm (minutes), Bun (seconds) and Poetry (days) write it.</summary>
    public static Cooldown FromNumber(long number, TimeSpan unit) =>
        number < 0 ? Cooldown.Invalid : Relative(number, unit);

    private static Cooldown Relative(double number, TimeSpan unit)
    {
        double seconds = number * unit.TotalSeconds;
        return seconds is >= 0 and < 3_153_600_000 // a century
            ? new Cooldown(CooldownKind.Relative, TimeSpan.FromSeconds(seconds))
            : Cooldown.Invalid;
    }

    private static bool TryNumber(string text, out double number) =>
        double.TryParse(text, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out number);

    /// <summary>"P7D", "P1W", "PT48H", "P1DT12H": weeks, days, hours, minutes and seconds only.</summary>
    private static Cooldown? ParseIso8601(string value)
    {
        Match match = Iso8601().Match(value);
        if (!match.Success || (match.Groups["w"].Length + match.Groups["d"].Length + match.Groups["h"].Length +
                match.Groups["m"].Length + match.Groups["s"].Length) == 0)
        {
            return null;
        }

        double seconds = 0;
        foreach ((string group, double unit) in new[] { ("w", 604800d), ("d", 86400d), ("h", 3600d), ("m", 60d), ("s", 1d) })
        {
            if (match.Groups[group].Length > 0)
            {
                if (!TryNumber(match.Groups[group].Value, out double number))
                {
                    return Cooldown.Invalid;
                }

                seconds += number * unit;
            }
        }

        return Relative(seconds, TimeSpan.FromSeconds(1));
    }

    /// <summary>"7 days", "1 week", "24 hours", "36h", "1 week 2 days": one or more number-and-unit pairs.</summary>
    private static Cooldown? ParseFriendly(string value)
    {
        MatchCollection parts = FriendlyPart().Matches(value);
        if (parts.Count == 0 || string.Concat(parts.Select(p => p.Value)).Length != value.Length)
        {
            return null;
        }

        double seconds = 0;
        foreach (Match part in parts)
        {
            if (!TryNumber(part.Groups["n"].Value, out double number))
            {
                return Cooldown.Invalid;
            }

            double? unit = part.Groups["u"].Value.ToLowerInvariant() switch
            {
                "w" or "wk" or "wks" or "week" or "weeks" => 604800,
                "d" or "day" or "days" => 86400,
                "h" or "hr" or "hrs" or "hour" or "hours" => 3600,
                "m" or "min" or "mins" or "minute" or "minutes" => 60,
                "s" or "sec" or "secs" or "second" or "seconds" => 1,
                _ => null, // months and years are refused: their length varies
            };
            if (unit is null)
            {
                return Cooldown.Invalid;
            }

            seconds += number * unit.Value;
        }

        return Relative(seconds, TimeSpan.FromSeconds(1));
    }

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:?\d{2})?)?$", RegexOptions.CultureInvariant, 250)]
    private static partial Regex AbsoluteDate();

    [GeneratedRegex(
        @"^P(?:(?<w>\d+(?:\.\d+)?)W)?(?:(?<d>\d+(?:\.\d+)?)D)?(?:T(?:(?<h>\d+(?:\.\d+)?)H)?(?:(?<m>\d+(?:\.\d+)?)M)?(?:(?<s>\d+(?:\.\d+)?)S)?)?$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
        250)]
    private static partial Regex Iso8601();

    [GeneratedRegex(@"\s*(?<n>\d+(?:\.\d+)?)\s*(?<u>[A-Za-z]+)\s*,?", RegexOptions.CultureInvariant, 250)]
    private static partial Regex FriendlyPart();

    [GeneratedRegex(@"^(?<n>\d+(?:\.\d+)?)\s*(?<u>[A-Za-z]*)$", RegexOptions.CultureInvariant, 250)]
    private static partial Regex ShortForm();
}
