using System.Globalization;

namespace SecReview.SupplyChain;

/// <summary>
/// A tool's version as "major.minor.patch". Anything after the numbers (a pre-release or
/// build label) is ignored, which is right for the question asked here: "is this at least the
/// version that brought a setting?".
/// </summary>
public readonly record struct ToolVersion(int Major, int Minor = 0, int Patch = 0) : IComparable<ToolVersion>
{
    /// <summary>Reads "12.19.0", "v0.12.19", "11.10" or "2.27.0rc1"; null if the text does not start with a number.</summary>
    public static ToolVersion? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        ReadOnlySpan<char> rest = text.AsSpan().Trim();
        if (rest.Length > 1 && rest[0] is 'v' or 'V')
        {
            rest = rest[1..];
        }

        Span<int> parts = [0, 0, 0];
        for (int i = 0; i < 3; i++)
        {
            int length = 0;
            while (length < rest.Length && char.IsAsciiDigit(rest[length]))
            {
                length++;
            }

            if (length == 0 || !int.TryParse(rest[..length], NumberStyles.None, CultureInfo.InvariantCulture, out parts[i]))
            {
                // No number where the major version belongs is not a version; later parts may be absent.
                if (i == 0)
                {
                    return null;
                }

                break;
            }

            rest = rest[length..];
            if (rest.Length == 0 || rest[0] != '.')
            {
                break;
            }

            rest = rest[1..];
        }

        return new ToolVersion(parts[0], parts[1], parts[2]);
    }

    public int CompareTo(ToolVersion other) =>
        Major != other.Major ? Major.CompareTo(other.Major)
        : Minor != other.Minor ? Minor.CompareTo(other.Minor)
        : Patch.CompareTo(other.Patch);

    public static bool operator <(ToolVersion left, ToolVersion right) => left.CompareTo(right) < 0;

    public static bool operator >(ToolVersion left, ToolVersion right) => left.CompareTo(right) > 0;

    public static bool operator <=(ToolVersion left, ToolVersion right) => left.CompareTo(right) <= 0;

    public static bool operator >=(ToolVersion left, ToolVersion right) => left.CompareTo(right) >= 0;

    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}.{Patch}");
}
