using System.Text;

namespace SecReview.Config;

/// <summary>One "key = value" of a Java-style properties file.</summary>
/// <param name="Key">The key.</param>
/// <param name="Value">The value, with continued lines joined.</param>
/// <param name="Line">The 1-based line the entry starts on.</param>
public sealed record PropertyEntry(string Key, string Value, int Line);

/// <summary>
/// Reads Java-style properties files (<c>gradle.properties</c>): <c>key=value</c>,
/// <c>key: value</c> or <c>key value</c> per line, comments starting with <c>#</c> or
/// <c>!</c>, and a backslash at the end of a line to continue it. The format has no line a
/// reader could fail to understand, so there is no error case; escapes other than the
/// separator ones are kept as written, which is enough to tell whether a value is there.
/// </summary>
public static class PropertiesReader
{
    public static IReadOnlyList<PropertyEntry> Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var entries = new List<PropertyEntry>();
        string[] lines = text.Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            int number = i + 1;
            string line = lines[i].TrimEnd('\r').TrimStart(' ', '\t', '\f');
            if (i == 0 && line.StartsWith((char)0xFEFF))
            {
                line = line[1..].TrimStart(' ', '\t', '\f');
            }

            if (line.Length == 0 || line[0] is '#' or '!')
            {
                continue;
            }

            // A line ending in an odd number of backslashes goes on with the next line.
            // Only the piece just added is looked at, so a long run of continued lines stays cheap.
            var whole = new StringBuilder(line);
            string piece = line;
            while (EndsContinued(piece) && i + 1 < lines.Length)
            {
                whole.Length--;
                i++;
                piece = lines[i].TrimEnd('\r').TrimStart(' ', '\t', '\f');
                whole.Append(piece);
            }

            string entry = whole.ToString();

            // The key ends at the first "=", ":" or space that has no backslash before it.
            int end = 0;
            while (end < entry.Length && entry[end] is not ('=' or ':' or ' ' or '\t'))
            {
                end += entry[end] == '\\' && end + 1 < entry.Length ? 2 : 1;
            }

            end = Math.Min(end, entry.Length);
            string key = entry[..end].Replace("\\", string.Empty, StringComparison.Ordinal);

            // Then spaces, at most one "=" or ":", and more spaces.
            int start = end;
            while (start < entry.Length && entry[start] is ' ' or '\t')
            {
                start++;
            }

            if (start < entry.Length && entry[start] is '=' or ':')
            {
                start++;
                while (start < entry.Length && entry[start] is ' ' or '\t')
                {
                    start++;
                }
            }

            if (key.Length > 0)
            {
                entries.Add(new PropertyEntry(key, entry[start..], number));
            }
        }

        return entries;
    }

    private static bool EndsContinued(string line)
    {
        int backslashes = 0;
        for (int i = line.Length - 1; i >= 0 && line[i] == '\\'; i--)
        {
            backslashes++;
        }

        return backslashes % 2 == 1;
    }
}
