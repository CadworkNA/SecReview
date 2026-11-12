using System.Text;

namespace SecReview.Config;

/// <summary>One setting from a Git settings file.</summary>
/// <param name="Section">The section, in lower case ("http", "url").</param>
/// <param name="Subsection">The quoted part of the section header, as written; null if there is none.</param>
/// <param name="Name">The setting's name, in lower case.</param>
/// <param name="Value">The value; null for a name written alone, which Git reads as "true".</param>
/// <param name="Line">The 1-based line it is on.</param>
public sealed record GitSetting(string Section, string? Subsection, string Name, string? Value, int Line)
{
    /// <summary>
    /// The value as yes/no the way Git reads it: the words, or a whole number (decimal or
    /// "0x" hexadecimal, with an optional k, m or g), where zero is no and anything else yes.
    /// Null if it is neither.
    /// </summary>
    public bool? AsBoolean
    {
        get
        {
            if (Value is null)
            {
                return true;
            }

            string text = Value.Trim().ToLowerInvariant();
            switch (text)
            {
                case "true" or "yes" or "on":
                    return true;
                case "false" or "no" or "off" or "":
                    return false;
            }

            // Git falls back to reading a number.
            string digits = text.TrimStart('+', '-');
            if (digits.Length != text.Length && text.Length - digits.Length > 1)
            {
                return null;
            }

            if (digits.Length > 1 && digits[^1] is 'k' or 'm' or 'g')
            {
                digits = digits[..^1];
            }

            bool hex = digits.StartsWith("0x", StringComparison.Ordinal);
            if (hex)
            {
                digits = digits[2..];
            }

            if (digits.Length == 0 || digits.Length > 16 || !digits.All(c => hex ? char.IsAsciiHexDigit(c) : char.IsAsciiDigit(c)))
            {
                return null;
            }

            return digits.Any(c => c != '0');
        }
    }
}

/// <summary>
/// The outcome of reading a Git settings file: every setting in file order, or the first
/// thing that was not understood. There is no partial result.
/// </summary>
public sealed class GitConfigFile
{
    private GitConfigFile(IReadOnlyList<GitSetting>? settings, string? problem, int problemLine)
    {
        Settings = settings;
        Problem = problem;
        ProblemLine = problemLine;
    }

    /// <summary>The settings, in file order; null if the file could not be read in full.</summary>
    public IReadOnlyList<GitSetting>? Settings { get; }

    public string? Problem { get; }

    public int ProblemLine { get; }

    public bool IsOk => Settings is not null;

    /// <summary>"could not evaluate (line N): reason", for results.</summary>
    public string Describe() => IsOk ? string.Empty : $"could not evaluate (line {ProblemLine}): {Problem}";

    internal static GitConfigFile Ok(IReadOnlyList<GitSetting> settings) => new(settings, null, 0);

    internal static GitConfigFile Failed(int line, string problem) => new(null, problem, line);
}

/// <summary>
/// Reads Git's settings files (<c>.gitconfig</c>, <c>.git\config</c>): <c>[section]</c> and
/// <c>[section "subsection"]</c> headers, <c>name = value</c> lines, names written alone,
/// comments, quoted parts, backslash escapes and lines continued with a backslash. A setting
/// may be written many times; all are kept, in order. Anything else stops the read with the
/// line number.
/// </summary>
public static class GitConfigReader
{
    public static GitConfigFile Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            return GitConfigFile.Ok(Parse(text));
        }
        catch (ConfigSyntaxException problem)
        {
            return GitConfigFile.Failed(problem.Line, problem.Message);
        }
#pragma warning disable CA1031 // A reader must answer for every possible file content.
        catch (Exception unexpected)
#pragma warning restore CA1031
        {
            return GitConfigFile.Failed(1, $"the file could not be read ({unexpected.GetType().Name})");
        }
    }

    private static List<GitSetting> Parse(string text)
    {
        var settings = new List<GitSetting>();
        string? section = null;
        string? subsection = null;

        string[] lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            int number = i + 1;
            string line = lines[i].TrimEnd('\r');
            if (i == 0 && line.StartsWith((char)0xFEFF))
            {
                line = line[1..];
            }

            int position = SkipSpaces(line, 0);
            if (position == line.Length || line[position] is '#' or ';')
            {
                continue;
            }

            if (line[position] == '[')
            {
                (section, subsection, position) = ReadHeader(line, position, number);
                position = SkipSpaces(line, position);
                if (position == line.Length || line[position] is '#' or ';')
                {
                    continue;
                }

                // Git allows the first setting on the header's line.
            }

            if (section is null)
            {
                throw new ConfigSyntaxException(number, "a setting before any section");
            }

            int nameStart = position;
            while (position < line.Length && (char.IsAsciiLetterOrDigit(line[position]) || line[position] == '-'))
            {
                position++;
            }

            if (position == nameStart || !char.IsAsciiLetter(line[nameStart]))
            {
                throw new ConfigSyntaxException(number, "expected a setting's name");
            }

            string name = line[nameStart..position].ToLowerInvariant();
            position = SkipSpaces(line, position);
            if (position == line.Length || line[position] is '#' or ';')
            {
                settings.Add(new GitSetting(section, subsection, name, null, number));
                continue;
            }

            if (line[position] != '=')
            {
                throw new ConfigSyntaxException(number, "expected \"name = value\"");
            }

            string value = ReadValue(lines, ref i, position + 1, number);
            settings.Add(new GitSetting(section, subsection, name, value, number));
        }

        return settings;
    }

    private static int SkipSpaces(string line, int position)
    {
        while (position < line.Length && line[position] is ' ' or '\t')
        {
            position++;
        }

        return position;
    }

    /// <summary>Reads "[section]", "[section "sub"]" or the old "[section.sub]"; returns the position after "]".</summary>
    private static (string Section, string? Subsection, int Next) ReadHeader(string line, int open, int number)
    {
        int position = open + 1;
        int start = position;
        while (position < line.Length && (char.IsAsciiLetterOrDigit(line[position]) || line[position] is '-' or '.'))
        {
            position++;
        }

        if (position == start)
        {
            throw new ConfigSyntaxException(number, "a section has no name");
        }

        string section = line[start..position];
        string? subsection = null;

        // The old form: everything after the first dot is the subsection, in lower case.
        int dot = section.IndexOf('.', StringComparison.Ordinal);
        if (dot >= 0)
        {
            subsection = section[(dot + 1)..].ToLowerInvariant();
            section = section[..dot];
        }

        position = SkipSpaces(line, position);
        if (position < line.Length && line[position] == '"')
        {
            if (subsection is not null)
            {
                throw new ConfigSyntaxException(number, "a section header mixes both ways of naming a subsection");
            }

            var quoted = new StringBuilder();
            position++;
            while (true)
            {
                if (position >= line.Length)
                {
                    throw new ConfigSyntaxException(number, "a section name is not closed");
                }

                char c = line[position++];
                if (c == '"')
                {
                    break;
                }

                if (c == '\\')
                {
                    if (position >= line.Length)
                    {
                        throw new ConfigSyntaxException(number, "a section name is not closed");
                    }

                    c = line[position++];
                }

                quoted.Append(c);
            }

            subsection = quoted.ToString();
            position = SkipSpaces(line, position);
        }

        if (position >= line.Length || line[position] != ']')
        {
            throw new ConfigSyntaxException(number, "a section name is not closed");
        }

        return (section.ToLowerInvariant(), subsection, position + 1);
    }

    /// <summary>
    /// Reads a value from <paramref name="start"/> on the current line, moving on to the next
    /// lines while each ends in a backslash. Quotes group, a comment sign outside quotes ends
    /// the value, and spaces at either end are dropped.
    /// </summary>
    private static string ReadValue(string[] lines, ref int index, int start, int number)
    {
        var value = new StringBuilder();
        string line = lines[index].TrimEnd('\r');
        int position = SkipSpaces(line, start);
        bool quoted = false;

        // Spaces at the end count only when quoted, so they are held back until something follows.
        int kept = 0;

        while (true)
        {
            if (position >= line.Length)
            {
                if (quoted)
                {
                    throw new ConfigSyntaxException(number, "a quoted value is not closed on its line");
                }

                break;
            }

            char c = line[position++];
            if (c == '\\')
            {
                if (position >= line.Length)
                {
                    // A backslash at the end of the line: the value goes on.
                    if (index + 1 >= lines.Length)
                    {
                        throw new ConfigSyntaxException(number, "a value is continued past the end of the file");
                    }

                    index++;
                    line = lines[index].TrimEnd('\r');
                    position = 0;
                    continue;
                }

                char escaped = line[position++];
                value.Append(escaped switch
                {
                    'n' => '\n',
                    't' => '\t',
                    'b' => '\b',
                    '"' => '"',
                    '\\' => '\\',
                    _ => throw new ConfigSyntaxException(number, $"\"\\{escaped}\" is not an escape Git knows"),
                });
                kept = value.Length;
            }
            else if (c == '"')
            {
                quoted = !quoted;
                kept = value.Length;
            }
            else if (!quoted && c is '#' or ';')
            {
                break;
            }
            else
            {
                value.Append(c);
                if (quoted || c is not (' ' or '\t'))
                {
                    kept = value.Length;
                }
            }
        }

        value.Length = kept;
        return value.ToString();
    }
}
