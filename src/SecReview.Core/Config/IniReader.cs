namespace SecReview.Config;

/// <summary>How an INI-style file is to be read; the tools that use the format differ in details.</summary>
public enum IniDialect
{
    /// <summary>
    /// npm's flavour (<c>.npmrc</c>, pnpm's <c>rc</c> and <c>auth.ini</c>, and git's own settings
    /// files): <c>key=value</c> lines, comments starting with <c>;</c> or <c>#</c>,
    /// <c>key[]=value</c> for lists, optional quotes. A key written again replaces the earlier
    /// value for the tool; here every value is kept, in order, as a list, so that a check can
    /// see both the value in force (the last) and what else the file holds.
    /// </summary>
    Npm,

    /// <summary>
    /// Python's configparser flavour (<c>pip.ini</c>, <c>.pypirc</c>): sections, <c>=</c> or
    /// <c>:</c> between key and value, and lines indented deeper than their key, which continue
    /// its value as further lines. A key written twice in a section is an error there, and
    /// here.
    /// </summary>
    Python,
}

/// <summary>
/// Reads INI-style settings files. Keys outside any section are entries of the root; a
/// <c>[section]</c> becomes a map under its name. Lines that fit none of this stop the read
/// with the line number.
/// </summary>
public static class IniReader
{
    public static ConfigFile Read(string text, IniDialect dialect)
    {
        ArgumentNullException.ThrowIfNull(text);
        return ConfigFile.From(() => Parse(text, dialect));
    }

    private static ConfigMap Parse(string text, IniDialect dialect)
    {
        var root = new ConfigMap(1);
        ConfigMap section = root;

        // The key a deeper-indented line would continue, and how far that key's own line is indented.
        string? lastKey = null;
        int lastKeyIndent = 0;

        string[] lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            int number = i + 1;
            string raw = lines[i].TrimEnd('\r');
            if (i == 0 && raw.StartsWith((char)0xFEFF))
            {
                raw = raw[1..];
            }

            string line = raw.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
            {
                // Neither an empty line nor a comment ends a value that is continued below it.
                continue;
            }

            int indent = raw.Length - raw.TrimStart().Length;

            // A line indented deeper than its key continues the value above (Python flavour only).
            if (dialect == IniDialect.Python && lastKey is not null && indent > lastKeyIndent)
            {
                Append(section, lastKey, new ConfigScalar(line, ScalarKind.Text, number));
                continue;
            }

            if (line[0] == '[')
            {
                if (line[^1] != ']' || line.Length < 3)
                {
                    throw new ConfigSyntaxException(number, "a section name is not closed");
                }

                string name = line[1..^1].Trim();
                switch (root[name])
                {
                    case null:
                        section = new ConfigMap(number);
                        root.TryAdd(name, section);
                        break;
                    case ConfigMap existing when dialect == IniDialect.Npm:
                        section = existing;
                        break;
                    case ConfigMap:
                        throw new ConfigSyntaxException(number, $"the section \"{name}\" is written twice");
                    default:
                        throw new ConfigSyntaxException(number, $"\"{name}\" is both a setting and a section");
                }

                lastKey = null;
                continue;
            }

            int separator = dialect == IniDialect.Python ? line.IndexOfAny(['=', ':']) : line.IndexOf('=', StringComparison.Ordinal);
            if (separator <= 0)
            {
                // npm reads a bare word as "true"; nothing a check looks at is written that way,
                // so a line without "=" is treated as not understood rather than guessed at.
                throw new ConfigSyntaxException(number, "expected \"name = value\"");
            }

            string key = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();
            bool isList = dialect == IniDialect.Npm && key.EndsWith("[]", StringComparison.Ordinal);
            if (isList)
            {
                key = key[..^2].TrimEnd();
            }

            if (key.Length == 0)
            {
                throw new ConfigSyntaxException(number, "a setting has no name");
            }

            if (dialect == IniDialect.Npm)
            {
                if (key.AsSpan().ContainsAny(';', '#'))
                {
                    throw new ConfigSyntaxException(number, "a setting's name contains a comment sign");
                }

                value = Unquote(WithoutComment(value), number);
            }
            else
            {
                // Python reads option names without regard to case, and pip treats "_" as "-"
                // and ignores a leading "--": "Trusted_Host" is "trusted-host".
                key = key.ToLowerInvariant().Replace('_', '-');
                if (key.StartsWith("--", StringComparison.Ordinal))
                {
                    key = key[2..];
                }

                if (key.Length == 0)
                {
                    throw new ConfigSyntaxException(number, "a setting has no name");
                }
            }

            var scalar = new ConfigScalar(value, ScalarKind.Text, number);
            if (section[key] is null && !isList)
            {
                section.TryAdd(key, scalar);
            }
            else if (dialect == IniDialect.Python)
            {
                throw new ConfigSyntaxException(number, $"\"{key}\" is written twice in its section");
            }
            else
            {
                Append(section, key, scalar);
            }

            lastKey = key;
            lastKeyIndent = indent;
        }

        return root;
    }

    /// <summary>Adds a further value to a key, turning a single value into a list.</summary>
    private static void Append(ConfigMap section, string key, ConfigScalar value)
    {
        switch (section[key])
        {
            case null:
                section.TryAdd(key, ConfigList.Growable(value, value.Line));
                break;
            case ConfigList list:
                list.TryAppend(value);
                break;
            case ConfigScalar { Text.Length: 0 } empty:
                // "key =" followed by deeper-indented lines: the lines are the value.
                section.Replace(key, ConfigList.Growable(value, empty.Line));
                break;
            case ConfigNode single:
                ConfigList both = ConfigList.Growable(single, single.Line);
                both.TryAppend(value);
                section.Replace(key, both);
                break;
        }
    }

    /// <summary>
    /// npm ends an unquoted value at the first ";" or "#" that has no backslash before it: the
    /// rest of the line is a comment. A value in quotes is kept whole.
    /// </summary>
    private static string WithoutComment(string value)
    {
        if (value.Length >= 2 && value[0] is '"' or '\'' && value[^1] == value[0])
        {
            return value;
        }

        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\')
            {
                i++;
            }
            else if (value[i] is ';' or '#')
            {
                return value[..i].TrimEnd();
            }
        }

        return value;
    }

    /// <summary>npm values may be wrapped in single or double quotes.</summary>
    private static string Unquote(string value, int number)
    {
        if (value.Length == 0 || value[0] is not ('"' or '\''))
        {
            return value;
        }

        if (value.Length < 2 || value[^1] != value[0])
        {
            throw new ConfigSyntaxException(number, "a quoted value is not closed");
        }

        return value[1..^1];
    }
}
