namespace SecReview.Config;

/// <summary>How an INI-style file is to be read; the tools that use the format differ in details.</summary>
public enum IniDialect
{
    /// <summary>
    /// npm's flavour (<c>.npmrc</c>, pnpm's <c>rc</c> and <c>auth.ini</c>): <c>key=value</c> lines,
    /// comments starting with <c>;</c> or <c>#</c>, <c>key[]=value</c> for lists, optional quotes.
    /// </summary>
    Npm,

    /// <summary>
    /// Python's configparser flavour (<c>pip.ini</c>, <c>.pypirc</c>): sections, <c>=</c> or <c>:</c>
    /// between key and value, and indented lines that continue the value above as further lines.
    /// </summary>
    Python,
}

/// <summary>
/// Reads INI-style settings files. Keys outside any section are entries of the root; a
/// <c>[section]</c> becomes a map under its name. A key written more than once, or continued
/// over several lines, becomes a list. Lines that fit none of this stop the read with the
/// line number.
/// </summary>
public static class IniReader
{
    public static ConfigFile Read(string text, IniDialect dialect)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            return ConfigFile.Ok(Parse(text, dialect));
        }
        catch (ConfigSyntaxException problem)
        {
            return ConfigFile.Failed(problem.Line, problem.Message);
        }
    }

    private static ConfigMap Parse(string text, IniDialect dialect)
    {
        var root = new ConfigMap(1);
        ConfigMap section = root;
        string? lastKey = null;

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
            if (line.Length == 0)
            {
                // In the Python flavour an empty line ends a continued value.
                lastKey = null;
                continue;
            }

            if (line[0] is ';' or '#')
            {
                continue;
            }

            // An indented line continues the value above (Python flavour only).
            if (dialect == IniDialect.Python && lastKey is not null && raw[0] is ' ' or '\t')
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
                    case ConfigMap existing:
                        section = existing;
                        break;
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
                value = Unquote(value, number);
            }

            var scalar = new ConfigScalar(value, ScalarKind.Text, number);
            if (isList || section[key] is not null)
            {
                Append(section, key, scalar);
            }
            else
            {
                section.TryAdd(key, scalar);
            }

            lastKey = key;
        }

        return root;
    }

    /// <summary>Adds a further value to a key, turning a single value into a list.</summary>
    private static void Append(ConfigMap section, string key, ConfigScalar value)
    {
        switch (section[key])
        {
            case null:
                section.TryAdd(key, new ConfigList([value], value.Line));
                break;
            case ConfigList list:
                section.Replace(key, new ConfigList([.. list.Items, value], list.Line));
                break;
            case ConfigScalar { Text.Length: 0 } empty:
                // "key =" followed by indented lines: the lines are the value.
                section.Replace(key, new ConfigList([value], empty.Line));
                break;
            case ConfigNode single:
                section.Replace(key, new ConfigList([single, value], single.Line));
                break;
        }
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
