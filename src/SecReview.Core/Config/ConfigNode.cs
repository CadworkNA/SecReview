using System.Globalization;

namespace SecReview.Config;

/// <summary>What kind of value a scalar is, as far as its file format says.</summary>
public enum ScalarKind
{
    /// <summary>Text. In formats without types (INI) every value is text.</summary>
    Text = 0,

    /// <summary>A whole number.</summary>
    Number,

    /// <summary>True or false.</summary>
    Boolean,

    /// <summary>Something else the format knows (a date, a decimal number, null); kept as written.</summary>
    Other,
}

/// <summary>
/// One value read from a settings file, with the line it is on. Settings files of every
/// format (TOML, YAML, INI) are read into this one shape so checks need not know the format.
/// </summary>
/// <param name="Line">The 1-based line the value starts on.</param>
public abstract record ConfigNode(int Line);

/// <summary>A single value.</summary>
/// <param name="Text">The value: unquoted and unescaped for text, as written otherwise.</param>
/// <param name="Kind">What the format says it is.</param>
/// <param name="Line">The line it is on.</param>
public sealed record ConfigScalar(string Text, ScalarKind Kind, int Line) : ConfigNode(Line)
{
    /// <summary>The value as true/false, if the format says it is one.</summary>
    public bool? AsBoolean => Kind == ScalarKind.Boolean
        ? Text.Equals("true", StringComparison.OrdinalIgnoreCase)
        : null;

    /// <summary>The value as a whole number, if the format says it is one.</summary>
    public long? AsNumber => Kind == ScalarKind.Number &&
        long.TryParse(Text.Replace("_", string.Empty, StringComparison.Ordinal), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long number)
            ? number
            : null;
}

/// <summary>A list of values.</summary>
/// <param name="Items">The values, in file order.</param>
/// <param name="Line">The line the list starts on.</param>
public sealed record ConfigList(IReadOnlyList<ConfigNode> Items, int Line) : ConfigNode(Line);

/// <summary>Named values (a table, a mapping, a section).</summary>
/// <param name="Line">The line it starts on.</param>
public sealed record ConfigMap(int Line) : ConfigNode(Line)
{
    private readonly List<KeyValuePair<string, ConfigNode>> _entries = [];

    /// <summary>The entries, in file order.</summary>
    public IReadOnlyList<KeyValuePair<string, ConfigNode>> Entries => _entries;

    /// <summary>The value of a key; null if there is none. Key names are matched exactly.</summary>
    public ConfigNode? this[string key]
    {
        get
        {
            foreach ((string name, ConfigNode value) in _entries)
            {
                if (name == key)
                {
                    return value;
                }
            }

            return null;
        }
    }

    /// <summary>The value at a path of keys, each inside the one before; null if any step is missing or is not a map.</summary>
    public ConfigNode? Find(params ReadOnlySpan<string> path)
    {
        ConfigNode? node = this;
        foreach (string key in path)
        {
            node = (node as ConfigMap)?[key];
            if (node is null)
            {
                return null;
            }
        }

        return node;
    }

    /// <summary>Adds an entry. Returns false, changing nothing, if the key is already there.</summary>
    internal bool TryAdd(string key, ConfigNode value)
    {
        if (this[key] is not null)
        {
            return false;
        }

        _entries.Add(new KeyValuePair<string, ConfigNode>(key, value));
        return true;
    }

    /// <summary>Replaces the value of a key that is already there.</summary>
    internal void Replace(string key, ConfigNode value)
    {
        int index = _entries.FindIndex(e => e.Key == key);
        _entries[index] = new KeyValuePair<string, ConfigNode>(key, value);
    }
}

/// <summary>
/// The outcome of reading a settings file: its contents, or the first thing in it that was
/// not understood. There is no partial result: a check must never judge half a file.
/// </summary>
public sealed class ConfigFile
{
    private ConfigFile(ConfigMap? root, string? problem, int problemLine)
    {
        Root = root;
        Problem = problem;
        ProblemLine = problemLine;
    }

    /// <summary>The file's contents; null if it could not be read in full.</summary>
    public ConfigMap? Root { get; }

    /// <summary>What was not understood; null when the whole file was read.</summary>
    public string? Problem { get; }

    /// <summary>The 1-based line of the problem.</summary>
    public int ProblemLine { get; }

    public bool IsOk => Root is not null;

    /// <summary>"could not evaluate (line N): reason", for results.</summary>
    public string Describe() => IsOk ? string.Empty : $"could not evaluate (line {ProblemLine}): {Problem}";

    internal static ConfigFile Ok(ConfigMap root) => new(root, null, 0);

    internal static ConfigFile Failed(int line, string problem) => new(null, problem, line);
}

/// <summary>Thrown inside a reader to stop at the first thing it does not understand.</summary>
internal sealed class ConfigSyntaxException(int line, string problem) : Exception(problem)
{
    public int Line { get; } = line;
}
