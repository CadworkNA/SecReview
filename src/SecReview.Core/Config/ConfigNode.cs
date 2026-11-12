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
public sealed record ConfigList(IReadOnlyList<ConfigNode> Items, int Line) : ConfigNode(Line)
{
    /// <summary>A list a reader can keep adding to, so that a long list is not copied for every item.</summary>
    internal static ConfigList Growable(ConfigNode first, int line) => new(new List<ConfigNode> { first }, line);

    /// <summary>Adds an item to a list made with <see cref="Growable"/>; false, changing nothing, for any other list.</summary>
    internal bool TryAppend(ConfigNode item)
    {
        if (Items is not List<ConfigNode> items)
        {
            return false;
        }

        items.Add(item);
        return true;
    }
}

/// <summary>Named values (a table, a mapping, a section).</summary>
/// <param name="Line">The line it starts on.</param>
public sealed record ConfigMap(int Line) : ConfigNode(Line)
{
    private readonly List<KeyValuePair<string, ConfigNode>> _entries = [];

    /// <summary>Where each key is in <see cref="_entries"/>, so that a large file is not searched line by line for every key.</summary>
    private readonly Dictionary<string, int> _index = new(StringComparer.Ordinal);

    /// <summary>The entries, in file order.</summary>
    public IReadOnlyList<KeyValuePair<string, ConfigNode>> Entries => _entries;

    /// <summary>The value of a key; null if there is none. Key names are matched exactly.</summary>
    public ConfigNode? this[string key] => _index.TryGetValue(key, out int at) ? _entries[at].Value : null;

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
        if (!_index.TryAdd(key, _entries.Count))
        {
            return false;
        }

        _entries.Add(new KeyValuePair<string, ConfigNode>(key, value));
        return true;
    }

    /// <summary>Replaces the value of a key that is already there.</summary>
    internal void Replace(string key, ConfigNode value) =>
        _entries[_index[key]] = new KeyValuePair<string, ConfigNode>(key, value);
}

/// <summary>Ways to look at a setting that may be written once or several times.</summary>
public static class ConfigValues
{
    /// <summary>
    /// Every single value a setting holds: the value itself, or each item of a list. Used when
    /// what the file contains matters whichever value is in force, as with a stored secret.
    /// </summary>
    public static IEnumerable<ConfigScalar> All(this ConfigNode? node) => node switch
    {
        ConfigScalar scalar => [scalar],
        ConfigList list => list.Items.OfType<ConfigScalar>(),
        _ => [],
    };

    /// <summary>
    /// The value in force: the value itself, or the last item when the setting was written more
    /// than once (the later line wins). Null when there is none.
    /// </summary>
    public static ConfigScalar? InForce(this ConfigNode? node) => node switch
    {
        ConfigScalar scalar => scalar,
        ConfigList { Items: [.., ConfigScalar last] } => last,
        _ => null,
    };
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

    /// <summary>
    /// Runs a reader and turns whatever happens into an answer. A reader stops at what it does
    /// not understand with a <see cref="ConfigSyntaxException"/>; anything else it might trip
    /// over on unexpected content ends the same way, as "not understood", never as a crash.
    /// </summary>
    internal static ConfigFile From(Func<ConfigMap> read)
    {
        try
        {
            return Ok(read());
        }
        catch (ConfigSyntaxException problem)
        {
            return Failed(problem.Line, problem.Message);
        }
#pragma warning disable CA1031 // A reader must answer for every possible file content.
        catch (Exception unexpected)
#pragma warning restore CA1031
        {
            return Failed(1, $"the file could not be read ({unexpected.GetType().Name})");
        }
    }
}

/// <summary>Thrown inside a reader to stop at the first thing it does not understand.</summary>
internal sealed class ConfigSyntaxException(int line, string problem) : Exception(problem)
{
    public int Line { get; } = line;
}
