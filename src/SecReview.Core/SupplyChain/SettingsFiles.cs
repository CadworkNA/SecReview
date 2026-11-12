using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain;

/// <summary>The formats settings files come in.</summary>
internal enum SettingsFormat
{
    Toml,
    Yaml,
    NpmIni,
    PythonIni,
}

/// <summary>
/// A settings file that exists: its contents, or why they could not be used. A file that is
/// there but cannot be read or understood is never treated as if it were absent.
/// </summary>
/// <param name="Path">The full path, for the "where this came from" of a finding.</param>
/// <param name="Root">The contents; null when <paramref name="Problem"/> is set.</param>
/// <param name="Problem">Why the file could not be used, in words fit for a result.</param>
/// <param name="Format">The format it was read as.</param>
internal sealed record SettingsFile(string Path, ConfigMap? Root, string? Problem, SettingsFormat Format = SettingsFormat.Toml)
{
    /// <summary>The file's name without its folder.</summary>
    public string Name => Path[(Path.LastIndexOf('\\') + 1)..];

    /// <summary>
    /// The one value a setting has in this file. In npm-style files a later line replaces an
    /// earlier one, so the last counts; in every other format a setting is one value or it is
    /// not a single value at all.
    /// </summary>
    public ConfigScalar? Single(ConfigNode? node) => Format == SettingsFormat.NpmIni ? node.InForce() : node as ConfigScalar;

    /// <summary>"path, line N", for a finding's source.</summary>
    public string At(ConfigNode node) => $"{Path}, line {node.Line}";
}

/// <summary>Reads settings files through the file probe.</summary>
internal static class SettingsFiles
{
    /// <summary>The file at a path; null if there is no such file.</summary>
    public static SettingsFile? Load(IFileProbe files, string path, SettingsFormat format)
    {
        ProbeResult<string> text = files.ReadText(path);
        if (text.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        string name = path[(path.LastIndexOf('\\') + 1)..];
        if (!text.IsOk)
        {
            return new SettingsFile(
                path, null, text.Status == ProbeStatus.AccessDenied ? $"{name} could not be read: access denied." : $"{name} could not be read: {text.Detail}", format);
        }

        ConfigFile parsed = format switch
        {
            SettingsFormat.Toml => TomlReader.Read(text.Value!),
            SettingsFormat.Yaml => YamlReader.Read(text.Value!),
            SettingsFormat.NpmIni => IniReader.Read(text.Value!, IniDialect.Npm),
            _ => IniReader.Read(text.Value!, IniDialect.Python),
        };

        return parsed.IsOk
            ? new SettingsFile(path, parsed.Root, null, format)
            : new SettingsFile(path, null, $"{name}: {parsed.Describe()}", format);
    }

    /// <summary>
    /// A JSON file's root; null if there is no such file. <paramref name="problem"/> is set
    /// when the file exists but cannot be read or is not valid JSON.
    /// </summary>
    public static JsonElement? LoadJson(IFileProbe files, string path, out string? problem)
    {
        problem = null;
        ProbeResult<string> text = files.ReadText(path);
        if (text.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        string name = path[(path.LastIndexOf('\\') + 1)..];
        if (!text.IsOk)
        {
            problem = text.Status == ProbeStatus.AccessDenied ? $"{name} could not be read: access denied." : $"{name} could not be read: {text.Detail}";
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(
                text.Value!, new JsonDocumentOptions { MaxDepth = 32, CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            return document.RootElement.Clone();
        }
        catch (JsonException exception)
        {
            problem = $"{name}: could not evaluate (line {(exception.LineNumber ?? 0) + 1}): it is not valid JSON.";
            return null;
        }
    }

    /// <summary>Whether a folder exists (and can be listed); a folder that cannot be listed counts as there.</summary>
    public static bool FolderExists(IFileProbe files, string path) => files.List(path).Status != ProbeStatus.NotFound;

    /// <summary>Whether a folder has an entry of that name; false if the folder is not there.</summary>
    public static bool Exists(IFileProbe files, string folder, string name)
    {
        ProbeResult<IReadOnlyList<FileEntry>> entries = files.List(folder);
        return entries.IsOk && entries.Value!.Any(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Environment variables that are set for good: for the user (they win) or for the whole PC.
/// A variable set only in one terminal session cannot be seen and is not claimed to be.
/// </summary>
internal static class PersistentEnvironment
{
    internal const string UserKey = "Environment";
    internal const string MachineKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    /// <summary>
    /// A variable's value and where it is set ("your environment variables" or "the PC's
    /// environment variables"); both null if it is not set. Returns the outcome for a failed read.
    /// </summary>
    public static CheckOutcome? Read(SystemProbes probes, string name, out string? value, out string? source)
    {
        value = null;
        source = null;
        IRegistryProbe registry = probes.Registry;
        if (RegistryReader.Text(registry, RegistryRoot.CurrentUser, UserKey, name, "your environment variables", out string? user) is { } failed)
        {
            return failed;
        }

        if (user is not null)
        {
            (value, source) = (Expand(user, probes.Environment), $"your environment variables ({name})");
            return null;
        }

        if (RegistryReader.Text(registry, RegistryRoot.LocalMachine, MachineKey, name, "the PC's environment variables", out string? machine) is { } failedToo)
        {
            return failedToo;
        }

        if (machine is not null)
        {
            (value, source) = (Expand(machine, probes.Environment), $"the PC's environment variables ({name})");
        }

        return null;
    }

    /// <summary>
    /// Replaces "%NAME%" references, as Windows does for a variable stored in that form
    /// ("%USERPROFILE%\.config"). A name that is not set is left as written.
    /// </summary>
    internal static string Expand(string text, IEnvironmentProbe environment)
    {
        if (!text.Contains('%', StringComparison.Ordinal))
        {
            return text;
        }

        var expanded = new System.Text.StringBuilder(text.Length);
        int position = 0;
        while (position < text.Length)
        {
            int open = text.IndexOf('%', position);
            int close = open < 0 ? -1 : text.IndexOf('%', open + 1);
            if (close < 0)
            {
                expanded.Append(text, position, text.Length - position);
                break;
            }

            expanded.Append(text, position, open - position);
            string name = text[(open + 1)..close];
            string? known = name.Length == 0 ? null : environment.Variable(name) ?? WellKnown(name, environment);
            if (known is null)
            {
                // Not a variable: keep the first "%" and look again from the next one.
                expanded.Append('%');
                position = open + 1;
            }
            else
            {
                expanded.Append(known);
                position = close + 1;
            }
        }

        return expanded.ToString();
    }

    /// <summary>The folders Windows always defines, for when the process environment does not have them.</summary>
    private static string? WellKnown(string name, IEnvironmentProbe environment)
    {
        KnownFolder? folder = name.ToUpperInvariant() switch
        {
            "USERPROFILE" => KnownFolder.UserProfile,
            "APPDATA" => KnownFolder.RoamingAppData,
            "LOCALAPPDATA" => KnownFolder.LocalAppData,
            "PROGRAMDATA" or "ALLUSERSPROFILE" => KnownFolder.ProgramData,
            "PROGRAMFILES" => KnownFolder.ProgramFiles,
            _ => null,
        };
        return folder is { } known && environment.Folder(known) is { IsOk: true } path ? path.Value : null;
    }

    /// <summary>The names of every persistent variable, user and machine; a failed read gives the outcome.</summary>
    public static CheckOutcome? Names(IRegistryProbe registry, out IReadOnlyList<string> names)
    {
        var all = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        names = [];
        foreach ((RegistryRoot root, string key) in new[] { (RegistryRoot.CurrentUser, UserKey), (RegistryRoot.LocalMachine, MachineKey) })
        {
            ProbeResult<IReadOnlyList<string>> read = registry.GetValueNames(root, key);
            if (read.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!read.IsOk)
            {
                return ProbeOutcomes.FromFailure(read, "the environment variables");
            }

            all.UnionWith(read.Value!);
        }

        names = [.. all];
        return null;
    }
}
