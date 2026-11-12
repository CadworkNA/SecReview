using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Scoop;

namespace SecReview.SupplyChain.Git;

/// <summary>One setting Git would read, with the file it is in.</summary>
/// <param name="Setting">The setting.</param>
/// <param name="Path">The file it is written in.</param>
/// <param name="Conditional">True when the file is only included for some repositories (<c>includeIf</c>).</param>
internal sealed record GitEntry(GitSetting Setting, string Path, bool Conditional)
{
    /// <summary>Where the setting is, for a finding. A setting from a variable has no line.</summary>
    public string Source => Setting.Line > 0 ? $"{Path}, line {Setting.Line}" : Path;

    /// <summary>Words to add to a finding's item when the setting does not apply everywhere.</summary>
    public string Scope => Conditional ? " (in some repositories)" : string.Empty;
}

/// <summary>
/// Git's settings for this user outside any repository: the PC's files and the user's, in the
/// order Git reads them (later entries win), with included files in place. Git is never run.
/// A repository's own <c>.git\config</c> can add to these; this is the baseline.
/// </summary>
/// <param name="Entries">Every setting, in the order Git reads them.</param>
/// <param name="Problem">The first file that exists but could not be read or understood; null if all were.</param>
/// <param name="Home">The folder Git takes as the user's home.</param>
/// <param name="ConfigHome">The folder Git's XDG-style files are under.</param>
internal sealed record GitInstall(IReadOnlyList<GitEntry> Entries, string? Problem, string Home, string ConfigHome)
{
    /// <summary>Every value of a setting without a subsection, in order.</summary>
    public IEnumerable<GitEntry> All(string section, string name) =>
        Entries.Where(e => e.Setting.Subsection is null && e.Setting.Section == section && e.Setting.Name == name);

    /// <summary>
    /// The values of a setting without a subsection that can be in force somewhere: the last
    /// one that applies everywhere, and every one after it from a file included only for some
    /// repositories. A conditional value never hides the unconditional one: outside the
    /// repositories it is for, the unconditional one still decides.
    /// </summary>
    public IReadOnlyList<GitEntry> Deciding(string section, string name) => Deciding(All(section, name));

    /// <summary>As <see cref="Deciding(string, string)"/>, for each subsection the setting is written under.</summary>
    public IEnumerable<GitEntry> DecidingPerSubsection(string section, string name) => Entries
        .Where(e => e.Setting.Subsection is not null && e.Setting.Section == section && e.Setting.Name == name)
        .GroupBy(e => e.Setting.Subsection, StringComparer.Ordinal)
        .SelectMany(Deciding);

    /// <summary>The last entry that applies everywhere, and the conditional ones after it.</summary>
    public static IReadOnlyList<GitEntry> Deciding(IEnumerable<GitEntry> entries)
    {
        List<GitEntry> all = [.. entries];
        int from = Math.Max(all.FindLastIndex(e => !e.Conditional), 0);
        return all.GetRange(from, all.Count - from);
    }
}

internal static class GitLocator
{
    private const int MaximumIncludeDepth = 5;

    /// <summary>
    /// Git's settings; <paramref name="git"/> is null when no trace of Git is found. Returns the
    /// outcome when something needed to tell could not be read.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out GitInstall? git)
    {
        git = null;
        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!programData.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where its shared folder is.");
        }

        if (Home(probes, out string home) is { } noHome)
        {
            return noHome;
        }

        var variables = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (string name in (string[])["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL", "XDG_CONFIG_HOME"])
        {
            if (PersistentEnvironment.Read(probes, name, out string? value, out _) is { } failed)
            {
                return failed;
            }

            variables[name] = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }

        // Where Git is installed: its own installer records it; Scoop keeps it under its apps.
        if (RegistryReader.Text(probes.Registry, RegistryRoot.LocalMachine, @"SOFTWARE\GitForWindows", "InstallPath", "Git's install record", out string? installed) is { } unread)
        {
            return unread;
        }

        // An install for one user alone records itself under that user instead.
        if (RegistryReader.Text(probes.Registry, RegistryRoot.CurrentUser, @"SOFTWARE\GitForWindows", "InstallPath", "Git's install record", out string? installedForUser) is { } unreadToo)
        {
            return unreadToo;
        }

        var installs = new List<string>(3);
        foreach (string? record in (string?[])[installed, installedForUser])
        {
            if (!string.IsNullOrWhiteSpace(record))
            {
                installs.Add(record.Trim().TrimEnd('\\'));
            }
        }

        if (ScoopLocator.Locate(probes, out ScoopInstall? scoop) is null && scoop is not null &&
            SettingsFiles.FolderExists(probes.Files, $@"{scoop.Root}\apps\git\current"))
        {
            installs.Add($@"{scoop.Root}\apps\git\current");
        }

        string configHome = variables["XDG_CONFIG_HOME"]?.TrimEnd('\\', '/') ?? $@"{home}\.config";

        var paths = new List<string>();
        bool noSystem = variables["GIT_CONFIG_NOSYSTEM"] is { } off && Flags.Parse(off) == true;
        if (!noSystem)
        {
            paths.Add($@"{programData.Value}\Git\config");
            if (variables["GIT_CONFIG_SYSTEM"] is { } system)
            {
                paths.Add(system);
            }
            else
            {
                paths.AddRange(installs.Select(install => $@"{install}\etc\gitconfig"));
            }
        }

        if (variables["GIT_CONFIG_GLOBAL"] is { } global)
        {
            paths.Add(global);
        }
        else
        {
            paths.Add($@"{configHome}\git\config");
            paths.Add($@"{home}\.gitconfig");
        }

        var loader = new Loader(probes.Files, home);
        bool anyFile = false;
        foreach (string path in paths)
        {
            anyFile |= loader.Add(path.Replace('/', '\\'), conditional: false, depth: 0);
        }

        // Settings handed to Git through variables come last and win: GIT_CONFIG_COUNT says how
        // many, GIT_CONFIG_KEY_n and GIT_CONFIG_VALUE_n hold each.
        if (FromVariables(probes, loader.Entries, out bool anyVariable) is { } unreadVariables)
        {
            return unreadVariables;
        }

        if (anyFile || anyVariable || installs.Count > 0)
        {
            git = new GitInstall(loader.Entries, loader.Problem, home, configHome);
        }

        return null;
    }

    private static CheckOutcome? FromVariables(SystemProbes probes, List<GitEntry> entries, out bool any)
    {
        const int Most = 64;
        any = false;
        if (PersistentEnvironment.Read(probes, "GIT_CONFIG_COUNT", out string? count, out _) is { } failed)
        {
            return failed;
        }

        if (!int.TryParse(count?.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int settings))
        {
            return null;
        }

        for (int i = 0; i < Math.Min(settings, Most); i++)
        {
            if (PersistentEnvironment.Read(probes, $"GIT_CONFIG_KEY_{i}", out string? key, out string? source) is { } unreadKey)
            {
                return unreadKey;
            }

            if (PersistentEnvironment.Read(probes, $"GIT_CONFIG_VALUE_{i}", out string? value, out _) is { } unreadValue)
            {
                return unreadValue;
            }

            // "section.name" or "section.subsection.name": the subsection is all that is in between.
            int first = key?.IndexOf('.', StringComparison.Ordinal) ?? -1;
            int last = key?.LastIndexOf('.') ?? -1;
            if (key is null || first <= 0 || last == key.Length - 1)
            {
                continue;
            }

            any = true;
            entries.Add(new GitEntry(
                new GitSetting(
                    key[..first].Trim().ToLowerInvariant(), last > first ? key[(first + 1)..last] : null, key[(last + 1)..].Trim().ToLowerInvariant(), value ?? string.Empty, 0),
                source!,
                Conditional: false));
        }

        return null;
    }

    /// <summary>
    /// The folder Git for Windows takes as home, where <c>.gitconfig</c> and the files of saved
    /// passwords are: <c>HOME</c> if set, else the home drive and path Windows gives the
    /// session if that folder exists (a mapped home share), else the user's profile folder.
    /// </summary>
    public static CheckOutcome? Home(SystemProbes probes, out string home)
    {
        home = string.Empty;
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        if (!profile.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folder is.");
        }

        home = profile.Value!;
        if (PersistentEnvironment.Read(probes, "HOME", out string? set, out _) is { } failed)
        {
            return failed;
        }

        if (!string.IsNullOrWhiteSpace(set))
        {
            home = set.Trim().Replace('/', '\\').TrimEnd('\\');
            return null;
        }

        string? drive = probes.Environment.Variable("HOMEDRIVE");
        string? path = probes.Environment.Variable("HOMEPATH");
        if (!string.IsNullOrWhiteSpace(drive) && !string.IsNullOrWhiteSpace(path))
        {
            string session = (drive.Trim() + path.Trim()).Replace('/', '\\').TrimEnd('\\');
            if (session.Length > 2 && SettingsFiles.FolderExists(probes.Files, session))
            {
                home = session;
            }
        }

        return null;
    }

    /// <summary>
    /// Reads files into one ordered list, following includes where they are written. The work
    /// is bounded whatever the files say: a depth, a number of files and a number of settings;
    /// past any of them the answer is "could not evaluate", never a partial one.
    /// </summary>
    private sealed class Loader(IFileProbe files, string home)
    {
        private const int MaximumFiles = 64;
        private const int MaximumEntries = 20_000;

        private readonly HashSet<string> _open = new(StringComparer.OrdinalIgnoreCase);
        private int _filesRead;

        public List<GitEntry> Entries { get; } = [];

        public string? Problem { get; private set; }

        /// <summary>Adds a file's settings; false if there is no such file.</summary>
        public bool Add(string path, bool conditional, int depth)
        {
            string name = path[(path.LastIndexOf('\\') + 1)..];
            if (depth > MaximumIncludeDepth || _open.Contains(path))
            {
                Problem ??= $"{name}: could not evaluate: Git's included files go too deep or in a circle.";
                return true;
            }

            if (_filesRead >= MaximumFiles || Entries.Count >= MaximumEntries)
            {
                Problem ??= $"{name}: could not evaluate: Git's settings include more files or settings than are read.";
                return true;
            }

            ProbeResult<string> text = files.ReadText(path);
            if (text.Status == ProbeStatus.NotFound)
            {
                return false;
            }

            _filesRead++;
            if (!text.IsOk)
            {
                Problem ??= text.Status == ProbeStatus.AccessDenied ? $"{name} could not be read: access denied." : $"{name} could not be read: {text.Detail}";
                return true;
            }

            GitConfigFile parsed = GitConfigReader.Read(text.Value!);
            if (parsed.Settings is null)
            {
                Problem ??= $"{name}: {parsed.Describe()}";
                return true;
            }

            _open.Add(path);
            foreach (GitSetting setting in parsed.Settings)
            {
                bool includes = setting is { Section: "include", Subsection: null, Name: "path" };
                bool includesSometimes = setting is { Section: "includeif", Subsection: not null, Name: "path" };
                if ((includes || includesSometimes) && !string.IsNullOrWhiteSpace(setting.Value))
                {
                    if (Resolve(setting.Value.Trim(), path) is not { } included)
                    {
                        // Where such a path leads depends on how Git was started; it is not guessed at.
                        Problem ??= $"{name}: could not evaluate (line {setting.Line}): the included file's path cannot be resolved from here.";
                    }
                    else
                    {
                        // An included file that is not there is skipped, as Git does.
                        Add(included, conditional || includesSometimes, depth + 1);
                    }
                }
                else if (Entries.Count < MaximumEntries)
                {
                    Entries.Add(new GitEntry(setting, path, conditional));
                }
                else
                {
                    Problem ??= $"{name}: could not evaluate: Git's settings include more files or settings than are read.";
                    break;
                }
            }

            _open.Remove(path);
            return true;
        }

        /// <summary>
        /// An included path as Git resolves it: "~/" is the home folder, a relative path starts at
        /// the including file's folder. Null for the forms that depend on how Git was started: a
        /// path from the root of "the current drive", and "%(prefix)".
        /// </summary>
        private string? Resolve(string included, string from)
        {
            string path = included.Replace('/', '\\');
            if (path.StartsWith(@"~\", StringComparison.Ordinal))
            {
                return home + path[1..];
            }

            if (path.StartsWith(@"\\", StringComparison.Ordinal) || (path.Length >= 3 && path[1] == ':' && path[2] == '\\'))
            {
                return path;
            }

            if (path.StartsWith('\\') || path.StartsWith('%') || path.StartsWith('~'))
            {
                return null;
            }

            return from[..(from.LastIndexOf('\\') + 1)] + path;
        }
    }
}
