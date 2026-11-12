using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Ssh;

/// <summary>One setting in an SSH client settings file, in the order OpenSSH reads them.</summary>
/// <param name="Keyword">The setting's name, in lower case.</param>
/// <param name="Value">Its value, without quotes.</param>
/// <param name="AllHosts">Whether it applies to every host (outside any block, <c>Host *</c>, <c>Match all</c>).</param>
/// <param name="Hosts">The block it is in, for example "Host build-*"; empty when outside any block.</param>
/// <param name="Source">The file and line, for example "config, line 12".</param>
internal sealed record SshSetting(string Keyword, string Value, bool AllHosts, string Hosts, string Source);

/// <summary>The settings read, or why they could not all be read.</summary>
/// <param name="Settings">Every setting, in the order OpenSSH reads them (the first value for a host wins).</param>
/// <param name="Problem">Set when part of the settings could not be read; the result is then incomplete.</param>
/// <param name="AnyFile">Whether any settings file exists.</param>
internal sealed record SshSettings(IReadOnlyList<SshSetting> Settings, string? Problem, bool AnyFile);

/// <summary>
/// Reads OpenSSH client settings: the user's <c>.ssh\config</c>, then the system-wide file, with
/// the files they include. Anything that cannot be followed is reported, not skipped silently.
/// </summary>
internal static class SshConfigFile
{
    /// <summary>OpenSSH itself stops at 16 levels of included files.</summary>
    private const int MaximumIncludeDepth = 16;

    private const int MaximumFiles = 100;

    public static SshSettings Read(SystemProbes probes)
    {
        var state = new ReadState(probes);

        ProbeResult<string> userFolder = SshKeys.Folder(probes);
        if (userFolder.IsOk)
        {
            state.ReadFile($@"{userFolder.Value}\config", userFolder.Value!, inheritedAllHosts: true, inheritedHosts: string.Empty, depth: 0);
        }
        else
        {
            state.Problem ??= "Windows did not say where your user folder is.";
        }

        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (programData.IsOk)
        {
            string systemFolder = programData.Value + @"\ssh";
            state.ReadFile($@"{systemFolder}\ssh_config", systemFolder, inheritedAllHosts: true, inheritedHosts: string.Empty, depth: 0);
        }

        return new SshSettings(state.Settings, state.Problem, state.AnyFile);
    }

    /// <summary>Splits a line into its keyword and arguments, honouring quotes, "=" and comments.</summary>
    internal static (string Keyword, List<string> Arguments)? SplitLine(string line)
    {
        var tokens = new List<string>();
        int i = 0;
        while (i < line.Length)
        {
            char c = line[i];
            if (char.IsWhiteSpace(c) || (c == '=' && tokens.Count == 1))
            {
                i++;
                continue;
            }

            if (c == '#')
            {
                break;
            }

            if (c == '"')
            {
                int end = line.IndexOf('"', i + 1);
                if (end < 0)
                {
                    return null;
                }

                tokens.Add(line[(i + 1)..end]);
                i = end + 1;
                continue;
            }

            int start = i;
            while (i < line.Length && !char.IsWhiteSpace(line[i]) && line[i] != '"' && !(line[i] == '=' && tokens.Count == 0))
            {
                i++;
            }

            tokens.Add(line[start..i]);
        }

        return tokens.Count == 0 ? (string.Empty, []) : (tokens[0].ToLowerInvariant(), tokens[1..]);
    }

    private sealed class ReadState(SystemProbes probes)
    {
        private int _files;

        public List<SshSetting> Settings { get; } = [];

        public string? Problem { get; set; }

        public bool AnyFile { get; private set; }

        public void ReadFile(string path, string baseFolder, bool inheritedAllHosts, string inheritedHosts, int depth)
        {
            string name = path[(path.LastIndexOf('\\') + 1)..];
            ProbeResult<string> text = probes.Files.ReadText(path);
            if (text.Status == ProbeStatus.NotFound)
            {
                // OpenSSH ignores an included file that does not exist.
                return;
            }

            AnyFile = true;
            if (!text.IsOk)
            {
                Problem ??= $"{name} could not be read: {text.Detail ?? text.Status.ToString()}";
                return;
            }

            if (++_files > MaximumFiles || depth > MaximumIncludeDepth)
            {
                Problem ??= $"{name}: too many included files.";
                return;
            }

            bool allHosts = inheritedAllHosts;
            string hosts = inheritedHosts;
            int number = 0;
            foreach (string raw in text.Value!.Split('\n'))
            {
                number++;
                string source = $"{name}, line {number}";
                (string Keyword, List<string> Arguments)? split = SplitLine(raw.Trim());
                if (split is null)
                {
                    Problem ??= $"Could not evaluate {source}: a quote is not closed.";
                    continue;
                }

                (string keyword, List<string> arguments) = split.Value;
                if (keyword.Length == 0)
                {
                    continue;
                }

                switch (keyword)
                {
                    case "host":
                        // A block inside an included file cannot widen the block that included it.
                        allHosts = inheritedAllHosts && arguments.Contains("*");
                        hosts = Combine(inheritedHosts, "Host " + string.Join(' ', arguments));
                        break;

                    case "match":
                        allHosts = inheritedAllHosts && arguments.Count > 0 &&
                            arguments[^1].Equals("all", StringComparison.OrdinalIgnoreCase) &&
                            arguments.SkipLast(1).All(a => a.Equals("final", StringComparison.OrdinalIgnoreCase) ||
                                a.Equals("canonical", StringComparison.OrdinalIgnoreCase));
                        hosts = Combine(inheritedHosts, "Match " + string.Join(' ', arguments));
                        break;

                    case "include":
                        foreach (string pattern in arguments)
                        {
                            Include(pattern, baseFolder, allHosts, hosts, depth, source);
                        }

                        break;

                    default:
                        Settings.Add(new SshSetting(keyword, string.Join(' ', arguments), allHosts, hosts, source));
                        break;
                }
            }
        }

        private static string Combine(string outer, string inner) => outer.Length == 0 ? inner : $"{outer}, {inner}";

        private void Include(string pattern, string baseFolder, bool allHosts, string hosts, int depth, string source)
        {
            string path = pattern.Replace('/', '\\');
            if (path.StartsWith(@"~\", StringComparison.Ordinal))
            {
                ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
                if (!profile.IsOk)
                {
                    Problem ??= $"Could not evaluate {source}: the included file's place is not known.";
                    return;
                }

                path = profile.Value + path[1..];
            }
            else if (path.Contains('%', StringComparison.Ordinal) || path.Contains('$', StringComparison.Ordinal) || path.StartsWith('~'))
            {
                // Tokens and environment variables are expanded by OpenSSH; they are not guessed at here.
                Problem ??= $"Could not evaluate {source}: the included file's name uses a variable.";
                return;
            }
            else if (!Path.IsPathFullyQualified(path))
            {
                path = $@"{baseFolder}\{path}";
            }

            int lastSeparator = path.LastIndexOf('\\');
            string folder = path[..lastSeparator];
            string file = path[(lastSeparator + 1)..];
            if (folder.AsSpan().ContainsAny('*', '?'))
            {
                Problem ??= $"Could not evaluate {source}: a wildcard in a folder name is not followed.";
                return;
            }

            if (!file.AsSpan().ContainsAny('*', '?'))
            {
                ReadFile(path, baseFolder, allHosts, hosts, depth + 1);
                return;
            }

            ProbeResult<IReadOnlyList<FileEntry>> entries = probes.Files.List(folder);
            if (entries.Status == ProbeStatus.NotFound)
            {
                return;
            }

            if (!entries.IsOk)
            {
                Problem ??= $"Could not evaluate {source}: the folder of the included files could not be listed.";
                return;
            }

            foreach (FileEntry entry in entries.Value!)
            {
                if (!entry.IsDirectory && System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(file, entry.Name, ignoreCase: true))
                {
                    ReadFile($@"{folder}\{entry.Name}", baseFolder, allHosts, hosts, depth + 1);
                }
            }
        }
    }
}
