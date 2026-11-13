namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>How Windows reads the text a program is named with.</summary>
internal enum CommandForm
{
    /// <summary>A program followed by its arguments, as in a start-up entry.</summary>
    CommandLine,

    /// <summary>A service's program: a command line that may also be written from the Windows folder.</summary>
    ServiceImage,

    /// <summary>A path and nothing else; spaces need no quotes.</summary>
    PathOnly,
}

/// <summary>What a stored command turned out to name.</summary>
internal enum ReferenceKind
{
    /// <summary>It could not be told which program is meant; <see cref="ProgramReference.Problem"/> says why.</summary>
    Unresolvable = 0,

    /// <summary>A program on a drive of this PC.</summary>
    Local,

    /// <summary>A program on another computer. It is never opened.</summary>
    Network,

    /// <summary>Nothing is stored.</summary>
    Empty,
}

/// <summary>
/// The program a stored command names. Only the program: arguments can hold secrets and are
/// never kept.
/// </summary>
/// <param name="Kind">What was found.</param>
/// <param name="Candidates">
/// The files Windows would try, in its order. More than one when the program is named without
/// a folder, or without quotes around a path that has spaces: Windows then runs the first that
/// exists, so each earlier one is a place where another program could be put.
/// </param>
/// <param name="Quoted">Whether the program was written in quotes.</param>
/// <param name="ByName">Whether the program is named without a folder and looked up.</param>
/// <param name="PerUser">Whether the path differs per account ("%APPDATA%"), so that each user has their own copy.</param>
/// <param name="CommandOnly">Whether the program is one that runs what its arguments say, and what that is could not be told.</param>
/// <param name="Target">What such a program was asked to run, when that could be told.</param>
/// <param name="Problem">Why nothing could be told, for <see cref="ReferenceKind.Unresolvable"/>.</param>
/// <param name="Complete">
/// False when the text had no quotes and nothing in it ends the way a program does, so that
/// where the program stops and its arguments begin is a guess. Only the first candidate is
/// then sure to hold no argument.
/// </param>
internal sealed record ProgramReference(
    ReferenceKind Kind,
    IReadOnlyList<string> Candidates,
    bool Quoted = false,
    bool ByName = false,
    bool PerUser = false,
    bool CommandOnly = false,
    ProgramReference? Target = null,
    string? Problem = null,
    bool Complete = true)
{
    /// <summary>The longest command read. Windows itself stops at 32,767 characters; nothing honest is near this.</summary>
    public const int MaximumLength = 4096;

    /// <summary>The most places looked at for one command.</summary>
    public const int MaximumCandidates = 16;

    /// <summary>Endings Windows runs or loads. A path without quotes is taken to end at the first of these.</summary>
    private static readonly string[] ProgramEndings =
        [".exe", ".com", ".bat", ".cmd", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".msi", ".ps1", ".vbs", ".js", ".jar", ".pif"];

    /// <summary>The path was written without quotes although it has spaces, so Windows has to guess where it ends.</summary>
    public bool Ambiguous => !Quoted && !ByName && Candidates.Count > 1;

    /// <summary>
    /// The file meant when none of the candidates exists. Candidates after it may hold
    /// arguments and are never shown.
    /// </summary>
    public string Intended => Candidates.Count == 0 ? string.Empty : ByName || !Complete ? Candidates[0] : Candidates[^1];

    private static ProgramReference Empty { get; } = new(ReferenceKind.Empty, []);

    private static ProgramReference Network { get; } = new(ReferenceKind.Network, []);

    public static ProgramReference Parse(string? text, CommandForm form, MachineContext machine, bool view32 = false) =>
        Parse(text, form, machine, view32, followHost: true);

    private static ProgramReference Unresolvable(string problem) => new(ReferenceKind.Unresolvable, [], Problem: problem);

    private static ProgramReference Parse(string? text, CommandForm form, MachineContext machine, bool view32, bool followHost)
    {
        ArgumentNullException.ThrowIfNull(machine);
        string line = (text ?? string.Empty).Trim();
        if (line.Length == 0)
        {
            return Empty;
        }

        if (line.Length > MaximumLength || line.Any(char.IsControl))
        {
            return Unresolvable("The entry is not a command that can be read.");
        }

        line = machine.Expand(line, view32);

        string program;
        string rest = string.Empty;
        bool quoted = false;
        if (line[0] == '"')
        {
            int close = line.IndexOf('"', 1);
            if (close < 0)
            {
                return Unresolvable("The entry opens a quote and does not close it.");
            }

            (program, rest, quoted) = (line[1..close].Trim(), line[(close + 1)..], true);
        }
        else if (form == CommandForm.PathOnly)
        {
            program = WithoutArguments(line);
        }
        else
        {
            return Unquoted(line, form, machine, view32, followHost);
        }

        // A plain path has no arguments, so there is nothing a script host could be told to run.
        followHost &= form != CommandForm.PathOnly || rest.Trim().Length > 0;
        program = FromWindowsForm(program, form, machine);
        if (program.Length == 0)
        {
            return Empty;
        }

        if (IsNetworkPath(program))
        {
            return Network;
        }

        if (Unknown(program) is { } unknown)
        {
            return unknown with { Quoted = quoted };
        }

        if (MachineContext.IsLocalPath(program))
        {
            // Windows adds ".exe" to a program named without an ending; a plain path is taken as written.
            string file = form != CommandForm.PathOnly && !HasEnding(program) ? program + ".exe" : program;
            return WithTarget(new ProgramReference(ReferenceKind.Local, [Redirect(file, machine, view32)], quoted), rest, machine, view32, followHost);
        }

        return IsName(program)
            ? WithTarget(ByNameIn(program, machine, view32) with { Quoted = quoted }, rest, machine, view32, followHost)
            : Unresolvable("The entry names a program by a path that is not complete.");
    }

    /// <summary>
    /// A place meant to hold a path sometimes holds arguments after it. They are cut off where
    /// the text first ends the way a program does, so that they are never kept or shown.
    /// </summary>
    private static string WithoutArguments(string path)
    {
        for (int space = path.IndexOfAny([' ', '\t']); space >= 0; space = path.IndexOfAny([' ', '\t'], space + 1))
        {
            if (HasProgramEnding(path[..space]))
            {
                return path[..space];
            }
        }

        return path;
    }

    /// <summary>A command line whose program is not in quotes.</summary>
    private static ProgramReference Unquoted(string line, CommandForm form, MachineContext machine, bool view32, bool followHost)
    {
        line = FromWindowsForm(line, form, machine);
        if (IsNetworkPath(line))
        {
            return Network;
        }

        int firstSpace = line.IndexOfAny([' ', '\t']);
        string firstWord = firstSpace < 0 ? line : line[..firstSpace];
        if (IsName(firstWord))
        {
            return Unknown(firstWord) ??
                WithTarget(ByNameIn(firstWord, machine, view32), firstSpace < 0 ? string.Empty : line[firstSpace..], machine, view32, followHost);
        }

        if (!MachineContext.IsLocalPath(line))
        {
            return Unknown(firstWord) ?? Unresolvable("The entry names a program by a path that is not complete.");
        }

        // Windows tries the text up to each space in turn, adding ".exe" where there is no
        // ending, and runs the first file it finds. The trying stops here where the rest can
        // only be arguments, so that no argument ends up in a candidate that is shown.
        var candidates = new List<string>();
        string rest;
        bool complete;
        int space = firstSpace;
        while (true)
        {
            string upTo = space < 0 ? line : line[..space];
            complete = HasProgramEnding(upTo);
            if (upTo.Length > 0 && upTo[^1] is not ('\\' or '/' or ' ' or '\t'))
            {
                candidates.Add(Redirect(HasEnding(upTo) ? upTo : upTo + ".exe", machine, view32));
            }

            if (complete || space < 0 || candidates.Count == MaximumCandidates || !PathGoesOn(line, space))
            {
                rest = space < 0 ? string.Empty : line[space..];
                break;
            }

            space = line.IndexOfAny([' ', '\t'], space + 1);
        }

        if (candidates.Count == 0)
        {
            return Unresolvable("The entry names a folder, not a program.");
        }

        return Unknown(candidates[^1]) ??
            WithTarget(new ProgramReference(ReferenceKind.Local, candidates, Complete: complete), rest, machine, view32, followHost);
    }

    /// <summary>
    /// Whether the words after a space can still be part of the program's path: one of them
    /// continues the path or ends the way a program does, before any that is plainly an
    /// argument (a switch, a quoted text, another full path).
    /// </summary>
    private static bool PathGoesOn(string line, int space)
    {
        foreach (string word in line[space..].Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (word[0] is '-' or '/' or '"' || word.Contains(':', StringComparison.Ordinal) || word.Contains('"', StringComparison.Ordinal))
            {
                return false;
            }

            if (word.Contains('\\', StringComparison.Ordinal) || HasProgramEnding(word))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>A program named without a folder: the places Windows looks, in order.</summary>
    private static ProgramReference ByNameIn(string name, MachineContext machine, bool view32)
    {
        string file = HasEnding(name) ? name : name + ".exe";
        return new ProgramReference(
            ReferenceKind.Local,
            [.. machine.SearchFolders(view32).Take(MaximumCandidates).Select(folder => $@"{folder}\{file}")],
            ByName: true);
    }

    /// <summary>The reference for a path that still holds a variable, if it does.</summary>
    private static ProgramReference? Unknown(string program) =>
        MachineContext.HasPerUserVariable(program)
            ? new ProgramReference(ReferenceKind.Unresolvable, [], PerUser: true, Problem: "The path is each user's own.")
        : MachineContext.HasVariable(program) ? Unresolvable("The path uses a variable that is not set for the whole PC.")
        : null;

    /// <summary>The ways Windows writes its own folder in a service's program path.</summary>
    private static string FromWindowsForm(string path, CommandForm form, MachineContext machine)
    {
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            return machine.Windows + path[@"\SystemRoot".Length..];
        }

        // "\??\C:\..." and "\\?\C:\..." are a drive path written out in full.
        if ((path.StartsWith(@"\??\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal)) &&
            MachineContext.IsLocalPath(path[4..]))
        {
            return path[4..];
        }

        return form == CommandForm.ServiceImage &&
            (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            ? $@"{machine.Windows}\{path}"
            : path;
    }

    /// <summary>A 32-bit program asking for System32 is given SysWOW64.</summary>
    private static string Redirect(string path, MachineContext machine, bool view32)
    {
        string system32 = machine.System32 + "\\";
        return view32 && path.StartsWith(system32, StringComparison.OrdinalIgnoreCase)
            ? $@"{machine.SysWow64}\{path[system32.Length..]}"
            : path;
    }

    /// <summary>"\\server\share" in any spelling, including the long form "\\?\UNC\server\share".</summary>
    private static bool IsNetworkPath(string path) =>
        path.Length >= 2 && path[0] is '\\' or '/' && path[1] is '\\' or '/' &&
        !path.StartsWith(@"\\.\", StringComparison.Ordinal) &&
        (!path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase));

    private static bool IsName(string text) =>
        text.Length > 0 && text.IndexOfAny(['\\', '/', ':']) < 0;

    /// <summary>Whether the path ends the way a program or library does.</summary>
    private static bool HasProgramEnding(string path)
    {
        int name = path.LastIndexOfAny(['\\', '/']) + 1;
        return ProgramEndings.Any(ending => path.Length - name > ending.Length && path.EndsWith(ending, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Whether the file name has any ending at all; Windows adds ".exe" only when it has none.</summary>
    private static bool HasEnding(string path) =>
        path.LastIndexOf('.') > path.LastIndexOfAny(['\\', '/']) + 1;

    /// <summary>
    /// Some Windows programs only run what their arguments name. For those, in the Windows
    /// folder or named without a folder, the thing named is found too, one level deep.
    /// </summary>
    private static ProgramReference WithTarget(ProgramReference host, string rest, MachineContext machine, bool view32, bool followHost)
    {
        if (!followHost || host.Candidates.Count == 0)
        {
            return host;
        }

        // Windows PowerShell sits in a folder of its own under the Windows folder; the newer
        // PowerShell is installed under Program Files.
        string file = host.Candidates[^1];
        string name = Path.GetFileNameWithoutExtension(host.ByName ? host.Candidates[0] : file).ToUpperInvariant();
        bool fromWindows = host.ByName ||
            file.StartsWith(machine.Windows + "\\", StringComparison.OrdinalIgnoreCase) ||
            (name == "PWSH" && file.StartsWith(machine.ProgramFiles + "\\", StringComparison.OrdinalIgnoreCase));
        if (!fromWindows)
        {
            return host;
        }

        List<string> words = Words(rest);
        string? named = null;
        bool commandLine = false;
        switch (name)
        {
            case "RUNDLL32":
                // The library ends at the comma before the function's name.
                string library = rest.TrimStart();
                int closing = library.StartsWith('"') ? library.IndexOf('"', 1) : -1;
                named = library.Length == 0 ? null
                    : closing > 0 ? library[1..closing]
                    : library[..(library.IndexOfAny([',', ' ', '\t']) is >= 0 and int end ? end : library.Length)];
                break;
            case "REGSVR32":
                named = words.FirstOrDefault(word => !word.StartsWith('/') && !word.StartsWith('-'));
                break;
            case "WSCRIPT" or "CSCRIPT":
                named = words.FirstOrDefault(word => !word.StartsWith("//", StringComparison.Ordinal));
                break;
            case "MSIEXEC":
                named = After(words, "/i", "-i", "/package", "-package", "/a", "-a");
                named = named is { Length: > 0 } && named[0] == '{' ? string.Empty : named;
                break;
            case "POWERSHELL" or "PWSH":
                named = After(words, "-File", "/File", "-f");
                break;
            case "CMD":
                int run = rest.IndexOf("/c", StringComparison.OrdinalIgnoreCase) is >= 0 and int c ? c
                    : rest.IndexOf("/k", StringComparison.OrdinalIgnoreCase);
                named = run < 0 ? null : InnerCommand(rest[(run + 2)..]);
                commandLine = true;
                break;
            default:
                return host;
        }

        // A switch is not a file. Neither is a script named without its folder: where that
        // is looked for depends on where the program happens to be started.
        bool lookedUp = name is "RUNDLL32" or "REGSVR32" or "CMD";
        if (named is null ||
            (named.Length > 0 && named[0] is '-' or '/' && !IsNetworkPath(named)) ||
            (named.Length > 0 && !lookedUp && !MachineContext.IsLocalPath(named) && !IsNetworkPath(named) && !MachineContext.HasVariable(named)))
        {
            return host with { CommandOnly = true };
        }

        if (named.Length == 0)
        {
            return host;
        }

        ProgramReference target = Parse(named, commandLine ? CommandForm.CommandLine : CommandForm.PathOnly, machine, view32, followHost: false);
        return target.Kind is ReferenceKind.Local or ReferenceKind.Network || target.PerUser
            ? host with { Target = target }
            : host with { CommandOnly = true };
    }

    /// <summary>What "cmd /c" was given, when it is one program and not a script written on one line.</summary>
    private static string? InnerCommand(string text)
    {
        string command = text.Trim();

        // cmd drops one pair of quotes around the whole command: /c ""C:\a b\c.exe" argument".
        // Only the program is wanted, so dropping the opening one is enough.
        if (command.StartsWith("\"\"", StringComparison.Ordinal) && command.Length > 2 && command[2] != '"')
        {
            command = command[1..];
        }

        // A command of cmd's own (del, copy, start) is not a program on disk.
        string first = command.Split([' ', '\t', '/', '.'], 2)[0];
        return command.Length == 0 || command.IndexOfAny(['&', '|', '<', '>', '^', '(']) >= 0 ||
            OwnCommands.Contains(first, StringComparer.OrdinalIgnoreCase)
            ? null
            : command;
    }

    /// <summary>The commands cmd carries out itself.</summary>
    private static readonly string[] OwnCommands =
    [
        "assoc", "break", "call", "cd", "chdir", "cls", "color", "copy", "date", "del", "dir", "echo", "endlocal", "erase", "exit",
        "for", "ftype", "goto", "if", "md", "mkdir", "mklink", "move", "path", "pause", "popd", "prompt", "pushd", "rd", "rem", "ren",
        "rename", "rmdir", "set", "setlocal", "shift", "start", "time", "title", "type", "ver", "verify", "vol",
    ];

    private static string? After(List<string> words, params string[] switches)
    {
        int at = words.FindIndex(word => switches.Any(s => word.Equals(s, StringComparison.OrdinalIgnoreCase)));
        return at >= 0 && at + 1 < words.Count ? words[at + 1] : null;
    }

    /// <summary>The arguments, split at spaces outside quotes, without the quotes.</summary>
    private static List<string> Words(string text)
    {
        var words = new List<string>();
        var word = new System.Text.StringBuilder();
        bool inQuotes = false;
        bool any = false;
        foreach (char c in text)
        {
            if (c == '"')
            {
                (inQuotes, any) = (!inQuotes, true);
            }
            else if (c is ' ' or '\t' && !inQuotes)
            {
                if (any)
                {
                    words.Add(word.ToString());
                    word.Clear();
                    any = false;
                }
            }
            else
            {
                word.Append(c);
                any = true;
            }
        }

        if (any)
        {
            words.Add(word.ToString());
        }

        return words;
    }
}
