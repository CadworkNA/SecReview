using SecReview.Probing;
using SecReview.SupplyChain;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// What a command stored for the whole PC is read against: the folders and variables that are
/// the same for every account. The environment of this process is never used, since it belongs
/// to one user and a stored command runs for others.
/// </summary>
/// <param name="Windows">The Windows folder.</param>
/// <param name="ProgramFiles">The folder for 64-bit programs.</param>
/// <param name="ProgramFilesX86">The folder for 32-bit programs.</param>
/// <param name="ProgramData">The shared data folder.</param>
/// <param name="Variables">Variable names and what they stand for.</param>
/// <param name="PathEntries">The PC's search path, as written, one entry each.</param>
internal sealed record MachineContext(
    string Windows,
    string ProgramFiles,
    string ProgramFilesX86,
    string ProgramData,
    IReadOnlyDictionary<string, string> Variables,
    IReadOnlyList<string> PathEntries)
{
    /// <summary>Variables that stand for something different for each account.</summary>
    private static readonly HashSet<string> PerUserNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "HOMEDRIVE", "HOMEPATH", "USERNAME", "USERDOMAIN",
        "OneDrive", "OneDriveConsumer", "OneDriveCommercial",
    };

    public string System32 => $@"{Windows}\System32";

    public string SysWow64 => $@"{Windows}\SysWOW64";

    /// <summary>Where Windows looks for a program named without a folder, in order.</summary>
    public IEnumerable<string> SearchFolders(bool view32) =>
        ((string[])[view32 ? SysWow64 : System32, Windows])
        .Concat(PathEntries.Select(entry => Expand(entry, view32).TrimEnd('\\', '/')).Where(IsLocalPath))
        .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>"C:\..." or "C:/...": a path on a drive, complete.</summary>
    public static bool IsLocalPath(string text) =>
        text.Length >= 3 && char.IsAsciiLetter(text[0]) && text[1] == ':' && text[2] is '\\' or '/';

    /// <summary>Whether the text still holds a variable that differs per account ("%APPDATA%").</summary>
    public static bool HasPerUserVariable(string text) =>
        Names(text).Any(PerUserNames.Contains);

    /// <summary>Whether the text still holds something written as a variable.</summary>
    public static bool HasVariable(string text) => Names(text).Any();

    /// <summary>
    /// The text with the variables that mean the same for every account replaced. Others are
    /// left as written, so that a caller can see them.
    /// </summary>
    public string Expand(string text, bool view32 = false)
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
            if (view32 && name.Equals("ProgramFiles", StringComparison.OrdinalIgnoreCase))
            {
                expanded.Append(ProgramFilesX86);
                position = close + 1;
            }
            else if (Variables.TryGetValue(name, out string? value))
            {
                expanded.Append(value);
                position = close + 1;
            }
            else
            {
                // Not one of ours: keep the first "%" and look again from the next one.
                expanded.Append('%');
                position = open + 1;
            }
        }

        return expanded.ToString();
    }

    /// <summary>Reads the folders and the PC's variables. Returns the outcome when that fails.</summary>
    public static CheckOutcome? Load(SystemProbes probes, out MachineContext machine)
    {
        ArgumentNullException.ThrowIfNull(probes);
        machine = new MachineContext(string.Empty, string.Empty, string.Empty, string.Empty, new Dictionary<string, string>(), []);

        ProbeResult<string> windows = probes.Environment.Folder(KnownFolder.Windows);
        ProbeResult<string> programFiles = probes.Environment.Folder(KnownFolder.ProgramFiles);
        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!windows.IsOk || !programFiles.IsOk || !programData.IsOk || !IsLocalPath(windows.Value!))
        {
            return CheckOutcome.Error("Windows did not say where its folders are.");
        }

        string programFilesX86 = probes.Environment.Folder(KnownFolder.ProgramFilesX86) is { IsOk: true } x86 ? x86.Value! : programFiles.Value!;
        string drive = windows.Value![..2];
        var variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windows.Value,
            ["windir"] = windows.Value,
            ["SystemDrive"] = drive,
            ["ProgramFiles"] = programFiles.Value!,
            ["ProgramW6432"] = programFiles.Value!,
            ["ProgramFiles(x86)"] = programFilesX86,
            ["CommonProgramFiles"] = $@"{programFiles.Value}\Common Files",
            ["CommonProgramW6432"] = $@"{programFiles.Value}\Common Files",
            ["CommonProgramFiles(x86)"] = $@"{programFilesX86}\Common Files",
            ["ProgramData"] = programData.Value!,
            ["ALLUSERSPROFILE"] = programData.Value!,
            ["PUBLIC"] = $@"{drive}\Users\Public",
        };
        machine = new MachineContext(windows.Value, programFiles.Value!, programFilesX86, programData.Value!, variables, []);

        // The PC's own variables may be written with the ones above ("%SystemRoot%\tools").
        ProbeResult<IReadOnlyList<string>> names = probes.Registry.GetValueNames(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey);
        if (!names.IsOk && names.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(names, "the PC's environment variables");
        }

        string path = string.Empty;
        foreach (string name in names.Value ?? [])
        {
            ProbeResult<RegistryValue> value = probes.Registry.GetValue(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, name);
            if (!value.IsOk && value.Status != ProbeStatus.NotFound)
            {
                return ProbeOutcomes.FromFailure(value, "the PC's environment variables");
            }

            if (value is not { IsOk: true, Value.Type: RegistryValueType.Text })
            {
                continue;
            }

            if (name.Equals("Path", StringComparison.OrdinalIgnoreCase))
            {
                path = value.Value.Text;
            }
            else if (!PerUserNames.Contains(name))
            {
                variables.TryAdd(name, machine.Expand(value.Value.Text));
            }
        }

        machine = machine with
        {
            PathEntries = [.. path.Split(';').Select(entry => entry.Trim().Trim('"').Trim()).Where(entry => entry.Length > 0)],
        };
        return null;
    }

    /// <summary>What is written between pairs of "%" and could be a variable's name.</summary>
    private static IEnumerable<string> Names(string text)
    {
        int position = 0;
        while (position < text.Length)
        {
            int open = text.IndexOf('%', position);
            int close = open < 0 ? -1 : text.IndexOf('%', open + 1);
            if (close < 0)
            {
                yield break;
            }

            string name = text[(open + 1)..close];
            if (name.Length > 0 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '(' or ')'))
            {
                yield return name;
                position = close + 1;
            }
            else
            {
                position = open + 1;
            }
        }
    }
}
