using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// The programs Windows starts for every user who signs in must not be replaceable by a
/// standard user: whoever replaces one runs code as each of them, with that user's rights.
/// Covers the start-up lists kept for the whole PC, what Windows itself starts at sign-in, and
/// the start-up folder shared by all users. Each user's own start-up list is theirs to change
/// and is not judged.
/// </summary>
public sealed class StartupProgramsCheck : ICheck
{
    public const string Id = "system.startup";

    internal const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    internal const string RunOnceKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    internal const string Run32Key = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    internal const string RunOnce32Key = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
    internal const string PolicyRunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
    internal const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    /// <summary>The folder under the shared data folder whose contents start for every user.</summary>
    internal const string StartupFolder = @"Microsoft\Windows\Start Menu\Programs\StartUp";

    private const string What = "the programs that start with Windows";

    private static readonly (string Key, bool View32, bool Policy)[] Lists =
    [
        (RunKey, false, false),
        (RunOnceKey, false, false),
        (Run32Key, true, false),
        (RunOnce32Key, true, false),
        (PolicyRunKey, false, true),
    ];

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.SystemIntegrity, Severity.Medium, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        IRegistryProbe registry = context.Probes.Registry;
        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("start-up program", "start-up programs", context.IsElevated);

        foreach ((string key, bool view32, bool policy) in Lists)
        {
            ProbeResult<IReadOnlyList<string>> names = registry.GetValueNames(RegistryRoot.LocalMachine, key);
            if (names.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!names.IsOk)
            {
                return ProbeOutcomes.FromFailure(names, What);
            }

            // Whoever can write to the list can add a program to it.
            string source = $@"HKLM\{key}";
            Verdict list = judge.Key(RegistryRoot.LocalMachine, key);
            if (list.Kind != VerdictKind.Protected)
            {
                report.Add("Start-up list", list, source);
            }

            foreach (string name in names.Value!)
            {
                context.Cancellation.ThrowIfCancellationRequested();
                int before = report.Problems;
                Add(report, judge, machine, registry, key, name, $"Start-up entry: {Shown(name)}", view32);
                report.ManagedByPolicy |= policy && report.Problems > before;
            }
        }

        // What Windows starts for every sign-in: the desktop, and the program that sets it up.
        ProbeResult<IReadOnlyList<string>> winlogon = registry.GetValueNames(RegistryRoot.LocalMachine, WinlogonKey);
        if (!winlogon.IsOk && winlogon.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(winlogon, What);
        }

        if (winlogon.IsOk && judge.Key(RegistryRoot.LocalMachine, WinlogonKey) is { Kind: not VerdictKind.Protected } settings)
        {
            report.Add("Windows sign-in settings", settings, $@"HKLM\{WinlogonKey}");
        }

        foreach (string name in (string[])["Shell", "Userinit"])
        {
            Add(report, judge, machine, registry, WinlogonKey, name, $"Windows sign-in: {name}", view32: false);
        }

        AddFolder(context, report, judge, $@"{machine.ProgramData}\{StartupFolder}");
        return report.Outcome("No program is set to start for every user.");
    }

    /// <summary>One value of a start-up list. Windows takes several programs from one value, separated by commas, at sign-in.</summary>
    private static void Add(
        EntryReport report, ProgramJudge judge, MachineContext machine, IRegistryProbe registry, string key, string name, string item, bool view32)
    {
        string source = $@"HKLM\{key}";
        ProbeResult<RegistryValue> value = registry.GetValue(RegistryRoot.LocalMachine, key, name);
        if (value.Status == ProbeStatus.NotFound)
        {
            return;
        }

        if (!value.IsOk)
        {
            report.Unread(item, value.Detail ?? "The entry could not be read", value.Status == ProbeStatus.AccessDenied, source);
            return;
        }

        if (value.Value!.Type != RegistryValueType.Text)
        {
            report.Unread(item, "The entry is not text", needsAdministrator: false, source);
            return;
        }

        string[] commands = key == WinlogonKey ? value.Value.Text.Split(',', StringSplitOptions.RemoveEmptyEntries) : [value.Value.Text];
        foreach (string command in commands)
        {
            ProgramReference reference = ProgramReference.Parse(command, CommandForm.CommandLine, machine, view32);
            if (reference.Kind != ReferenceKind.Empty)
            {
                report.Add(item, judge.Command(reference), source);
            }
        }
    }

    /// <summary>
    /// The folder whose contents start for every user. Its shortcuts are files a user could
    /// rewrite; where they point is not read.
    /// </summary>
    private static void AddFolder(CheckContext context, EntryReport report, ProgramJudge judge, string folder)
    {
        ProbeResult<IReadOnlyList<FileEntry>> entries = context.Probes.Files.List(folder);
        if (entries.Status == ProbeStatus.NotFound)
        {
            return;
        }

        const string Item = "Start-up folder for all users";
        if (!entries.IsOk)
        {
            report.Unread(Item, entries.Detail ?? "The folder could not be listed", entries.Status == ProbeStatus.AccessDenied, folder);
            return;
        }

        report.Add(Item, judge.Folder(folder), folder);
        FileEntry[] started = [.. entries.Value!.Where(e => !e.IsDirectory && !e.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))];
        foreach (FileEntry entry in started)
        {
            context.Cancellation.ThrowIfCancellationRequested();
            report.Add($"Start-up shortcut: {Shown(entry.Name)}", judge.File($@"{folder}\{entry.Name}"), folder);
        }

        if (started.Any(e => e.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)))
        {
            report.Note(Item, "Where its shortcuts point is not read", folder);
        }
    }

    /// <summary>A name as stored, kept to a length that fits a row.</summary>
    private static string Shown(string name) => name.Length <= 80 ? name : name[..80] + "…";
}
