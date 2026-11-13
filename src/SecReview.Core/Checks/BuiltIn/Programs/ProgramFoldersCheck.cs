using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// A program is only as safe as the folder it sits in. Windows protects what is installed
/// under Program Files; a folder made at the top of the drive is, unless someone changes that,
/// open to every user. This check looks at the folders under Program Files and at the folders
/// at the top of the Windows drive that hold programs, and fails for those standard users can
/// change. Folders without programs are not its business.
/// </summary>
public sealed class ProgramFoldersCheck : ICheck
{
    public const string Id = "system.programfolders";

    /// <summary>How far below a top folder programs are looked for.</summary>
    internal const int MaximumDepth = 3;

    /// <summary>The most folders listed, and entries looked at, below one top folder.</summary>
    internal const int MaximumFolders = 50;
    internal const int MaximumEntries = 5000;

    /// <summary>Folders Windows puts at the top of its drive, which have checks or protections of their own.</summary>
    private static readonly HashSet<string> WindowsOwn = new(StringComparer.OrdinalIgnoreCase)
    {
        "Program Files", "Program Files (x86)", "ProgramData", "Users", "PerfLogs", "Recovery", "System Volume Information",
        "$Recycle.Bin", "$WinREAgent", "$Windows.~BT", "$Windows.~WS", "$SysReset", "$GetCurrent", "Windows.old", "Config.Msi",
        "MSOCache", "OneDriveTemp", "Documents and Settings",
    };

    private static readonly string[] ProgramEndings = [".exe", ".dll", ".sys", ".com", ".scr", ".msi", ".cmd", ".bat", ".ps1"];

    private enum Looked
    {
        NoPrograms,
        Programs,
        NotInFull,
        Unread,
    }

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.SystemIntegrity, Severity.Medium, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        IFileProbe files = context.Probes.Files;
        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("program folder", "program folders", context.IsElevated);

        foreach (string root in new[] { machine.ProgramFiles, machine.ProgramFilesX86 }.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ProbeResult<IReadOnlyList<FileEntry>> installed = files.List(root);
            if (installed.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!installed.IsOk)
            {
                return ProbeOutcomes.FromFailure(installed, "the program folders");
            }

            report.Add($"Program folder: {root}", judge.Folder(root), root);
            foreach (FileEntry entry in installed.Value!.Where(e => e.IsDirectory && !e.IsLink))
            {
                context.Cancellation.ThrowIfCancellationRequested();
                string folder = $@"{root}\{entry.Name}";
                report.Add($"Program folder: {folder}", judge.Folder(folder), folder);
            }
        }

        // The top of the Windows drive: Windows lets every user create folders there, and
        // what they create is theirs to fill.
        string drive = machine.Windows[..3];
        ProbeResult<IReadOnlyList<FileEntry>> top = files.List(drive);
        if (!top.IsOk)
        {
            return ProbeOutcomes.FromFailure(top, $"the folders at the top of drive {drive[..2]}");
        }

        Verdict topItself = judge.Folder(drive);
        if (topItself.Kind != VerdictKind.Protected)
        {
            report.Add($"The top of drive {drive[..2]}", topItself, drive);
        }

        string windows = Path.GetFileName(machine.Windows);
        foreach (FileEntry entry in top.Value!.Where(e => e.IsDirectory && !e.IsLink))
        {
            context.Cancellation.ThrowIfCancellationRequested();
            if (WindowsOwn.Contains(entry.Name) || entry.Name.Equals(windows, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string folder = drive + entry.Name;
            string item = $"Folder with programs: {folder}";
            Verdict verdict = judge.Folder(folder);
            if (verdict.Kind == VerdictKind.Unknown)
            {
                report.Unread($"Folder: {folder}", verdict.Found, verdict.NeedsAdministrator, folder);
            }
            else if (verdict.IsProblem)
            {
                switch (Look(context, files, folder))
                {
                    case Looked.Programs:
                        report.Problem(item, verdict.Found, folder);
                        break;
                    case Looked.NotInFull:
                        report.Note($"Folder: {folder}", $"{verdict.Found}; it was not looked through in full for programs", folder);
                        break;
                    case Looked.Unread:
                        report.Unread($"Folder: {folder}", $"{verdict.Found}; what it holds could not be listed", needsAdministrator: false, folder);
                        break;
                }
            }
        }

        return report.Outcome("No program folders were found.");
    }

    /// <summary>Whether a folder holds programs, looking a little way down and no further.</summary>
    private static Looked Look(CheckContext context, IFileProbe files, string top)
    {
        var waiting = new Queue<(string Folder, int Depth)>();
        waiting.Enqueue((top, 0));
        int folders = 0;
        int entries = 0;
        bool cutShort = false;
        while (waiting.Count > 0)
        {
            context.Cancellation.ThrowIfCancellationRequested();
            (string folder, int depth) = waiting.Dequeue();
            if (++folders > MaximumFolders)
            {
                return Looked.NotInFull;
            }

            ProbeResult<IReadOnlyList<FileEntry>> listed = files.List(folder);
            if (listed.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!listed.IsOk)
            {
                return Looked.Unread;
            }

            foreach (FileEntry entry in listed.Value!)
            {
                if (++entries > MaximumEntries)
                {
                    return Looked.NotInFull;
                }

                if (entry.IsLink)
                {
                    continue;
                }

                if (!entry.IsDirectory)
                {
                    if (ProgramEndings.Any(ending => entry.Name.EndsWith(ending, StringComparison.OrdinalIgnoreCase)))
                    {
                        return Looked.Programs;
                    }
                }
                else if (depth < MaximumDepth)
                {
                    waiting.Enqueue(($@"{folder}\{entry.Name}", depth + 1));
                }
                else
                {
                    cutShort = true;
                }
            }
        }

        return cutShort ? Looked.NotInFull : Looked.NoPrograms;
    }
}
