using System.Globalization;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// A scheduled task that runs as the system, as an administrator or "with highest
/// privileges" starts its program without asking anyone. A standard user who can replace that
/// program runs code with those rights the next time the task fires. The tasks are read from
/// the files Windows keeps for them, which only an administrator may read; no task is started
/// and the scheduler is not asked. Tasks that run with a user's ordinary rights are counted
/// and not judged.
/// </summary>
public sealed class ScheduledTasksCheck : ICheck
{
    public const string Id = "system.tasks";

    /// <summary>The folder under System32 that holds one file per task.</summary>
    internal const string TasksFolder = "Tasks";

    /// <summary>The most task files read. A PC with more gets "could not check", not a partial answer.</summary>
    internal const int MaximumTasks = 2000;

    private const int MaximumDepth = 16;

    private static readonly string[] SystemAccounts =
    [
        "S-1-5-18", "S-1-5-19", "S-1-5-20", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "LOCALSYSTEM",
        @"NT AUTHORITY\SYSTEM", @"NT AUTHORITY\LOCAL SERVICE", @"NT AUTHORITY\NETWORK SERVICE", @"NT AUTHORITY\LOCALSERVICE", @"NT AUTHORITY\NETWORKSERVICE",
    ];

    private static readonly string[] AdministratorGroups = ["S-1-5-32-544", "Administrators", @"BUILTIN\Administrators"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SystemIntegrity, Severity.High, AdminNeed.Yes, CheckScope.Machine);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Windows refuses the files to anyone else; an empty answer without rights would read as "none".
        if (!context.IsElevated)
        {
            return CheckOutcome.NeedsAdmin("Windows shows the scheduled tasks' files to administrators only.");
        }

        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        string root = $@"{machine.System32}\{TasksFolder}";
        var files = new List<string>();
        if (Collect(context, root, files) is { } unlisted)
        {
            return unlisted;
        }

        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("task program", "task programs", context.IsElevated);
        int ordinary = 0;
        foreach (string file in files)
        {
            context.Cancellation.ThrowIfCancellationRequested();
            string item = $"Task: {file[root.Length..]}";
            ProbeResult<string> text = context.Probes.Files.ReadText(file);
            if (text.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            MarkupFile? task = text.IsOk ? MarkupReader.Read(text.Value!) : null;
            if (task is not { IsOk: true } || !task.Root!.Is("Task"))
            {
                report.Unread(item, text.IsOk ? "Its file is not a task Windows wrote" : text.Detail ?? "Its file could not be read", needsAdministrator: false, file);
                continue;
            }

            ordinary += Add(report, judge, machine, context.Probes.Registry, task.Root, item, file) ? 0 : 1;
        }

        if (ordinary > 0)
        {
            report.Note("Ordinary tasks", string.Create(
                CultureInfo.InvariantCulture, $"{ordinary} {(ordinary == 1 ? "task runs" : "tasks run")} with a user's ordinary rights; not judged"));
        }

        return report.Outcome("No scheduled task runs with high rights.");
    }

    /// <summary>Every task file below the folder; links are not followed. Returns the outcome when it cannot be done.</summary>
    private static CheckOutcome? Collect(CheckContext context, string root, List<string> files)
    {
        var waiting = new Stack<(string Folder, int Depth)>();
        waiting.Push((root, 0));
        while (waiting.Count > 0)
        {
            context.Cancellation.ThrowIfCancellationRequested();
            (string folder, int depth) = waiting.Pop();
            ProbeResult<IReadOnlyList<FileEntry>> entries = context.Probes.Files.List(folder);
            if (entries.Status == ProbeStatus.NotFound && depth > 0)
            {
                // Removed while the folders were being listed.
                continue;
            }

            if (!entries.IsOk)
            {
                return ProbeOutcomes.FromFailure(entries, "the scheduled tasks");
            }

            foreach (FileEntry entry in entries.Value!.Where(e => !e.IsLink))
            {
                if (!entry.IsDirectory)
                {
                    files.Add($@"{folder}\{entry.Name}");
                }
                else if (depth < MaximumDepth)
                {
                    waiting.Push(($@"{folder}\{entry.Name}", depth + 1));
                }

                if (files.Count > MaximumTasks)
                {
                    return CheckOutcome.Error(string.Create(
                        CultureInfo.InvariantCulture, $"More than {MaximumTasks} scheduled tasks are set up; they were not read."));
                }
            }
        }

        files.Sort(StringComparer.OrdinalIgnoreCase);
        return null;
    }

    /// <summary>Judges what one task runs. False when the task runs with ordinary rights and was not judged.</summary>
    private static bool Add(
        EntryReport report, ProgramJudge judge, MachineContext machine, IRegistryProbe registry, MarkupElement task, string item, string file)
    {
        MarkupElement[] principals = [.. task.ChildrenNamed("Principals").SelectMany(p => p.ChildrenNamed("Principal"))];
        if (!principals.Any(IsHigh))
        {
            return false;
        }

        bool disabled = task.Child("Settings")?.Child("Enabled")?.Text.Equals("false", StringComparison.OrdinalIgnoreCase) == true;
        foreach (MarkupElement action in task.ChildrenNamed("Actions").SelectMany(a => a.Children))
        {
            ProgramReference? reference = action switch
            {
                _ when action.Is("Exec") => Program(action, machine),
                _ when action.Is("ComHandler") => Component(action, machine, registry),
                _ => null,
            };
            if (reference is null || reference.Kind == ReferenceKind.Empty)
            {
                continue;
            }

            CommandVerdict verdict = judge.Command(reference);
            if (disabled && verdict.IsProblem)
            {
                report.Fine();
                report.Note(item, $"Disabled. {verdict.Found}", file);
            }
            else
            {
                report.Add(item, verdict, file);
            }
        }

        return true;
    }

    /// <summary>Whether the task runs as Windows itself, as the administrators group, or with all the rights its user has.</summary>
    private static bool IsHigh(MarkupElement principal) =>
        principal.Child("RunLevel")?.Text.Equals("HighestAvailable", StringComparison.OrdinalIgnoreCase) == true ||
        (principal.Child("UserId")?.Text is { } user && SystemAccounts.Contains(user, StringComparer.OrdinalIgnoreCase)) ||
        (principal.Child("GroupId")?.Text is { } group && AdministratorGroups.Contains(group, StringComparer.OrdinalIgnoreCase));

    /// <summary>A program and its arguments are stored apart; put together, the usual reading finds what a script host runs.</summary>
    private static ProgramReference Program(MarkupElement action, MachineContext machine)
    {
        string command = (action.Child("Command")?.Text ?? string.Empty).Trim().Trim('"').Trim();
        string arguments = action.Child("Arguments")?.Text ?? string.Empty;
        return command.Length == 0 || command.Contains('"', StringComparison.Ordinal)
            ? ProgramReference.Parse(command, CommandForm.PathOnly, machine)
            : ProgramReference.Parse($"\"{command}\" {arguments}", CommandForm.CommandLine, machine);
    }

    /// <summary>A task may name a registered component instead of a program: that component's file is what runs.</summary>
    private static ProgramReference? Component(MarkupElement action, MachineContext machine, IRegistryProbe registry)
    {
        string id = (action.Child("ClassId")?.Text ?? string.Empty).Trim();
        if (id.Length is 0 or > 64 || id.Contains('\\', StringComparison.Ordinal))
        {
            return null;
        }

        foreach ((string kind, CommandForm form) in new[] { ("InprocServer32", CommandForm.PathOnly), ("LocalServer32", CommandForm.CommandLine) })
        {
            ProbeResult<RegistryValue> value = registry.GetValue(
                RegistryRoot.LocalMachine, $@"{RegisteredComponentsCheck.ClassesKey}\{id}\{kind}", string.Empty);
            if (value is { IsOk: true, Value.Type: RegistryValueType.Text })
            {
                return ProgramReference.Parse(value.Value.Text, form, machine);
            }
        }

        return null;
    }
}
