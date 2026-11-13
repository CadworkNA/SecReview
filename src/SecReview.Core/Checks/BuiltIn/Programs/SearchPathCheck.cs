using SecReview.Probing;
using SecReview.SupplyChain;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// Windows, services and administrators' own commands look for programs in the folders of the
/// PC's search path, in order. A folder there that standard users can add files to lets them
/// put a program in front of the real one; so does an entry that is not a complete path, is
/// missing where they could create it, or lies on a network. Only the path set for the whole
/// PC is judged: each user's own addition to it is theirs.
/// </summary>
public sealed class SearchPathCheck : ICheck
{
    public const string Id = "system.searchpath";

    private const string Source = @"HKLM\" + PersistentEnvironment.MachineKey + @"\Path";

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.SystemIntegrity, Severity.High, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("search path folder", "search path folders", context.IsElevated);

        // Whoever can change the variables can add a folder of their own.
        Verdict variables = judge.Key(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey);
        if (variables.Kind is not (VerdictKind.Protected or VerdictKind.Missing))
        {
            report.Add("The PC's environment variables", variables, $@"HKLM\{PersistentEnvironment.MachineKey}");
        }

        foreach (string entry in machine.PathEntries.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            context.Cancellation.ThrowIfCancellationRequested();
            string folder = machine.Expand(entry).Replace('/', '\\');
            string item = $"Search path: {folder}";
            if (MachineContext.HasPerUserVariable(folder))
            {
                report.Fine();
                report.Note(item, "Each user's own folder; not judged", Source);
            }
            else if (MachineContext.HasVariable(folder))
            {
                report.Unread(item, "Uses a variable that is not set for the whole PC", needsAdministrator: false, Source);
            }
            else if (folder.StartsWith(@"\\", StringComparison.Ordinal))
            {
                report.Problem("Search path: a network folder", "On a network location", Source);
            }
            else if (!MachineContext.IsLocalPath(folder))
            {
                report.Problem(item, "Not a complete path: it is looked for from wherever a program is started", Source);
            }
            else
            {
                report.Add(item, judge.Folder(folder), Source);
            }
        }

        return report.Outcome("The PC's search path is empty.");
    }
}
