using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// Ransomware protection (controlled folder access) stops programs from changing the user's
/// documents unless they are on its list of allowed apps. If a standard user can replace an
/// allowed app, the protection no longer covers what that app does. Windows shows the list to
/// administrators only, so without an elevated scan the answer is "needs administrator",
/// never "none". Does not apply while the protection is off.
/// </summary>
public sealed class AllowedAppsCheck : ICheck
{
    public const string Id = "defender.allowedapps";

    internal const string LocalKey = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
    internal const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
    internal const string Switch = "EnableControlledFolderAccess";
    internal const string List = "AllowedApplications";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SystemIntegrity, Severity.Medium, AdminNeed.Yes, CheckScope.Machine);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Windows refuses the list to anyone else; an empty answer without rights would read as "none".
        if (!context.IsElevated)
        {
            return CheckOutcome.NeedsAdmin("Microsoft Defender shows the apps it allows to administrators only.");
        }

        IRegistryProbe registry = context.Probes.Registry;
        const string What = "the ransomware protection setting";
        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, PolicyKey, Switch, What, out long? byPolicy) is { } unreadPolicy)
        {
            return unreadPolicy;
        }

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, LocalKey, Switch, What, out long? local) is { } unreadLocal)
        {
            return unreadLocal;
        }

        if ((byPolicy ?? local ?? 0) == 0)
        {
            return CheckOutcome.NotApplicable("Ransomware protection (controlled folder access) is off, so it allows no apps.");
        }

        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("allowed app", "allowed apps", context.IsElevated);
        var judged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach ((string key, bool policy) in new[] { (LocalKey, false), (PolicyKey, true) })
        {
            ProbeResult<IReadOnlyList<string>> apps = registry.GetValueNames(RegistryRoot.LocalMachine, $@"{key}\{List}");
            if (apps.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!apps.IsOk)
            {
                return ProbeOutcomes.FromFailure(apps, "the apps ransomware protection allows");
            }

            foreach (string app in apps.Value!.Where(name => name.Trim().Length > 0 && judged.Add(name.Trim())))
            {
                context.Cancellation.ThrowIfCancellationRequested();
                ProgramReference reference = ProgramReference.Parse(app, CommandForm.PathOnly, machine);
                CommandVerdict verdict = judge.Command(reference);
                string item = verdict.Program.Path.Length > 0 ? $"Allowed app: {Path.GetFileName(verdict.Program.Path)}" : "Allowed app";
                report.ManagedByPolicy |= policy && verdict.IsProblem;
                report.Add(item, verdict, $@"HKLM\{key}\{List}");
            }
        }

        return report.Outcome("Ransomware protection allows no extra apps.");
    }
}
