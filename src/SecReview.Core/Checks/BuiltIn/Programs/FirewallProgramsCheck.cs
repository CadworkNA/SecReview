using System.Globalization;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// A firewall rule that lets connections in for a program trusts whatever file is at that
/// path. If standard users can replace the file, the opening is theirs to use. The rules are
/// read as Windows stores them, for the PC and from the organisation's policy; rules that are
/// off, that block, or that are for outgoing connections are not judged.
/// </summary>
public sealed class FirewallProgramsCheck : ICheck
{
    public const string Id = "firewall.programs";

    internal const string LocalKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    internal const string PolicyKey = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.FirewallAndSharing, Severity.Medium, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        IRegistryProbe registry = context.Probes.Registry;
        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("program allowed through the firewall", "programs allowed through the firewall", context.IsElevated);
        var judged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int leftBehind = 0;
        int perUser = 0;

        foreach ((string key, bool policy) in new[] { (LocalKey, false), (PolicyKey, true) })
        {
            ProbeResult<IReadOnlyList<string>> names = registry.GetValueNames(RegistryRoot.LocalMachine, key);
            if (names.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!names.IsOk)
            {
                return ProbeOutcomes.FromFailure(names, "the firewall rules");
            }

            string source = $@"HKLM\{key}";
            foreach (string name in names.Value!)
            {
                context.Cancellation.ThrowIfCancellationRequested();
                ProbeResult<RegistryValue> value = registry.GetValue(RegistryRoot.LocalMachine, key, name);
                if (value.Status == ProbeStatus.NotFound)
                {
                    continue;
                }

                if (value is not { IsOk: true, Value.Type: RegistryValueType.Text } || FirewallRuleText.Parse(value.Value.Text) is not { } rule)
                {
                    report.Unread("Firewall rule", value.IsOk ? "A stored rule could not be understood" : value.Detail ?? "A stored rule could not be read", value.Status == ProbeStatus.AccessDenied, source);
                    continue;
                }

                if (!rule.Active || !rule.Inbound || !rule.Allows || rule.Program is not { } program)
                {
                    continue;
                }

                if (!judged.Add(program))
                {
                    continue;
                }

                ProgramReference reference = ProgramReference.Parse(program, CommandForm.PathOnly, machine);
                CommandVerdict verdict = judge.Command(reference);
                string item = rule.Name is { } shown
                    ? $"Firewall rule: {(shown.Length <= 80 ? shown : shown[..80] + "…")}"
                    : $"Firewall rule for {(verdict.Program.Path.Length > 0 ? Path.GetFileName(verdict.Program.Path) : "a program")}";
                if (reference.PerUser)
                {
                    perUser++;
                    report.Fine();
                }
                else if (verdict.IsMissing)
                {
                    leftBehind++;
                    report.Fine();
                }
                else
                {
                    report.ManagedByPolicy |= policy && verdict.IsProblem;
                    report.Add(item, verdict, source);
                }
            }
        }

        if (leftBehind > 0)
        {
            report.Note("Left behind", string.Create(
                CultureInfo.InvariantCulture, $"{leftBehind} allowed {(leftBehind == 1 ? "program is" : "programs are")} not there any more"));
        }

        if (perUser > 0)
        {
            report.Note("Each user's own", string.Create(
                CultureInfo.InvariantCulture, $"{perUser} allowed {(perUser == 1 ? "program is" : "programs are")} in the user's own folders; not judged"));
        }

        return report.Outcome("No firewall rule lets connections in for a program.");
    }
}
