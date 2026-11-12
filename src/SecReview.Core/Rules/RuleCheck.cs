using System.Globalization;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;

namespace SecReview.Rules;

/// <summary>
/// Runs one rule. Like every check it only reads, and anything it cannot read becomes "needs
/// administrator" or "could not check", never a pass.
/// </summary>
public sealed class RuleCheck : ICheck
{
    private readonly RuleDefinition _rule;

    public RuleCheck(RuleDefinition rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _rule = rule;

        // Audit policy and user rights can only be read with administrator rights. A rule
        // about the user's own registry reads the signed-in user, so it never runs elevated.
        AdminNeed admin = rule.AuditPolicy is not null || rule.UserRight is not null ? AdminNeed.Yes : AdminNeed.No;
        CheckScope scope = rule.Registry?.Root == RegistryRoot.CurrentUser ? CheckScope.User : CheckScope.Machine;
        Definition = new CheckDefinition(rule.Id, rule.Category, rule.Severity, admin, scope);
    }

    public CheckDefinition Definition { get; }

    /// <summary>The rule this check runs.</summary>
    public RuleDefinition Rule => _rule;

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        return _rule switch
        {
            { Registry: { } registry } => Run(registry, probes.Registry),
            { Service: { } service } => Run(service, probes.Services),
            { AccountPolicy: { } policy } => Run(policy, probes.AccountPolicy),
            { AuditPolicy: { } audit } => Run(audit, probes.AuditPolicy),
            { UserRight: { } right } => Run(right, probes.UserRights),
            { Defender: { } defender } => Run(defender, probes),
            { DefenderRules: { } rules } => Run(rules, probes),
            _ => CheckOutcome.Error("This rule does not say what to read."),
        };
    }

    private static CheckOutcome Run(RegistryRule rule, IRegistryProbe registry)
    {
        string root = rule.Root == RegistryRoot.LocalMachine ? "HKLM" : "HKCU";
        foreach (RegistryLocation location in rule.Locations)
        {
            if (RegistryReader.Number(registry, rule.Root, location.Key, location.Value, $"the setting \"{rule.Item}\"", out long? value)
                is { } failed)
            {
                return failed;
            }

            if (value is null)
            {
                continue;
            }

            value /= location.DivideBy;
            string found = Describe(value.Value, rule.Labels, rule.Unit);
            string source = $@"{root}\{location.Key}\{location.Value}";
            return (rule.Expect.Matches(value.Value)
                ? CheckOutcome.Pass($"{rule.Item}: {found}.", Finding.Ok(rule.Item, found, rule.Expected, source))
                : CheckOutcome.Fail(
                    $"{rule.Item}: {found}. Expected: {rule.Expected}.", Finding.Problem(rule.Item, found, rule.Expected, source)))
                with { ManagedByPolicy = location.Policy };
        }

        // Stored nowhere: Windows' own behaviour applies, and the rule says whether that is fine.
        RegistryLocation last = rule.Locations[^1];
        string where = $@"{root}\{last.Key}\{last.Value}";
        return rule.Absent.Passes
            ? CheckOutcome.Pass($"{rule.Item}: {rule.Absent.Found}.", Finding.Ok(rule.Item, rule.Absent.Found, rule.Expected, where))
            : CheckOutcome.Fail(
                $"{rule.Item}: {rule.Absent.Found}. Expected: {rule.Expected}.",
                Finding.Problem(rule.Item, rule.Absent.Found, rule.Expected, where));
    }

    private static CheckOutcome Run(ServiceRule rule, IServiceProbe services)
    {
        string expected = rule.Require == ServiceRequirement.Disabled ? "Disabled" : "Not running";
        ProbeResult<ServiceInfo> read = services.GetService(rule.Name);
        if (read.Status == ProbeStatus.NotFound)
        {
            return CheckOutcome.Pass($"{rule.Item} is not installed.", Finding.Ok(rule.Item, "Not installed", expected));
        }

        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, $"the {rule.Item} service");
        }

        ServiceInfo service = read.Value!;
        string startType = service.StartType switch
        {
            ServiceStartType.Disabled => "Disabled",
            ServiceStartType.Manual => "Starts on demand",
            _ => "Starts automatically",
        };
        string found = service.IsRunning ? $"{startType}, running" : service.StartType == ServiceStartType.Disabled ? "Disabled" : $"{startType}, not running";

        bool fine = !service.IsRunning &&
            (rule.Require == ServiceRequirement.NotRunning || service.StartType == ServiceStartType.Disabled);
        return fine
            ? CheckOutcome.Pass($"{rule.Item}: {found}.", Finding.Ok(rule.Item, found, expected))
            : CheckOutcome.Fail($"{rule.Item}: {found}. Expected: {expected}.", Finding.Problem(rule.Item, found, expected));
    }

    private static CheckOutcome Run(AccountPolicyRule rule, IAccountPolicyProbe probe)
    {
        ProbeResult<AccountPolicy> read = probe.GetPolicy();
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "the password and lockout policy");
        }

        AccountPolicy policy = read.Value!;
        (long value, string? words) = rule.Field switch
        {
            AccountPolicyField.MinimumPasswordLength =>
                (policy.MinimumPasswordLength, policy.MinimumPasswordLength == 0 ? "No minimum" : null),
            AccountPolicyField.PasswordHistoryLength =>
                (policy.PasswordHistoryLength, policy.PasswordHistoryLength == 0 ? "None remembered" : null),
            AccountPolicyField.MaximumPasswordAgeDays => policy.MaximumPasswordAge is { } age
                ? ((long)age.TotalDays, (string?)null)
                : (0, "Passwords never expire"),
            AccountPolicyField.LockoutThreshold =>
                (policy.LockoutThreshold, policy.LockoutThreshold == 0 ? "Accounts never lock" : null),

            // No duration means locked until an administrator unlocks the account: the strictest setting.
            AccountPolicyField.LockoutDurationMinutes => policy.LockoutDuration is { } duration
                ? ((long)duration.TotalMinutes, null)
                : (int.MaxValue, "Until an administrator unlocks it"),
            _ => (-1, "Unknown setting"),
        };

        if (rule.Field == AccountPolicyField.LockoutDurationMinutes && policy.LockoutThreshold == 0)
        {
            return CheckOutcome.NotApplicable("Accounts never lock on this PC, so there is no lockout time to judge.");
        }

        string found = words ?? Describe(value, null, rule.Unit);
        return rule.Expect.Matches(value)
            ? CheckOutcome.Pass($"{rule.Item}: {found}.", Finding.Ok(rule.Item, found, rule.Expected))
            : CheckOutcome.Fail($"{rule.Item}: {found}. Expected: {rule.Expected}.", Finding.Problem(rule.Item, found, rule.Expected));
    }

    private static CheckOutcome Run(AuditPolicyRule rule, IAuditPolicyProbe probe)
    {
        ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>> read = probe.GetSubcategories([rule.Subcategory]);
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "the audit policy");
        }

        if (!read.Value!.TryGetValue(rule.Subcategory, out AuditSetting setting))
        {
            return CheckOutcome.Error($"Windows did not report the audit setting \"{rule.Item}\".");
        }

        AuditSetting required =
            (rule.Success ? AuditSetting.Success : AuditSetting.None) | (rule.Failure ? AuditSetting.Failure : AuditSetting.None);
        string found = Words(setting);
        string expected = Words(required);
        string item = $"Audit: {rule.Item}";
        return (setting & required) == required
            ? CheckOutcome.Pass($"{item} records {found.ToLowerInvariant()}.", Finding.Ok(item, found, expected))
            : CheckOutcome.Fail(
                $"{item} records {found.ToLowerInvariant()}. Expected: {expected.ToLowerInvariant()}.",
                Finding.Problem(item, found, expected));

        static string Words(AuditSetting value) => value switch
        {
            AuditSetting.Success | AuditSetting.Failure => "Success and failure",
            AuditSetting.Success => "Success",
            AuditSetting.Failure => "Failure",
            _ => "Nothing",
        };
    }

    private static CheckOutcome Run(UserRightRule rule, IUserRightsProbe probe)
    {
        ProbeResult<IReadOnlyList<AccountReference>> read = probe.GetAccountsWithRight(rule.Right);
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, $"who holds the right \"{rule.Item}\"");
        }

        var findings = new List<Finding>();
        int others = 0;
        foreach (AccountReference account in read.Value!)
        {
            // Only well-known groups are named; a personal account is counted, not named.
            string name = account.Name ?? "Another account";
            if (rule.Allowed.Contains(account.Sid, StringComparer.OrdinalIgnoreCase))
            {
                findings.Add(Finding.Ok(name, "Has the right", "Allowed", rule.Right));
            }
            else
            {
                others++;
                findings.Add(Finding.Problem(name, "Has the right", "Does not have it", rule.Right));
            }
        }

        if (findings.Count == 0)
        {
            findings.Add(Finding.Ok(rule.Item, "Nobody has it", "Only the allowed groups", rule.Right));
        }

        return others == 0
            ? CheckOutcome.Pass($"\"{rule.Item}\" is held only by the groups that should have it.", findings)
            : CheckOutcome.Fail(
                $"\"{rule.Item}\" is held by {others} account{Wording.Plural(others)} or group{Wording.Plural(others)} that should not have it.",
                findings);
    }

    private static CheckOutcome Run(DefenderRule rule, SystemProbes probes)
    {
        if (DefenderCheck.ReadStatus(probes, out _) is { } notInUse)
        {
            return notInUse;
        }

        ProbeResult<IReadOnlyList<WmiObject>> read =
            probes.Wmi.Query(DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, [rule.Property]);
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "Microsoft Defender's settings");
        }

        WmiObject? settings = read.Value!.Count > 0 ? read.Value[0] : null;
        long? value = settings?.Number(rule.Property) ?? (settings?.Flag(rule.Property) is { } flag ? (flag ? 1 : 0) : null);
        if (value is null)
        {
            return CheckOutcome.Error($"Microsoft Defender did not report the setting \"{rule.Item}\".");
        }

        string found = Describe(value.Value, rule.Labels, null);
        return rule.Expect.Matches(value.Value)
            ? CheckOutcome.Pass($"{rule.Item}: {found}.", Finding.Ok(rule.Item, found, rule.Expected))
            : CheckOutcome.Fail($"{rule.Item}: {found}. Expected: {rule.Expected}.", Finding.Problem(rule.Item, found, rule.Expected));
    }

    private static CheckOutcome Run(DefenderRulesRule rule, SystemProbes probes)
    {
        const string Ids = "AttackSurfaceReductionRules_Ids";
        const string Actions = "AttackSurfaceReductionRules_Actions";
        const long Block = 1;

        if (DefenderCheck.ReadStatus(probes, out _) is { } notInUse)
        {
            return notInUse;
        }

        ProbeResult<IReadOnlyList<WmiObject>> read =
            probes.Wmi.Query(DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, [Ids, Actions]);
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "Microsoft Defender's settings");
        }

        if (read.Value!.Count == 0)
        {
            return CheckOutcome.Error("Microsoft Defender did not report its attack surface reduction rules.");
        }

        IReadOnlyList<string> ids = read.Value[0].Texts(Ids);
        IReadOnlyList<long> actions = read.Value[0].Numbers(Actions);
        if (ids.Count != actions.Count)
        {
            return CheckOutcome.Error("Microsoft Defender reported its attack surface reduction rules inconsistently.");
        }

        var configured = new Dictionary<Guid, long>();
        for (int i = 0; i < ids.Count; i++)
        {
            if (Guid.TryParse(ids[i], out Guid id))
            {
                configured[id] = actions[i];
            }
        }

        var findings = new List<Finding>(rule.Rules.Count);
        int missing = 0;
        foreach (AttackSurfaceRule expected in rule.Rules)
        {
            string found = configured.TryGetValue(expected.Id, out long action)
                ? action switch
                {
                    0 => "Off",
                    1 => "Block",
                    2 => "Audit only",
                    6 => "Warn",
                    _ => action.ToString(CultureInfo.InvariantCulture),
                }
                : "Not configured";
            if (configured.TryGetValue(expected.Id, out action) && action == Block)
            {
                findings.Add(Finding.Ok(expected.Name, found, "Block"));
            }
            else
            {
                missing++;
                findings.Add(Finding.Problem(expected.Name, found, "Block"));
            }
        }

        return missing == 0
            ? CheckOutcome.Pass($"All {rule.Rules.Count} attack surface reduction rules block.", findings)
            : CheckOutcome.Fail(
                $"{missing} of {rule.Rules.Count} attack surface reduction rules {(missing == 1 ? "does" : "do")} not block.", findings);
    }

    /// <summary>A value in words: its label if it has one, else the number with its unit.</summary>
    private static string Describe(long value, IReadOnlyDictionary<string, string>? labels, string? unit)
    {
        string number = value.ToString(CultureInfo.InvariantCulture);
        if (labels is not null && labels.TryGetValue(number, out string? label))
        {
            return label;
        }

        return unit is null ? number : $"{number} {unit}";
    }
}
