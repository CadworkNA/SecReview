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
    /// <summary>
    /// Stands for "never" where a larger number is the stricter one, so that a rule with only
    /// an upper bound ("at most 365 days") fails when the answer is "never", without its author
    /// having to remember a lower bound.
    /// </summary>
    private const long Never = int.MaxValue;

    private readonly RuleDefinition _rule;

    public RuleCheck(RuleDefinition rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _rule = rule;

        // Audit policy and user rights can only be read with administrator rights. Microsoft
        // Defender's settings are closed to normal users on some PCs, so those rules join the
        // administrator scan too. A rule about the user's own registry reads the signed-in
        // user, so it never runs elevated.
        AdminNeed admin =
            rule.AuditPolicy is not null || rule.UserRight is not null ? AdminNeed.Yes
            : rule.NeedsAdmin ?? (rule.Defender is not null || rule.DefenderRules is not null ? AdminNeed.ForFullDetail : AdminNeed.No);
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

    /// <summary>The outcome of comparing one value: "Item: found." or "Item: found. Expected: expected."</summary>
    private static CheckOutcome Judge(string item, string found, string expected, bool fine, string? source = null) => fine
        ? CheckOutcome.Pass($"{item}: {found}.", Finding.Ok(item, found, expected, source))
        : CheckOutcome.Fail($"{item}: {found}. Expected: {expected}.", Finding.Problem(item, found, expected, source));

    private static CheckOutcome Run(RegistryRule rule, IRegistryProbe registry)
    {
        string root = rule.Root == RegistryRoot.LocalMachine ? "HKLM" : "HKCU";
        string what = $"the setting \"{rule.Item}\"";

        if (rule.OnlyWhen is { } condition)
        {
            if (RegistryReader.Number(registry, rule.Root, condition.Key, condition.Value, what, out long? depends) is { } failed)
            {
                return failed;
            }

            if (!(depends is { } number ? condition.Expect.Matches(number) : condition.HoldsWhenAbsent))
            {
                return CheckOutcome.NotApplicable(condition.Otherwise);
            }
        }

        foreach (RegistryLocation location in rule.Locations)
        {
            if (RegistryReader.Number(registry, rule.Root, location.Key, location.Value, what, out long? value) is { } failed)
            {
                return failed;
            }

            if (value is null)
            {
                continue;
            }

            value /= location.DivideBy;
            return Judge(
                rule.Item,
                Describe(value.Value, rule.Labels, rule.Unit),
                rule.Expected,
                rule.Expect.Matches(value.Value),
                $@"{root}\{location.Key}\{location.Value}") with { ManagedByPolicy = location.Policy };
        }

        // Stored nowhere: Windows' own behaviour applies, and the rule says whether that is fine.
        RegistryLocation last = rule.Locations[^1];
        return Judge(rule.Item, rule.Absent.Found, rule.Expected, rule.Absent.Passes, $@"{root}\{last.Key}\{last.Value}");
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
        string found = service.IsRunning ? $"{startType}, running"
            : service.StartType == ServiceStartType.Disabled ? "Disabled"
            : $"{startType}, not running";

        bool fine = !service.IsRunning &&
            (rule.Require == ServiceRequirement.NotRunning || service.StartType == ServiceStartType.Disabled);
        return Judge(rule.Item, found, expected, fine);
    }

    private static CheckOutcome Run(AccountPolicyRule rule, IAccountPolicyProbe probe)
    {
        ProbeResult<AccountPolicy> read = probe.GetPolicy();
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "the password and lockout policy");
        }

        AccountPolicy policy = read.Value!;
        if (rule.Field == AccountPolicyField.LockoutDurationMinutes && policy.LockoutThreshold == 0)
        {
            return CheckOutcome.NotApplicable("Accounts never lock on this PC, so there is no lockout time to judge.");
        }

        (long Value, string? Words)? reading = rule.Field switch
        {
            AccountPolicyField.MinimumPasswordLength =>
                (policy.MinimumPasswordLength, policy.MinimumPasswordLength == 0 ? "No minimum" : null),
            AccountPolicyField.PasswordHistoryLength =>
                (policy.PasswordHistoryLength, policy.PasswordHistoryLength == 0 ? "None remembered" : null),
            AccountPolicyField.MaximumPasswordAgeDays => policy.MaximumPasswordAge is { } age
                ? ((long)age.TotalDays, null)
                : (Never, "Passwords never expire"),
            AccountPolicyField.LockoutThreshold => policy.LockoutThreshold == 0
                ? (Never, "Accounts never lock")
                : (policy.LockoutThreshold, null),

            // No duration means locked until an administrator unlocks the account: the strictest setting.
            AccountPolicyField.LockoutDurationMinutes => policy.LockoutDuration is { } duration
                ? ((long)duration.TotalMinutes, null)
                : (Never, "Until an administrator unlocks it"),
            _ => null,
        };

        if (reading is not { } answer)
        {
            return CheckOutcome.Error("This rule names a policy value SecReview does not know.");
        }

        return Judge(
            rule.Item, answer.Words ?? Describe(answer.Value, null, rule.Unit), rule.Expected, rule.Expect.Matches(answer.Value));
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
        if (DefenderCheck.ReadSettings(probes, [rule.Property], out WmiObject settings) is { } unread)
        {
            return unread;
        }

        long? value = settings.Number(rule.Property) ?? (settings.Flag(rule.Property) is { } flag ? (flag ? 1 : 0) : null);
        if (value is null)
        {
            return CheckOutcome.Error($"Microsoft Defender did not report the setting \"{rule.Item}\".");
        }

        return Judge(rule.Item, Describe(value.Value, rule.Labels, null), rule.Expected, rule.Expect.Matches(value.Value));
    }

    private static CheckOutcome Run(DefenderRulesRule rule, SystemProbes probes)
    {
        const string Ids = DefenderCheck.AttackSurfaceIds;
        const string Actions = DefenderCheck.AttackSurfaceActions;
        const long Block = 1;

        if (DefenderCheck.ReadSettings(probes, [Ids, Actions], out WmiObject settings) is { } unread)
        {
            return unread;
        }

        // No value means no rule is configured. A value that is not a list is something this
        // check does not understand, which is not the same thing.
        if ((settings.Has(Ids) && !settings.IsList(Ids)) || (settings.Has(Actions) && !settings.IsList(Actions)))
        {
            return CheckOutcome.Error("Microsoft Defender reported its attack surface reduction rules in a form SecReview cannot read.");
        }

        IReadOnlyList<string> ids = settings.Texts(Ids);
        IReadOnlyList<long> actions = settings.Numbers(Actions);
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
            string found = !configured.TryGetValue(expected.Id, out long action) ? "Not configured" : action switch
            {
                0 => "Off",
                Block => "Block",
                2 => "Audit only",
                6 => "Warn",
                _ => action.ToString(CultureInfo.InvariantCulture),
            };

            if (found == "Block")
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
