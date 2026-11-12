using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.Rules;

/// <summary>
/// The rules shipped with the app: every <c>rules/*.json</c> file, embedded at build time, in
/// file-name order. A rule file that does not hold together stops the load with the reason,
/// rather than running a rule that might pass by mistake.
/// </summary>
public static class RuleSet
{
    private const string ResourcePrefix = "SecReview.Rules.";

    private static readonly Lazy<List<RuleDefinition>> Loaded = new(Load);

    /// <summary>Every shipped rule.</summary>
    public static IReadOnlyList<RuleDefinition> Shipped => Loaded.Value;

    /// <summary>Reads one rule file and checks every rule in it.</summary>
    /// <exception cref="JsonException">The file is not valid, or a rule in it is not.</exception>
    public static IReadOnlyList<RuleDefinition> Parse(Stream json, string fileName)
    {
        RuleFile file;
        try
        {
            file = JsonSerializer.Deserialize(json, RulesJson.Default.RuleFile)
                ?? throw new JsonException("The file is empty.");
        }
        catch (JsonException exception)
        {
            throw new JsonException($"Rule file {fileName}: {exception.Message}", exception);
        }

        if (file.Rules is null)
        {
            throw new JsonException($"Rule file {fileName}: it has no rules.");
        }

        foreach (RuleDefinition? rule in file.Rules)
        {
            string? problem;
            try
            {
                problem = Problem(rule);
            }
#pragma warning disable CA1031 // Whatever a malformed rule trips over, the answer is the same: refuse the file, by name.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                problem = $"it could not be checked ({exception.GetType().Name}).";
            }

            if (problem is not null)
            {
                throw new JsonException($"Rule file {fileName}, rule '{rule?.Id}': {problem}");
            }
        }

        return file.Rules;
    }

    /// <summary>What is wrong with a rule, or null if it holds together.</summary>
    internal static string? Problem(RuleDefinition? rule)
    {
        if (rule is null)
        {
            return "the rule is empty.";
        }

        if (string.IsNullOrWhiteSpace(rule.Id) || rule.Text is null || string.IsNullOrWhiteSpace(rule.Source))
        {
            return "id, text and source are all required.";
        }

        if (rule.Text.Fix is null || rule.Text.References is null || rule.Text.Fix.Any(string.IsNullOrWhiteSpace) ||
            new[] { rule.Text.Name, rule.Text.TitlePass, rule.Text.TitleFail, rule.Text.Why, rule.Text.TimeToFix }.Any(string.IsNullOrWhiteSpace))
        {
            return "the text needs a name, both titles, why, fix steps and the time to fix.";
        }

        // A number where a name belongs would be accepted by the reader; an unknown one must not be.
        if (!Enum.IsDefined(rule.Category) || !Enum.IsDefined(rule.Severity) ||
            (rule.NeedsAdmin is { } need && !Enum.IsDefined(need)))
        {
            return "category, severity and needsAdmin must be known values.";
        }

        if (rule.Verified == default)
        {
            return "the day the rule was verified is required.";
        }

        object?[] kinds =
            [rule.Registry, rule.Service, rule.AccountPolicy, rule.AuditPolicy, rule.UserRight, rule.Defender, rule.DefenderRules];
        if (kinds.Count(k => k is not null) != 1)
        {
            return "exactly one of registry, service, accountPolicy, auditPolicy, userRight, defender and defenderRules must be set.";
        }

        // A rule about the user's own settings is never read under an administrator's account.
        if (rule.NeedsAdmin is not null and not AdminNeed.No && rule.Registry?.Root == RegistryRoot.CurrentUser)
        {
            return "a rule about the user's own settings cannot need administrator rights.";
        }

        return rule switch
        {
            { Registry: { } registry } => Problem(registry),
            { Service: { } service } => string.IsNullOrWhiteSpace(service.Item) || string.IsNullOrWhiteSpace(service.Name) ||
                !Enum.IsDefined(service.Require)
                    ? "a service rule needs the service's name, its display name and a known requirement."
                    : null,
            { AccountPolicy: { } policy } => IsEmpty(policy.Expect) || string.IsNullOrWhiteSpace(policy.Item) ||
                string.IsNullOrWhiteSpace(policy.Expected) || !Enum.IsDefined(policy.Field)
                    ? "an account policy rule needs an item, a known field, an expectation and the expectation in words."
                    : null,
            { AuditPolicy: { } audit } => audit.Subcategory == Guid.Empty || string.IsNullOrWhiteSpace(audit.Item) ||
                (!audit.Success && !audit.Failure)
                    ? "an audit policy rule needs a subcategory, an item, and success or failure."
                    : null,
            { UserRight: { } right } => string.IsNullOrWhiteSpace(right.Item) || right.Right is null ||
                !right.Right.StartsWith("Se", StringComparison.Ordinal) || right.Allowed is null ||
                right.Allowed.Any(sid => sid is null || !sid.StartsWith("S-1-", StringComparison.Ordinal))
                    ? "a user right rule needs an item, a right named Se..., and allowed identifiers starting with S-1-."
                    : null,
            { Defender: { } defender } => IsEmpty(defender.Expect) || string.IsNullOrWhiteSpace(defender.Item) ||
                string.IsNullOrWhiteSpace(defender.Expected) || !WmiNames.IsIdentifier(defender.Property)
                    ? "a Defender rule needs an item, a property name, an expectation and the expectation in words."
                    : null,
            { DefenderRules: { } rules } => rules.Rules is not { Count: > 0 } ||
                rules.Rules.Any(r => r is null || r.Id == Guid.Empty || string.IsNullOrWhiteSpace(r.Name))
                    ? "a Defender rules rule needs at least one rule, each with an identifier and a name."
                    : null,
            _ => null,
        };
    }

    private static string? Problem(RegistryRule registry)
    {
        if (registry.Locations is not { Count: > 0 } || registry.Locations.Any(l => l is null) || registry.Absent is null ||
            string.IsNullOrWhiteSpace(registry.Absent.Found) || string.IsNullOrWhiteSpace(registry.Item) ||
            string.IsNullOrWhiteSpace(registry.Expected) || !Enum.IsDefined(registry.Root))
        {
            return "a registry rule needs an item, a known root, locations, an expectation, the expectation in words and what absence means.";
        }

        if (IsEmpty(registry.Expect) || (registry.OnlyWhen is { } condition && IsEmpty(condition.Expect)))
        {
            return "the expectation says nothing.";
        }

        if (registry.Locations.Any(l => l.DivideBy < 1))
        {
            return "divideBy is 1 or more.";
        }

        IEnumerable<(string? Key, string? Value)> places = registry.Locations.Select(l => ((string?)l.Key, (string?)l.Value));
        if (registry.OnlyWhen is { } when)
        {
            if (string.IsNullOrWhiteSpace(when.Otherwise))
            {
                return "a condition says what to report when it does not hold.";
            }

            places = places.Append((when.Key, when.Value));
        }

        if (places.Any(p => string.IsNullOrWhiteSpace(p.Key) || string.IsNullOrWhiteSpace(p.Value) ||
                p.Key.StartsWith('\\') || p.Key.StartsWith("HK", StringComparison.OrdinalIgnoreCase)))
        {
            return "a registry key is written without its root and without a leading backslash.";
        }

        // A value under SOFTWARE\Policies is put there by an organisation's policy; saying so
        // is part of an honest result, and saying it of any other key would be wrong.
        if (registry.Locations.Any(l => l.Policy != l.Key.StartsWith(@"SOFTWARE\Policies\", StringComparison.OrdinalIgnoreCase)))
        {
            return @"the locations under SOFTWARE\Policies, and only those, are marked as policy.";
        }

        return null;
    }

    private static bool IsEmpty(Expectation? expectation) => expectation is null || expectation.IsEmpty;

    private static List<RuleDefinition> Load()
    {
        var assembly = typeof(RuleSet).Assembly;
        var rules = new List<RuleDefinition>();
        foreach (string resource in assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal))
        {
            using Stream stream = assembly.GetManifestResourceStream(resource)!;
            rules.AddRange(Parse(stream, resource[ResourcePrefix.Length..]));
        }

        string? duplicate = rules.GroupBy(r => r.Id, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1)?.Key;
        return duplicate is null
            ? rules
            : throw new JsonException($"The rule '{duplicate}' is defined more than once.");
    }
}
