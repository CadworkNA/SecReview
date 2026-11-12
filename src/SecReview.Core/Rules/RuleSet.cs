using System.Text.Json;
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

        foreach (RuleDefinition rule in file.Rules ?? [])
        {
            if (Problem(rule) is { } problem)
            {
                throw new JsonException($"Rule file {fileName}, rule '{rule?.Id}': {problem}");
            }
        }

        return file.Rules ?? [];
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

        object?[] kinds =
            [rule.Registry, rule.Service, rule.AccountPolicy, rule.AuditPolicy, rule.UserRight, rule.Defender, rule.DefenderRules];
        if (kinds.Count(k => k is not null) != 1)
        {
            return "exactly one of registry, service, accountPolicy, auditPolicy, userRight, defender and defenderRules must be set.";
        }

        if (rule.Registry is { } registry)
        {
            if (registry.Locations is not { Count: > 0 } || registry.Expect is null || registry.Absent is null ||
                string.IsNullOrWhiteSpace(registry.Item) || string.IsNullOrWhiteSpace(registry.Expected))
            {
                return "a registry rule needs an item, locations, an expectation, the expectation in words and what absence means.";
            }

            if (registry.Expect.IsEmpty)
            {
                return "the expectation says nothing.";
            }

            if (registry.Locations.Any(l => l.DivideBy < 1))
            {
                return "divideBy is 1 or more.";
            }

            if (registry.Locations.Any(l => string.IsNullOrWhiteSpace(l.Key) || string.IsNullOrWhiteSpace(l.Value) ||
                    l.Key.StartsWith('\\') || l.Key.StartsWith("HK", StringComparison.OrdinalIgnoreCase)))
            {
                return "a registry key is written without its root and without a leading backslash.";
            }

            // A value under SOFTWARE\Policies is put there by an organisation's policy; saying so
            // is part of an honest result, and saying it of any other key would be wrong.
            if (registry.Locations.Any(l => l.Policy != l.Key.StartsWith(@"SOFTWARE\Policies\", StringComparison.OrdinalIgnoreCase)))
            {
                return @"the locations under SOFTWARE\Policies, and only those, are marked as policy.";
            }
        }

        if (rule.Service is { } service && (string.IsNullOrWhiteSpace(service.Item) || string.IsNullOrWhiteSpace(service.Name)))
        {
            return "a service rule needs the service's name and display name.";
        }

        if (rule.AccountPolicy is { } policy &&
            (policy.Expect is null || policy.Expect.IsEmpty || string.IsNullOrWhiteSpace(policy.Item) || string.IsNullOrWhiteSpace(policy.Expected)))
        {
            return "an account policy rule needs an item, an expectation and the expectation in words.";
        }

        if (rule.AuditPolicy is { } audit &&
            (audit.Subcategory == Guid.Empty || string.IsNullOrWhiteSpace(audit.Item) || (!audit.Success && !audit.Failure)))
        {
            return "an audit policy rule needs a subcategory, an item, and success or failure.";
        }

        if (rule.UserRight is { } right &&
            (string.IsNullOrWhiteSpace(right.Item) || right.Right is null || !right.Right.StartsWith("Se", StringComparison.Ordinal) ||
             right.Allowed is null || right.Allowed.Any(sid => !sid.StartsWith("S-1-", StringComparison.Ordinal))))
        {
            return "a user right rule needs an item, a right named Se..., and allowed identifiers starting with S-1-.";
        }

        if (rule.Defender is { } defender &&
            (defender.Expect is null || defender.Expect.IsEmpty || string.IsNullOrWhiteSpace(defender.Item) ||
             string.IsNullOrWhiteSpace(defender.Expected) || !WmiNames.IsIdentifier(defender.Property)))
        {
            return "a Defender rule needs an item, a property name, an expectation and the expectation in words.";
        }

        if (rule.DefenderRules is { } rules &&
            (rules.Rules is not { Count: > 0 } || rules.Rules.Any(r => r.Id == Guid.Empty || string.IsNullOrWhiteSpace(r.Name))))
        {
            return "a Defender rules rule needs at least one rule, each with an identifier and a name.";
        }

        return null;
    }

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
