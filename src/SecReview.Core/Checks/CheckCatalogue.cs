using SecReview.Catalogue;
using SecReview.Checks.BuiltIn;
using SecReview.Rules;

namespace SecReview.Checks;

/// <summary>
/// Everything SecReview checks: the checks written in code, then the rules shipped as data,
/// each with its wording.
/// </summary>
public static class CheckCatalogue
{
    private static readonly Lazy<(IReadOnlyList<ICheck> Checks, CheckTexts Texts)> Loaded = new(Load);

    /// <summary>Every check, in the order they are shown.</summary>
    public static IReadOnlyList<ICheck> Checks => Loaded.Value.Checks;

    /// <summary>The wording of every check.</summary>
    public static CheckTexts Texts => Loaded.Value.Texts;

    private static (IReadOnlyList<ICheck> Checks, CheckTexts Texts) Load()
    {
        IReadOnlyList<RuleDefinition> rules = RuleSet.Shipped;
        IReadOnlyList<ICheck> checks = [.. BuiltInChecks.All, .. rules.Select(rule => new RuleCheck(rule))];
        CheckTexts texts = CheckTexts.Load().With(rules.Select(rule => KeyValuePair.Create(rule.Id, rule.Text)));
        return (checks, texts);
    }
}
