using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// An antivirus registered with Windows must be switched on with current definitions. Reads
/// what Windows Security Center itself reports, so any product that registers is recognised.
/// </summary>
public sealed class AntivirusCheck : ICheck
{
    public const string Id = "antivirus.active";

    private const string Expected = "On, definitions current";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.SystemIntegrity, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<IReadOnlyList<SecurityProduct>> result =
            context.Probes.SecurityCenter.GetProducts(SecurityProductKind.Antivirus);
        if (!result.IsOk)
        {
            // Includes Windows Server, which has no Security Center: the antivirus state is
            // then unknown, not irrelevant, so this is "could not check", never "does not apply".
            return ProbeOutcomes.FromFailure(result, "the antivirus state");
        }

        IReadOnlyList<SecurityProduct> products = result.Value!;
        if (products.Count == 0)
        {
            return CheckOutcome.Fail(
                "No antivirus is registered with Windows.",
                Finding.Problem("Antivirus", "None registered", Expected));
        }

        // One product that is on and current is enough; others may be installed but idle.
        SecurityProduct? good = products.FirstOrDefault(IsOnAndCurrent);
        List<Finding> findings = [.. products.Select(p => ToFinding(p, anotherIsGood: good is not null))];

        if (good is not null)
        {
            return CheckOutcome.Pass($"{good.Name} is on and up to date.", findings);
        }

        SecurityProduct? onButStale = products.FirstOrDefault(p => p.State == SecurityProductState.On);
        if (onButStale is not null)
        {
            return CheckOutcome.Fail($"{onButStale.Name} is on, but its definitions are out of date.", findings);
        }

        SecurityProduct first = products[0];
        return CheckOutcome.Fail($"{first.Name} is {Describe(first.State)}.", findings);
    }

    private static bool IsOnAndCurrent(SecurityProduct product) =>
        product.State == SecurityProductState.On && product.SignaturesUpToDate == true;

    private static Finding ToFinding(SecurityProduct product, bool anotherIsGood)
    {
        string found = product.State == SecurityProductState.On
            ? product.SignaturesUpToDate == true ? "On, definitions current" : "On, definitions out of date"
            : Capitalise(Describe(product.State));

        if (IsOnAndCurrent(product))
        {
            return Finding.Ok(product.Name, found, Expected);
        }

        // An idle second product is normal when another one is doing the job.
        return anotherIsGood
            ? Finding.Note(product.Name, found)
            : Finding.Problem(product.Name, found, Expected);
    }

    private static string Describe(SecurityProductState state) => state switch
    {
        SecurityProductState.On => "on",
        SecurityProductState.Snoozed => "paused",
        SecurityProductState.Expired => "expired",
        _ => "off",
    };

    private static string Capitalise(string text) => char.ToUpperInvariant(text[0]) + text[1..];
}
