using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Trust;

/// <summary>
/// Windows trusts the certificate authorities in its own list, and any that were added for
/// one account alone. Adding one for an account needs no administrator rights, and whoever
/// holds its key can pose as any website or package registry to that account. Development
/// tools add them too (a local HTTPS certificate, a company proxy), so they are listed, by
/// thumbprint, for the user to recognise; none is judged from here.
/// </summary>
public sealed class RootCertificatesCheck : ICheck
{
    public const string Id = "sc.trust.rootcerts";

    internal const string UserRoots = @"Software\Microsoft\SystemCertificates\Root\Certificates";

    private const int Most = 10;

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<IReadOnlyList<string>> roots = context.Probes.Registry.GetSubKeyNames(RegistryRoot.CurrentUser, UserRoots);
        if (!roots.IsOk && roots.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(roots, "the certificate authorities trusted for your account");
        }

        // Each certificate is a key named after its thumbprint.
        string[] thumbprints = roots.IsOk
            ? [.. roots.Value!.Where(IsThumbprint).Select(t => t.ToUpperInvariant()).Order(StringComparer.Ordinal)]
            : [];
        if (thumbprints.Length == 0)
        {
            return CheckOutcome.Pass(
                "No certificate authority is trusted for your account alone.",
                Finding.Ok("Certificate authorities added for your account", "None", "Only ones you know"));
        }

        var findings = new List<Finding>(Math.Min(thumbprints.Length, Most) + 1);
        foreach (string thumbprint in thumbprints.Take(Most))
        {
            findings.Add(Finding.Note("Certificate authority added for your account", $"Thumbprint {thumbprint}", $@"HKCU\{UserRoots}"));
        }

        if (thumbprints.Length > Most)
        {
            findings.Add(Finding.Note("More certificate authorities", $"{thumbprints.Length - Most} more", $@"HKCU\{UserRoots}"));
        }

        return CheckOutcome.Pass(
            thumbprints.Length == 1
                ? "1 certificate authority is trusted for your account alone; check that you know it."
                : $"{thumbprints.Length} certificate authorities are trusted for your account alone; check that you know each.",
            findings);
    }

    private static bool IsThumbprint(string name) => name.Length == 40 && name.All(char.IsAsciiHexDigit);
}
