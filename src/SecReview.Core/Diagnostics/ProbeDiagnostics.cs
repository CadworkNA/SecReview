using System.Globalization;
using SecReview.Probing;

namespace SecReview.Diagnostics;

/// <summary>
/// Runs every probe once and writes one line each: which reads work on this PC, which need
/// administrator rights, and which fail. For support, and for CI on real Windows.
/// </summary>
public static class ProbeDiagnostics
{
    /// <summary>Writes the report. Returns false if any probe failed outright.</summary>
    public static bool Run(SystemProbes probes, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(output);

        bool allFine = true;

        allFine &= Report(output, "firewall", probes.Firewall.GetState(), Describe);
        allFine &= Report(
            output, "antivirus products", probes.SecurityCenter.GetProducts(SecurityProductKind.Antivirus), Describe);
        allFine &= Report(
            output, "firewall products", probes.SecurityCenter.GetProducts(SecurityProductKind.Firewall), Describe);
        allFine &= Report(output, "account policy", probes.AccountPolicy.GetPolicy(), Describe);

        return allFine;
    }

    private static bool Report<T>(TextWriter output, string name, ProbeResult<T> result, Func<T, string> describe)
    {
        string status = result.Status switch
        {
            ProbeStatus.Ok => "ok",
            ProbeStatus.NotFound => "not found",
            ProbeStatus.AccessDenied => "needs administrator",
            ProbeStatus.NotSupported => "not supported",
            _ => "FAILED",
        };

        string text = result.IsOk ? describe(result.Value!) : result.Detail ?? string.Empty;
        output.WriteLine($"{name,-20} {status,-20} {text}".TrimEnd());

        return result.Status != ProbeStatus.Failed;
    }

    private static string Describe(FirewallState state)
    {
        IEnumerable<string> profiles = state.Profiles.Select(profile =>
            $"{profile.Profile}: {(profile.Enabled ? "on" : "off")}" +
            $"{(profile.BlocksInboundByDefault ? ", blocks inbound" : ", allows inbound")}");
        return $"{string.Join("; ", profiles)}; active: {state.ActiveProfiles}";
    }

    private static string Describe(IReadOnlyList<SecurityProduct> products) => products.Count == 0
        ? "none registered"
        : string.Join("; ", products.Select(product =>
            $"{product.Name} ({product.State}, definitions {(product.SignaturesUpToDate ? "current" : "out of date")})"));

    private static string Describe(AccountPolicy policy) => string.Create(
        CultureInfo.InvariantCulture,
        $"minimum length {policy.MinimumPasswordLength}, history {policy.PasswordHistoryLength}, " +
        $"maximum age {Days(policy.MaximumPasswordAge)}, lockout after {policy.LockoutThreshold} for " +
        $"{Minutes(policy.LockoutDuration)}");

    private static string Days(TimeSpan? value) =>
        value is null ? "never" : string.Create(CultureInfo.InvariantCulture, $"{value.Value.TotalDays:0} days");

    private static string Minutes(TimeSpan? value) =>
        value is null ? "ever" : string.Create(CultureInfo.InvariantCulture, $"{value.Value.TotalMinutes:0} min");
}
