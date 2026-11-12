using System.Globalization;
using SecReview.Probing;

namespace SecReview.Diagnostics;

/// <summary>
/// Runs every probe once and writes one line each: which reads work on this PC, which need
/// administrator rights, and which fail. For support, and for CI on real Windows.
/// </summary>
public static class ProbeDiagnostics
{
    private const string WindowsVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    /// <summary>A service present on every Windows edition, to prove the service reading works.</summary>
    private const string SampleService = "EventLog";

    /// <summary>Writes the report. Returns false if any probe failed outright.</summary>
    public static bool Run(SystemProbes probes, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(output);

        bool allFine = true;

        allFine &= Report(
            output,
            "registry",
            probes.Registry.GetValue(RegistryRoot.LocalMachine, WindowsVersionKey, "CurrentBuild"),
            value => $"Windows build {value.Text}");
        allFine &= Report(output, "services", probes.Services.GetService(SampleService), Describe);
        allFine &= Report(output, "power plan", probes.Power.GetSettings(), Describe);
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

    private static string Describe(ServiceInfo service) =>
        $"{service.Name}: {service.StartType}, {(service.IsRunning ? "running" : "stopped")}";

    private static string Describe(PowerSettings settings) =>
        $"plugged in: {Describe(settings.PluggedIn)}; on battery: {Describe(settings.OnBattery)}; " +
        $"battery: {(settings.HasBattery ? "yes" : "no")}";

    private static string Describe(PowerSourceSettings source) =>
        $"display off {Minutes(source.DisplayOff, "never")}, sleep {Minutes(source.Sleep, "never")}, " +
        $"{(source.RequirePasswordOnWake ? "password on wake" : "no password on wake")}";

    private static string Describe(FirewallState state)
    {
        IEnumerable<string> profiles = state.Profiles.Select(profile =>
            $"{profile.Profile}: {(profile.Enabled ? "on" : "off")}" +
            $"{(profile.BlocksInboundByDefault ? ", blocks inbound" : ", allows inbound")}");
        return $"{string.Join("; ", profiles)}; active: {state.ActiveProfiles}";
    }

    private static string Describe(IReadOnlyList<SecurityProduct> products) => products.Count == 0
        ? "none registered"
        : string.Join("; ", products.Select(Describe));

    private static string Describe(SecurityProduct product) => product.SignaturesUpToDate switch
    {
        null => $"{product.Name} ({product.State})",
        true => $"{product.Name} ({product.State}, definitions current)",
        false => $"{product.Name} ({product.State}, definitions out of date)",
    };

    private static string Describe(AccountPolicy policy)
    {
        // A threshold of 0 means accounts are never locked out; the duration then means nothing.
        string lockout = policy.LockoutThreshold == 0
            ? "no lockout"
            : string.Create(
                CultureInfo.InvariantCulture,
                $"lockout after {policy.LockoutThreshold} failed sign-ins for {Minutes(policy.LockoutDuration, "ever")}");

        return string.Create(
            CultureInfo.InvariantCulture,
            $"minimum length {policy.MinimumPasswordLength}, history {policy.PasswordHistoryLength}, " +
            $"maximum age {Days(policy.MaximumPasswordAge)}, {lockout}");
    }

    private static string Days(TimeSpan? value) =>
        value is null ? "never" : string.Create(CultureInfo.InvariantCulture, $"{value.Value.TotalDays:0} days");

    private static string Minutes(TimeSpan? value, string whenNull) =>
        value is null ? whenNull : string.Create(CultureInfo.InvariantCulture, $"{value.Value.TotalMinutes:0} min");
}
