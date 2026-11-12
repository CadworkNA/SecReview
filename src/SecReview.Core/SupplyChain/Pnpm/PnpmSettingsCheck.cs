using SecReview.Checks;
using SecReview.Config;

namespace SecReview.SupplyChain.Pnpm;

/// <summary>
/// pnpm's protections against tampered and unexpected packages must not be switched off in
/// its global settings: trusting the lockfile blindly, allowing every package to run build
/// scripts, dependencies from arbitrary URLs, store integrity, TLS checks, plain-HTTP
/// registries. Each setting is looked up in the file the installed pnpm reads; with an
/// unknown version, in both. The recommended <c>trustPolicy: no-downgrade</c> is noted, not
/// required: pnpm's default is off.
/// </summary>
public sealed class PnpmSettingsCheck : ICheck
{
    public const string Id = "sc.pnpm.settings";

    /// <summary>YAML name, INI name, what it is, and the value that is a problem.</summary>
    private static readonly (string Yaml, string Ini, string Item, bool Bad, string Found, string Expected)[] Switches =
    [
        ("trustLockfile", "trust-lockfile", "Lockfile verification", true, "Skipped", "On"),
        ("dangerouslyAllowAllBuilds", "dangerously-allow-all-builds", "Build scripts", true, "Every package may run them", "Only approved packages"),
        ("strictDepBuilds", "strict-dep-builds", "Unapproved build scripts", false, "Ignored silently", "Stop the install"),
        ("blockExoticSubdeps", "block-exotic-subdeps", "Dependencies from arbitrary addresses", false, "Allowed", "Blocked"),
        ("verifyStoreIntegrity", "verify-store-integrity", "Package store integrity check", false, "Off", "On"),
        ("strictStorePkgContentCheck", "strict-store-pkg-content-check", "Package content check", false, "Off", "On"),
        ("strictSsl", "strict-ssl", "TLS certificate checks", false, "Off", "On"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (PnpmLocator.Locate(context.Probes, out PnpmInstall? pnpm) is { } failed)
        {
            return failed;
        }

        if (pnpm is null)
        {
            return CheckOutcome.NotApplicable("pnpm is not installed.");
        }

        var problems = new List<Finding>();

        // pnpm 11 and later take their own settings from config.yaml; pnpm 10 from rc.
        // Network settings (TLS, registries) stay in rc for every version.
        bool yamlCounts = pnpm.ReadsYaml != false;
        bool rcCounts = pnpm.ReadsYaml != true;

        foreach ((string yaml, string ini, string item, bool bad, string found, string expected) in Switches)
        {
            bool isNetwork = yaml == "strictSsl";
            if (yamlCounts && pnpm.Yaml?.Root?[yaml] is { } inYaml && PnpmLocator.Flag(inYaml) == bad)
            {
                problems.Add(Finding.Problem(item, found, expected, pnpm.Yaml.At(inYaml)));
            }

            if ((rcCounts || isNetwork) && pnpm.Rc?.Root?[ini] is { } inRc && PnpmLocator.Flag(inRc) == bad)
            {
                problems.Add(Finding.Problem(item, found, expected, pnpm.Rc.At(inRc)));
            }
        }

        // Registries over plain HTTP: "registry" and "@scope:registry" in rc, the registries map in config.yaml.
        if (pnpm.Rc?.Root is { } rc)
        {
            foreach ((string key, ConfigNode value) in rc.Entries)
            {
                if ((key == "registry" || key.EndsWith(":registry", StringComparison.Ordinal)) && IsPlainHttp(value))
                {
                    problems.Add(Finding.Problem(key == "registry" ? "Default registry" : $"Registry for {key[..^":registry".Length]}", "Plain HTTP", "HTTPS", pnpm.Rc.At(value)));
                }
            }
        }

        if (yamlCounts && pnpm.Yaml?.Root is { } settings)
        {
            if (IsPlainHttp(settings["registry"]))
            {
                problems.Add(Finding.Problem("Default registry", "Plain HTTP", "HTTPS", pnpm.Yaml.At(settings["registry"]!)));
            }

            foreach (string map in (string[])["registries", "namedRegistries"])
            {
                if (settings[map] is ConfigMap registries)
                {
                    foreach ((string name, ConfigNode value) in registries.Entries)
                    {
                        if (IsPlainHttp(value))
                        {
                            problems.Add(Finding.Problem($"Registry \"{name}\"", "Plain HTTP", "HTTPS", pnpm.Yaml.At(value)));
                        }
                    }
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"pnpm: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"pnpm has {problems.Count} protections switched off.",
                problems);
        }

        // Nothing found. If a settings file could not be read, "nothing wrong" is not known.
        if (pnpm.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        var findings = new List<Finding> { Finding.Ok("Protections switched off", "None", "None") };

        // pnpm's own advice against a package silently changing who publishes it.
        ConfigNode? trustPolicy = yamlCounts ? pnpm.Yaml?.Root?["trustPolicy"] : pnpm.Rc?.Root?["trust-policy"];
        findings.Add(PnpmLocator.Text(trustPolicy) == "no-downgrade"
            ? Finding.Ok("Trust policy", "no-downgrade", "no-downgrade", (yamlCounts ? pnpm.Yaml : pnpm.Rc)!.At(trustPolicy!))
            : Finding.Note("Trust policy", "Off (pnpm's default); \"trustPolicy: no-downgrade\" is recommended"));

        if (pnpm.Version is { Major: 10 } ten)
        {
            findings.Add(Finding.Note("pnpm version", $"{ten}: pnpm 11 and later block more by default"));
        }

        return CheckOutcome.Pass("pnpm's protections are on.", findings);
    }

    private static bool IsPlainHttp(ConfigNode? node) =>
        PnpmLocator.Text(node)?.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true;
}
