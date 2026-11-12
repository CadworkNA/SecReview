using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Pnpm;

/// <summary>
/// pnpm must not keep registry tokens where any program can read them. pnpm has written them
/// to three places over time, and old tokens stay behind when it moves on: <c>auth.ini</c>
/// (pnpm 11, and again from 12.16), the <c>_auth</c> map in <c>config.yaml</c> (pnpm 12.1 to
/// 12.15) and the INI file <c>rc</c> (pnpm 10). All three are read, with the persistent
/// environment variables pnpm takes tokens from. Only where a token sits is reported.
/// The user's <c>.npmrc</c>, which npm shares, is covered by the npm check.
/// </summary>
public sealed class PnpmCredentialsCheck : ICheck
{
    public const string Id = "sc.pnpm.credentials";

    private const string Expected = "Not stored as plain text";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (PnpmLocator.Locate(probes, out PnpmInstall? pnpm) is { } failed)
        {
            return failed;
        }

        if (pnpm is null)
        {
            return CheckOutcome.NotApplicable("pnpm is not installed.");
        }

        if (pnpm.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        var problems = new List<Finding>();
        foreach (SettingsFile? file in (SettingsFile?[])[pnpm.AuthIni, pnpm.Rc])
        {
            if (file is not null)
            {
                problems.AddRange(NpmTokens.In(file));
            }
        }

        // config.yaml: _auth -> registry address -> scope ("@" or "@org") -> authToken.
        if (pnpm.Yaml?.Root?["_auth"] is ConfigMap registries)
        {
            foreach ((string registry, ConfigNode scopes) in registries.Entries)
            {
                foreach ((string scope, ConfigNode entry) in (scopes as ConfigMap)?.Entries ?? [])
                {
                    if ((entry as ConfigMap)?["authToken"] is ConfigScalar { Text.Length: > 0 } token && !NpmTokens.IsReference(token.Text))
                    {
                        string host = Uri.TryCreate(registry, UriKind.Absolute, out Uri? address) && address.Host.Length > 0 ? address.Host : "a registry";
                        problems.Add(Finding.Problem(
                            scope == "@" ? $"Token for {host}" : $"Token for {host} ({scope})", "Stored as plain text", Expected, pnpm.Yaml.At(token)));
                    }
                }
            }
        }

        if (PersistentEnvironment.Names(probes.Registry, out IReadOnlyList<string> variables) is { } unread)
        {
            return unread;
        }

        foreach (string variable in variables)
        {
            bool holdsToken =
                variable.Equals("pnpm_config__auth", StringComparison.OrdinalIgnoreCase) ||
                ((variable.StartsWith("npm_config_", StringComparison.OrdinalIgnoreCase) || variable.StartsWith("pnpm_config_", StringComparison.OrdinalIgnoreCase)) &&
                 (variable.EndsWith("_authToken", StringComparison.OrdinalIgnoreCase) || variable.EndsWith(":_auth", StringComparison.OrdinalIgnoreCase) ||
                  variable.EndsWith("_password", StringComparison.OrdinalIgnoreCase)));
            if (holdsToken)
            {
                problems.Add(Finding.Problem("A variable that holds a token", "Set for good", "Not set", "environment variables"));
            }
        }

        return problems.Count == 0
            ? CheckOutcome.Pass("pnpm keeps no registry tokens as plain text.", Finding.Ok("Registry tokens", "None stored as plain text", Expected))
            : CheckOutcome.Fail(
                problems.Count == 1 ? "pnpm keeps a registry token as plain text." : $"pnpm keeps {problems.Count} registry tokens as plain text.",
                problems);
    }
}
