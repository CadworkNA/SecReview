using SecReview.Checks;
using SecReview.SupplyChain.Npm;
using SecReview.SupplyChain.Pnpm;
using SecReview.SupplyChain.Scoop;
using SecReview.SupplyChain.Uv;

namespace SecReview.SupplyChain.Variables;

/// <summary>
/// Tokens and passwords should not sit in permanent environment variables: every program the
/// user runs inherits them, and install scripts of a bad package look there first. A variable
/// counts when its name says it holds a secret (<c>GITHUB_TOKEN</c>, <c>…_API_KEY</c>,
/// <c>…_PASSWORD</c>) and it is set to something that is not a file path. Only the name is
/// reported. Variables that a tool's own check already reports are left to that check.
/// </summary>
public sealed class EnvironmentTokensCheck : ICheck
{
    public const string Id = "sc.env.tokens";

    /// <summary>Name endings that say "this is a secret".</summary>
    private static readonly string[] SecretEndings =
    [
        "_TOKEN", "_API_KEY", "_APIKEY", "_SECRET", "_SECRET_KEY", "_PASSWORD", "_PASSWD", "_PAT", "_ACCESS_KEY", "_PRIVATE_KEY", "_AUTHTOKEN",
    ];

    /// <summary>Secrets whose names do not follow the pattern.</summary>
    private static readonly string[] SecretNames = ["GITHUB_PAT", "TWINE_PASSWORD", "DOCKER_AUTH_CONFIG", "VCPKG_BINARY_SOURCES_SAS"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (PersistentVariables.Load(context.Probes, out IReadOnlyList<PersistentVariable> variables) is { } failed)
        {
            return failed;
        }

        // Which tools are here decides which variables their own checks already report.
        bool? uv = null;
        bool? pnpm = null;
        bool? scoop = null;

        var secrets = new List<Finding>();
        foreach (PersistentVariable variable in variables)
        {
            if (!NamesASecret(variable.Name) || variable.Value.Trim().Length == 0 || IsFilePath(variable.Value))
            {
                continue;
            }

            if (ReportedElsewhere(variable.Name))
            {
                continue;
            }

            secrets.Add(Finding.Problem($"Variable {variable.Name}", "Holds a secret, set for good", "Not set", variable.Source));
        }

        return secrets.Count switch
        {
            0 => CheckOutcome.Pass(
                "No permanent variable holds a token or password.",
                Finding.Ok("Variables named like a secret", "None set", "None set")),
            1 => CheckOutcome.Fail("1 permanent variable holds a token or password.", secrets),
            _ => CheckOutcome.Fail($"{secrets.Count} permanent variables hold tokens or passwords.", secrets),
        };

        bool ReportedElsewhere(string name)
        {
            // npm's and Yarn's checks report their variables whether or not the tool is installed.
            if (name.Equals("NPM_TOKEN", StringComparison.OrdinalIgnoreCase) || name.Equals("NODE_AUTH_TOKEN", StringComparison.OrdinalIgnoreCase) ||
                NpmCredentialsCheck.HoldsToken(name) || name.StartsWith("YARN_NPM_AUTH_", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // The others do only when their tool is.
            if (UvCredentialsCheck.HoldsSecret(name))
            {
                return uv ??= UvLocator.Locate(context.Probes, out UvInstall? found) is null && found is not null;
            }

            if (name.StartsWith("pnpm_config_", StringComparison.OrdinalIgnoreCase))
            {
                return pnpm ??= PnpmLocator.Locate(context.Probes, out PnpmInstall? found) is null && found is not null;
            }

            if (name.Equals("SCOOP_GH_TOKEN", StringComparison.OrdinalIgnoreCase))
            {
                return scoop ??= ScoopLocator.Locate(context.Probes, out ScoopInstall? found) is null && found is not null;
            }

            return false;
        }
    }

    /// <summary>Whether a variable's name says it holds a secret.</summary>
    internal static bool NamesASecret(string name) =>
        SecretNames.Contains(name, StringComparer.OrdinalIgnoreCase) ||
        SecretEndings.Any(ending => name.EndsWith(ending, StringComparison.OrdinalIgnoreCase)) ||
        name.EndsWith(":_auth", StringComparison.OrdinalIgnoreCase) || name.EndsWith(":_password", StringComparison.OrdinalIgnoreCase);

    /// <summary>A value that names a file (a key file, a token file) is a pointer, not the secret.</summary>
    private static bool IsFilePath(string value)
    {
        string text = value.Trim();
        return text.StartsWith(@"\\", StringComparison.Ordinal) ||
            (text.Length >= 3 && char.IsAsciiLetter(text[0]) && text[1] == ':' && text[2] is '\\' or '/');
    }
}
