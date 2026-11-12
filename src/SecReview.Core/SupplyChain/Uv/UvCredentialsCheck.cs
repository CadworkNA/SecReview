using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Uv;

/// <summary>
/// uv must not keep sign-in secrets where any program can read them: its plain-text
/// credentials file (written by <c>uv auth login</c>) and persistent environment variables
/// that hold a token or password. Only where a secret sits is reported (the file and the
/// service's host, or the variable's name); the secret itself is never read into a result.
/// </summary>
public sealed class UvCredentialsCheck : ICheck
{
    public const string Id = "sc.uv.credentials";

    private const string Expected = "Not stored as plain text";

    /// <summary>Variables that hold a secret by their very purpose.</summary>
    private static readonly string[] SecretVariables = ["UV_PUBLISH_TOKEN", "UV_PUBLISH_PASSWORD", "UV_GITHUB_TOKEN"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (UvLocator.Locate(probes, out UvInstall? uv) is { } failed)
        {
            return failed;
        }

        if (uv is null)
        {
            return CheckOutcome.NotApplicable("uv is not installed.");
        }

        var problems = new List<Finding>();

        if (PersistentEnvironment.Read(probes, "UV_CREDENTIALS_DIR", out string? folder, out _) is { } unread)
        {
            return unread;
        }

        string path = $@"{folder?.TrimEnd('\\', '/') ?? uv.StateFolder + @"\credentials"}\credentials.toml";
        SettingsFile? file = SettingsFiles.Load(probes.Files, path, SettingsFormat.Toml);
        if (file?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        if (file?.Root?["credential"] is ConfigList credentials)
        {
            foreach (ConfigMap credential in credentials.Items.OfType<ConfigMap>())
            {
                ConfigNode? secret = HasValue(credential["password"]) ? credential["password"]
                    : HasValue(credential["token"]) ? credential["token"]
                    : null;
                if (secret is not null)
                {
                    problems.Add(Finding.Problem(
                        $"Sign-in for {Host(credential["service"])}", "Stored as plain text", Expected, file.At(secret)));
                }
            }
        }

        if (PersistentEnvironment.Names(probes.Registry, out IReadOnlyList<string> variables) is { } unreadNames)
        {
            return unreadNames;
        }

        foreach (string variable in variables)
        {
            if (HoldsSecret(variable))
            {
                problems.Add(Finding.Problem($"Variable {variable.ToUpperInvariant()}", "Holds a secret, set for good", "Not set", "environment variables"));
            }
        }

        return problems.Count == 0
            ? CheckOutcome.Pass("uv keeps no sign-in secrets as plain text.", Finding.Ok("Sign-in secrets", "None stored as plain text", Expected))
            : CheckOutcome.Fail(
                problems.Count == 1
                    ? "uv keeps a sign-in secret as plain text."
                    : $"uv keeps {problems.Count} sign-in secrets as plain text.",
                problems);
    }

    /// <summary>Whether a variable is one uv takes a secret from.</summary>
    internal static bool HoldsSecret(string variable) =>
        SecretVariables.Contains(variable, StringComparer.OrdinalIgnoreCase) ||
        (variable.StartsWith("UV_INDEX_", StringComparison.OrdinalIgnoreCase) && variable.EndsWith("_PASSWORD", StringComparison.OrdinalIgnoreCase));

    private static bool HasValue(ConfigNode? node) => node is ConfigScalar { Text.Length: > 0 };

    /// <summary>The host of the service a credential is for; never the whole address, which may carry a user name.</summary>
    private static string Host(ConfigNode? service) =>
        service is ConfigScalar { Kind: ScalarKind.Text } text && Uri.TryCreate(text.Text, UriKind.Absolute, out Uri? address) &&
        address.Host.Length > 0
            ? address.Host
            : "a service";
}
