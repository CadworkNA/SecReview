using System.Text.Json;
using SecReview.Checks;

namespace SecReview.SupplyChain.Scoop;

/// <summary>
/// Scoop keeps its settings, tokens included, in a plain JSON file. A GitHub token, a
/// VirusTotal key, a proxy address with a password in it, or request headers for private
/// hosts are all readable by every program the user runs. Only the name of the setting is
/// reported, never its value.
/// </summary>
public sealed class ScoopCredentialsCheck : ICheck
{
    public const string Id = "sc.scoop.credentials";

    private const string Expected = "Not stored as plain text";

    private static readonly (string Setting, string Item)[] SecretSettings =
    [
        ("gh_token", "GitHub token"),
        ("virustotal_api_key", "VirusTotal key"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (ScoopLocator.Locate(context.Probes, out ScoopInstall? scoop) is { } failed)
        {
            return failed;
        }

        if (scoop is null)
        {
            return CheckOutcome.NotApplicable("Scoop is not installed.");
        }

        var problems = new List<Finding>();
        foreach ((string setting, string item) in SecretSettings)
        {
            if (!string.IsNullOrEmpty(scoop.Setting(setting)))
            {
                problems.Add(Finding.Problem(item, "Stored as plain text", Expected, $"{scoop.ConfigPath} ({setting})"));
            }
        }

        // A proxy written as user:password@host.
        if (scoop.Setting("proxy") is { } proxy && proxy.Contains('@', StringComparison.Ordinal) &&
            proxy[..proxy.IndexOf('@', StringComparison.Ordinal)].Contains(':', StringComparison.Ordinal))
        {
            problems.Add(Finding.Problem("Proxy password", "Stored as plain text", Expected, $"{scoop.ConfigPath} (proxy)"));
        }

        // Headers sent to private hosts usually are, or carry, a token.
        if (scoop.Config is { ValueKind: JsonValueKind.Object } config &&
            config.TryGetProperty("private_hosts", out JsonElement hosts) && hosts.ValueKind == JsonValueKind.Array &&
            hosts.EnumerateArray().Any(h => h.ValueKind == JsonValueKind.Object && h.TryGetProperty("headers", out JsonElement headers) &&
                headers.ValueKind is JsonValueKind.String or JsonValueKind.Object or JsonValueKind.Array))
        {
            problems.Add(Finding.Problem("Sign-in headers for private hosts", "Stored as plain text", Expected, $"{scoop.ConfigPath} (private_hosts)"));
        }

        if (PersistentEnvironment.Read(context.Probes, "SCOOP_GH_TOKEN", out string? token, out string? source) is { } unread)
        {
            return unread;
        }

        if (token is not null)
        {
            problems.Add(Finding.Problem("GitHub token in a variable", "Set for good", "Not set", source));
        }

        return problems.Count == 0
            ? CheckOutcome.Pass("Scoop keeps no tokens as plain text.", Finding.Ok("Tokens and passwords", "None stored as plain text", Expected))
            : CheckOutcome.Fail(
                problems.Count == 1 ? "Scoop keeps a token as plain text." : $"Scoop keeps {problems.Count} tokens as plain text.",
                problems);
    }
}
