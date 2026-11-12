using SecReview.Checks;
using SecReview.Config;

namespace SecReview.SupplyChain;

/// <summary>
/// Finds sign-in secrets written into npm-style settings files (<c>.npmrc</c>, pnpm's
/// <c>rc</c> and <c>auth.ini</c>). Only the key and its line are reported. A value that only
/// refers to an environment variable (<c>${NPM_TOKEN}</c>) is not a stored secret.
/// </summary>
internal static class NpmTokens
{
    private const string Expected = "Not stored as plain text";

    /// <summary>The keys (or key endings) under which npm and pnpm keep a secret.</summary>
    private static readonly string[] SecretKeys = ["_authToken", "_auth", "_password"];

    /// <summary>A finding for every literal secret in the file's top level.</summary>
    public static IEnumerable<Finding> In(SettingsFile file)
    {
        if (file.Root is null)
        {
            yield break;
        }

        foreach ((string key, ConfigNode value) in file.Root.Entries)
        {
            if (IsSecretKey(key) && value is ConfigScalar { Text.Length: > 0 } secret && !IsReference(secret.Text))
            {
                yield return Finding.Problem(Describe(key), "Stored as plain text", Expected, file.At(secret));
            }
        }
    }

    /// <summary>Whether a value only names an environment variable: "${NAME}", possibly with a default.</summary>
    public static bool IsReference(string value)
    {
        string text = value.Trim();
        return text.StartsWith("${", StringComparison.Ordinal) && text.EndsWith('}') && text.IndexOf('}', StringComparison.Ordinal) == text.Length - 1;
    }

    private static bool IsSecretKey(string key) =>
        SecretKeys.Any(secret => key.Equals(secret, StringComparison.Ordinal) || key.EndsWith(":" + secret, StringComparison.Ordinal));

    /// <summary>"Token for registry.npmjs.org" from "//registry.npmjs.org/:_authToken"; the key itself where it names no host.</summary>
    private static string Describe(string key)
    {
        int colon = key.LastIndexOf(':');
        string what = key.EndsWith("_password", StringComparison.Ordinal) ? "Password" : "Token";
        if (colon > 2 && key.StartsWith("//", StringComparison.Ordinal))
        {
            string host = key[2..colon].Trim('/');
            int slash = host.IndexOf('/', StringComparison.Ordinal);
            return $"{what} for {(slash < 0 ? host : host[..slash])}";
        }

        return $"{what} ({key})";
    }
}
