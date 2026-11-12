using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Yarn;

/// <summary>The user's <c>.yarnrc.yml</c>, which Yarn 2 and later read for every project.</summary>
internal static class YarnFile
{
    /// <summary>The file; null if there is none. Returns the outcome when the user folder is not known.</summary>
    public static CheckOutcome? Load(SystemProbes probes, out SettingsFile? file)
    {
        file = null;
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        if (!profile.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folder is.");
        }

        file = SettingsFiles.Load(probes.Files, $@"{profile.Value}\.yarnrc.yml", SettingsFormat.Yaml);
        return null;
    }
}

/// <summary>
/// The user's <c>.yarnrc.yml</c> must not hold registry tokens as plain text
/// (<c>npmAuthToken</c>, <c>npmAuthIdent</c>), at the top level or for a scope or registry.
/// A value that refers to an environment variable is not a stored token.
/// </summary>
public sealed class YarnCredentialsCheck : ICheck
{
    public const string Id = "sc.yarn.credentials";

    private const string Expected = "Not stored as plain text";

    private static readonly string[] SecretKeys = ["npmAuthToken", "npmAuthIdent"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (YarnFile.Load(context.Probes, out SettingsFile? file) is { } failed)
        {
            return failed;
        }

        if (file is null)
        {
            return CheckOutcome.NotApplicable("There is no .yarnrc.yml file in your user folder.");
        }

        if (file.Root is not { } root)
        {
            return CheckOutcome.Error(file.Problem!);
        }

        var tokens = new List<Finding>();
        Collect(root, "the default registry");
        foreach (string group in (string[])["npmScopes", "npmRegistries"])
        {
            foreach ((string name, ConfigNode settings) in (root[group] as ConfigMap)?.Entries ?? [])
            {
                if (settings is ConfigMap map)
                {
                    Collect(map, group == "npmScopes" ? $"@{name.TrimStart('@')}" : Host(name));
                }
            }
        }

        return tokens.Count == 0
            ? CheckOutcome.Pass("Your .yarnrc.yml holds no registry tokens as plain text.", Finding.Ok("Registry tokens", "None stored as plain text", Expected))
            : CheckOutcome.Fail(
                tokens.Count == 1 ? "Your .yarnrc.yml holds a registry token as plain text." : $"Your .yarnrc.yml holds {tokens.Count} registry tokens as plain text.",
                tokens);

        void Collect(ConfigMap map, string what)
        {
            foreach (string key in SecretKeys)
            {
                if (map[key] is ConfigScalar { Text.Length: > 0 } secret && !NpmTokens.IsReference(secret.Text))
                {
                    tokens.Add(Finding.Problem($"Token for {what}", "Stored as plain text", Expected, file.At(secret)));
                }
            }
        }
    }

    /// <summary>The host of a registry address ("//npm.example/path" or a full URL); never more than that.</summary>
    private static string Host(string registry)
    {
        string text = registry.StartsWith("//", StringComparison.Ordinal) ? "https:" + registry : registry;
        return Uri.TryCreate(text, UriKind.Absolute, out Uri? address) && address.Host.Length > 0 ? address.Host : "a registry";
    }
}

/// <summary>
/// Yarn's user settings must not switch off TLS checks or checksum verification, allow plain
/// HTTP for any host, point at a registry over plain HTTP, or let every package run install
/// scripts (off by default from Yarn 4.14; switching it on undoes that).
/// </summary>
public sealed class YarnSettingsCheck : ICheck
{
    public const string Id = "sc.yarn.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (YarnFile.Load(context.Probes, out SettingsFile? file) is { } failed)
        {
            return failed;
        }

        if (file is null)
        {
            return CheckOutcome.NotApplicable("There is no .yarnrc.yml file in your user folder.");
        }

        if (file.Root is not { } root)
        {
            return CheckOutcome.Error(file.Problem!);
        }

        var problems = new List<Finding>();
        if (root["enableStrictSsl"] is ConfigScalar { AsBoolean: false } tls)
        {
            problems.Add(Finding.Problem("TLS certificate checks", "Off", "On", file.At(tls)));
        }

        if (root["checksumBehavior"] is ConfigScalar { Text: "ignore" } checksums)
        {
            problems.Add(Finding.Problem("Checksum verification", "Ignored", "On", file.At(checksums)));
        }

        if (root["enableScripts"] is ConfigScalar { AsBoolean: true } scripts)
        {
            problems.Add(Finding.Problem("Install scripts", "Every package may run them", "Only approved packages", file.At(scripts)));
        }

        if (root["unsafeHttpWhitelist"] is ConfigList { Items.Count: > 0 } hosts)
        {
            problems.Add(Finding.Problem(
                "Hosts allowed over plain HTTP", hosts.Items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), "None", file.At(hosts)));
        }

        if (root["npmRegistryServer"] is ConfigScalar server && server.Text.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(Finding.Problem("Default registry", "Plain HTTP", "HTTPS", file.At(server)));
        }

        foreach ((string scope, ConfigNode settings) in (root["npmScopes"] as ConfigMap)?.Entries ?? [])
        {
            if ((settings as ConfigMap)?["npmRegistryServer"] is ConfigScalar scoped &&
                scoped.Text.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                problems.Add(Finding.Problem($"Registry for @{scope.TrimStart('@')}", "Plain HTTP", "HTTPS", file.At(scoped)));
            }
        }

        return problems.Count switch
        {
            0 => CheckOutcome.Pass("Yarn's settings keep its protections on.", Finding.Ok("Protections switched off", "None", "None")),
            1 => CheckOutcome.Fail($"Yarn: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}.", problems),
            _ => CheckOutcome.Fail($"Yarn has {problems.Count} protections switched off.", problems),
        };
    }
}
