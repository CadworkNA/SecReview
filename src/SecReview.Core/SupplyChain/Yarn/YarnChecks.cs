using System.Globalization;
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

    /// <summary>
    /// A setting where Yarn takes it: its <c>YARN_…</c> variable (the setting's name in capitals
    /// with underscores), else the file. Both outputs are null when nothing sets it.
    /// </summary>
    public static CheckOutcome? Setting(
        SystemProbes probes, SettingsFile? file, string name, out ConfigNode? value, out string? source)
    {
        value = null;
        if (PersistentEnvironment.Read(probes, VariableFor(name), out string? fromVariable, out source) is { } failed)
        {
            return failed;
        }

        if (fromVariable is not null)
        {
            value = new ConfigScalar(fromVariable, ScalarKind.Text, 0);
            return null;
        }

        if (file?.Root?[name] is { } inFile)
        {
            (value, source) = (inFile, file.At(inFile));
        }

        return null;
    }

    /// <summary>"enableStrictSsl" becomes "YARN_ENABLE_STRICT_SSL".</summary>
    internal static string VariableFor(string setting)
    {
        var name = new System.Text.StringBuilder("YARN_");
        foreach (char c in setting)
        {
            if (char.IsUpper(c))
            {
                name.Append('_');
            }

            name.Append(char.ToUpperInvariant(c));
        }

        return name.ToString();
    }
}

/// <summary>
/// The user's <c>.yarnrc.yml</c> must not hold registry tokens as plain text
/// (<c>npmAuthToken</c>, <c>npmAuthIdent</c>), at the top level or for a scope or registry,
/// and none may sit in a persistent <c>YARN_NPM_AUTH_…</c> variable. A value that refers to
/// an environment variable is not a stored token.
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

        var tokens = new List<Finding>();
        foreach (string key in SecretKeys)
        {
            string variable = YarnFile.VariableFor(key);
            if (PersistentEnvironment.Read(context.Probes, variable, out string? value, out _) is { } unread)
            {
                return unread;
            }

            if (value is not null)
            {
                tokens.Add(Finding.Problem($"Variable {variable}", "Holds a token, set for good", "Not set", "environment variables"));
            }
        }

        if (file is null && tokens.Count == 0)
        {
            return CheckOutcome.NotApplicable("There is no .yarnrc.yml file in your user folder.");
        }

        if (file?.Root is { } root)
        {
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
        }

        if (tokens.Count > 0)
        {
            return CheckOutcome.Fail(
                tokens.Count == 1 ? "A registry token for Yarn is stored as plain text." : $"{tokens.Count} registry tokens for Yarn are stored as plain text.",
                tokens);
        }

        return file?.Problem is { } problem
            ? CheckOutcome.Error(problem)
            : CheckOutcome.Pass("No registry tokens for Yarn are stored as plain text.", Finding.Ok("Registry tokens", "None stored as plain text", Expected));

        void Collect(ConfigMap map, string what)
        {
            foreach (string key in SecretKeys)
            {
                if (map[key] is ConfigScalar { Text.Length: > 0 } secret && !NpmTokens.IsReference(secret.Text))
                {
                    tokens.Add(Finding.Problem($"Token for {what}", "Stored as plain text", Expected, file!.At(secret)));
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
/// scripts (off by default from Yarn 4.14; switching it on undoes that). Each setting is taken
/// where Yarn takes it, its <c>YARN_…</c> variable first, and read the way Yarn reads it:
/// "false", 0 and false all switch something off.
/// </summary>
public sealed class YarnSettingsCheck : ICheck
{
    public const string Id = "sc.yarn.settings";

    /// <summary>Setting, what it is, the value that is a problem, and the words for it.</summary>
    private static readonly (string Name, string Item, bool Bad, string Found, string Expected)[] Switches =
    [
        ("enableStrictSsl", "TLS certificate checks", false, "Off", "On"),
        ("enableScripts", "Install scripts", true, "Every package may run them", "Only approved packages"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (YarnFile.Load(probes, out SettingsFile? file) is { } failed)
        {
            return failed;
        }

        if (file is { Root: null })
        {
            return CheckOutcome.Error(file.Problem!);
        }

        var problems = new List<Finding>();
        bool anyVariable = false;

        foreach ((string name, string item, bool bad, string found, string expected) in Switches)
        {
            if (YarnFile.Setting(probes, file, name, out ConfigNode? value, out string? source) is { } unread)
            {
                return unread;
            }

            if (value is null)
            {
                continue;
            }

            anyVariable |= value.Line == 0;
            if (value is not ConfigScalar scalar || Flags.Parse(scalar.Text) is not { } flag)
            {
                return CheckOutcome.Error($"Yarn's {name} setting is not yes or no ({source}).");
            }

            if (flag == bad)
            {
                problems.Add(Finding.Problem(item, found, expected, source));
            }
        }

        if (YarnFile.Setting(probes, file, "checksumBehavior", out ConfigNode? checksums, out string? checksumSource) is { } unreadChecksums)
        {
            return unreadChecksums;
        }

        anyVariable |= checksums is { Line: 0 };
        if (checksums is ConfigScalar { Text: "ignore" })
        {
            problems.Add(Finding.Problem("Checksum verification", "Ignored", "On", checksumSource));
        }

        // A list in the file; Yarn also takes a single host, and the variable is always text.
        if (YarnFile.Setting(probes, file, "unsafeHttpWhitelist", out ConfigNode? hosts, out string? hostsSource) is { } unreadHosts)
        {
            return unreadHosts;
        }

        anyVariable |= hosts is { Line: 0 };
        int allowed = hosts switch
        {
            ConfigList list => list.Items.Count,
            ConfigScalar { Kind: ScalarKind.Other } => 0, // null
            ConfigScalar { Text.Length: > 0 } => 1,
            _ => 0,
        };
        if (allowed > 0)
        {
            problems.Add(Finding.Problem("Hosts allowed over plain HTTP", allowed.ToString(CultureInfo.InvariantCulture), "None", hostsSource));
        }

        if (YarnFile.Setting(probes, file, "npmRegistryServer", out ConfigNode? server, out string? serverSource) is { } unreadServer)
        {
            return unreadServer;
        }

        anyVariable |= server is { Line: 0 };
        if (IsPlainHttp(server))
        {
            problems.Add(Finding.Problem("Default registry", "Plain HTTP", "HTTPS", serverSource));
        }

        foreach ((string scope, ConfigNode settings) in (file?.Root?["npmScopes"] as ConfigMap)?.Entries ?? [])
        {
            if ((settings as ConfigMap)?["npmRegistryServer"] is ConfigScalar scoped && IsPlainHttp(scoped))
            {
                problems.Add(Finding.Problem($"Registry for @{scope.TrimStart('@')}", "Plain HTTP", "HTTPS", file!.At(scoped)));
            }
        }

        if (file is null && !anyVariable)
        {
            return CheckOutcome.NotApplicable("There is no .yarnrc.yml file in your user folder.");
        }

        return problems.Count switch
        {
            0 => CheckOutcome.Pass("Yarn's settings keep its protections on.", Finding.Ok("Protections switched off", "None", "None")),
            1 => CheckOutcome.Fail($"Yarn: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}.", problems),
            _ => CheckOutcome.Fail($"Yarn has {problems.Count} protections switched off.", problems),
        };
    }

    private static bool IsPlainHttp(ConfigNode? node) =>
        (node as ConfigScalar)?.Text.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true;
}
