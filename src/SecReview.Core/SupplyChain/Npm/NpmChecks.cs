using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Npm;

/// <summary>The npm settings files of the user: the user's <c>.npmrc</c> (or the file a variable names) and npm's global one.</summary>
internal static class NpmFiles
{
    /// <summary>
    /// The files that exist, the user's first; empty when there are none. Returns the outcome
    /// when something needed to tell could not be read.
    /// </summary>
    public static CheckOutcome? Load(SystemProbes probes, out List<SettingsFile> files)
    {
        files = [];
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        if (!profile.IsOk || !roaming.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        if (PersistentEnvironment.Read(probes, "NPM_CONFIG_USERCONFIG", out string? userConfig, out _) is { } failed)
        {
            return failed;
        }

        foreach (string path in (string[])[userConfig ?? $@"{profile.Value}\.npmrc", $@"{roaming.Value}\npm\etc\npmrc"])
        {
            if (SettingsFiles.Load(probes.Files, path, SettingsFormat.NpmIni) is { } file)
            {
                files.Add(file);
            }
        }

        return null;
    }
}

/// <summary>
/// The user's <c>.npmrc</c> must not hold registry tokens as plain text, and no token may sit
/// in a persistent environment variable. npm, pnpm and Yarn 1 all read this file, and
/// <c>npm login</c> writes the token there. Only the registry a token is for, or the
/// variable's name, is reported; a line that refers to an environment variable is not a
/// stored token.
/// </summary>
public sealed class NpmCredentialsCheck : ICheck
{
    public const string Id = "sc.npm.credentials";

    /// <summary>Variables that, by convention, hold a registry token.</summary>
    private static readonly string[] TokenVariables = ["NPM_TOKEN", "NODE_AUTH_TOKEN"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (NpmFiles.Load(context.Probes, out List<SettingsFile> files) is { } failed)
        {
            return failed;
        }

        if (PersistentEnvironment.Names(context.Probes.Registry, out IReadOnlyList<string> variables) is { } unread)
        {
            return unread;
        }

        var tokens = new List<Finding>();
        foreach (string variable in variables)
        {
            if (TokenVariables.Contains(variable, StringComparer.OrdinalIgnoreCase) || HoldsToken(variable))
            {
                tokens.Add(Finding.Problem($"Variable {variable}", "Holds a token, set for good", "Not set", "environment variables"));
            }
        }

        if (files.Count == 0 && tokens.Count == 0)
        {
            return CheckOutcome.NotApplicable("There is no .npmrc file.");
        }

        tokens.AddRange(files.SelectMany(NpmTokens.In));
        if (tokens.Count > 0)
        {
            return CheckOutcome.Fail(
                tokens.Count == 1 ? "A registry token for npm is stored as plain text." : $"{tokens.Count} registry tokens for npm are stored as plain text.",
                tokens);
        }

        // Nothing found. If a file could not be read, "no tokens" is not known.
        if (files.FirstOrDefault(f => f.Problem is not null)?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Pass(
            "No registry tokens for npm are stored as plain text.",
            Finding.Ok("Registry tokens", "None stored as plain text", "Not stored as plain text"));
    }

    /// <summary>Whether a variable is npm's way of passing a token setting: "npm_config_" followed by a key that holds a secret.</summary>
    internal static bool HoldsToken(string variable) =>
        variable.StartsWith("npm_config_", StringComparison.OrdinalIgnoreCase) &&
        (variable.EndsWith("_authToken", StringComparison.OrdinalIgnoreCase) || variable.EndsWith("_auth", StringComparison.OrdinalIgnoreCase) ||
         variable.EndsWith("_password", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// npm's settings must not switch off TLS checks, point at a registry over plain HTTP, or let
/// every package run install scripts (npm 12 denies them unless a project allows them; the
/// "allow all" switch undoes that). A setting is taken where npm takes it: the
/// <c>npm_config_…</c> variable, then the user's file, then the global one.
/// </summary>
public sealed class NpmSettingsCheck : ICheck
{
    public const string Id = "sc.npm.settings";

    /// <summary>Setting, what it is, the value that is a problem, and the words for it.</summary>
    private static readonly (string Key, string Item, bool Bad, string Found, string Expected)[] Switches =
    [
        ("strict-ssl", "TLS certificate checks", false, "Off", "On"),
        ("dangerously-allow-all-scripts", "Install scripts", true, "Every package may run them", "Only approved packages"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (NpmFiles.Load(probes, out List<SettingsFile> files) is { } failed)
        {
            return failed;
        }

        var problems = new List<Finding>();
        bool anyVariable = false;

        foreach ((string key, string item, bool bad, string found, string expected) in Switches)
        {
            if (Effective(probes, files, key, out string? value, out string? source) is { } unread)
            {
                return unread;
            }

            anyVariable |= source?.Contains("environment", StringComparison.Ordinal) == true;
            if (value is not null && Flags.Parse(value) == bad)
            {
                problems.Add(Finding.Problem(item, found, expected, source));
            }
        }

        if (Effective(probes, files, "registry", out string? registry, out string? registrySource) is { } unreadRegistry)
        {
            return unreadRegistry;
        }

        anyVariable |= registrySource?.Contains("environment", StringComparison.Ordinal) == true;
        if (IsPlainHttp(registry))
        {
            problems.Add(Finding.Problem("Default registry", "Plain HTTP", "HTTPS", registrySource));
        }

        // Registries for a scope ("@company:registry") can only be set in the files.
        foreach (SettingsFile file in files)
        {
            foreach ((string key, ConfigNode value) in file.Root?.Entries ?? [])
            {
                if (key.EndsWith(":registry", StringComparison.Ordinal) && file.Single(value) is { } scoped && IsPlainHttp(scoped.Text))
                {
                    problems.Add(Finding.Problem($"Registry for {key[..^":registry".Length]}", "Plain HTTP", "HTTPS", file.At(scoped)));
                }
            }
        }

        if (files.Count == 0 && !anyVariable)
        {
            return CheckOutcome.NotApplicable("There is no .npmrc file.");
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"npm: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"npm has {problems.Count} protections switched off.",
                problems);
        }

        // Nothing found. If a file could not be read, "nothing wrong" is not known.
        if (files.FirstOrDefault(f => f.Problem is not null)?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Pass("npm's settings keep its protections on.", Finding.Ok("Protections switched off", "None", "None"));
    }

    /// <summary>
    /// The value npm uses for a setting and where it comes from: the <c>npm_config_…</c>
    /// variable, else the first file that sets it. Both null when nothing sets it.
    /// </summary>
    private static CheckOutcome? Effective(SystemProbes probes, List<SettingsFile> files, string key, out string? value, out string? source)
    {
        string variable = "npm_config_" + key.Replace('-', '_');
        if (PersistentEnvironment.Read(probes, variable, out value, out source) is { } failed)
        {
            return failed;
        }

        if (value is not null)
        {
            return null;
        }

        foreach (SettingsFile file in files)
        {
            if (file.Single(file.Root?[key]) is { } inFile)
            {
                (value, source) = (inFile.Text, file.At(inFile));
                return null;
            }
        }

        return null;
    }

    private static bool IsPlainHttp(string? address) =>
        address?.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true;
}
