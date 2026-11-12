using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Npm;

/// <summary>The npm settings files of the user: the user's <c>.npmrc</c> (or the file a variable names) and npm's global one.</summary>
internal static class NpmFiles
{
    /// <summary>
    /// The files that exist; empty when there are none. Returns the outcome when something
    /// needed to tell could not be read.
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
/// The user's <c>.npmrc</c> must not hold registry tokens as plain text. npm, pnpm and Yarn 1
/// all read this file, and <c>npm login</c> writes the token there. Only the registry a token
/// is for is reported; a line that refers to an environment variable is not a stored token.
/// </summary>
public sealed class NpmCredentialsCheck : ICheck
{
    public const string Id = "sc.npm.credentials";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (NpmFiles.Load(context.Probes, out List<SettingsFile> files) is { } failed)
        {
            return failed;
        }

        if (files.Count == 0)
        {
            return CheckOutcome.NotApplicable("There is no .npmrc file.");
        }

        if (files.FirstOrDefault(f => f.Problem is not null)?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        List<Finding> tokens = [.. files.SelectMany(NpmTokens.In)];
        return tokens.Count == 0
            ? CheckOutcome.Pass(
                "Your .npmrc holds no registry tokens as plain text.",
                Finding.Ok("Registry tokens", "None stored as plain text", "Not stored as plain text"))
            : CheckOutcome.Fail(
                tokens.Count == 1 ? "Your .npmrc holds a registry token as plain text." : $"Your .npmrc holds {tokens.Count} registry tokens as plain text.",
                tokens);
    }
}

/// <summary>
/// npm's settings must not switch off TLS checks, point at a registry over plain HTTP, or let
/// every package run install scripts (npm 12 denies them unless a project allows them; the
/// "allow all" switch undoes that).
/// </summary>
public sealed class NpmSettingsCheck : ICheck
{
    public const string Id = "sc.npm.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (NpmFiles.Load(context.Probes, out List<SettingsFile> files) is { } failed)
        {
            return failed;
        }

        if (files.Count == 0)
        {
            return CheckOutcome.NotApplicable("There is no .npmrc file.");
        }

        var problems = new List<Finding>();
        foreach (SettingsFile file in files)
        {
            foreach ((string key, ConfigNode value) in file.Root?.Entries ?? [])
            {
                string? text = (value as ConfigScalar)?.Text.Trim();
                if (text is null)
                {
                    continue;
                }

                if (key == "strict-ssl" && text.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    problems.Add(Finding.Problem("TLS certificate checks", "Off", "On", file.At(value)));
                }
                else if (key == "dangerously-allow-all-scripts" && text.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    problems.Add(Finding.Problem("Install scripts", "Every package may run them", "Only approved packages", file.At(value)));
                }
                else if ((key == "registry" || key.EndsWith(":registry", StringComparison.Ordinal)) &&
                    text.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    problems.Add(Finding.Problem(
                        key == "registry" ? "Default registry" : $"Registry for {key[..^":registry".Length]}", "Plain HTTP", "HTTPS", file.At(value)));
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"npm: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"npm has {problems.Count} protections switched off.",
                problems);
        }

        if (files.FirstOrDefault(f => f.Problem is not null)?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Pass("npm's settings keep its protections on.", Finding.Ok("Protections switched off", "None", "None"));
    }
}
