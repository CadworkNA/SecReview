using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Credentials;

namespace SecReview.SupplyChain.Cargo;

/// <summary>Where Cargo keeps the user's settings: <c>%USERPROFILE%\.cargo</c>, or the folder <c>CARGO_HOME</c> names.</summary>
internal static class CargoHome
{
    /// <summary>Cargo's folder; null when it does not exist. Returns the outcome for a failed read.</summary>
    public static CheckOutcome? Locate(SystemProbes probes, out string? home)
    {
        home = null;
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        if (!profile.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folder is.");
        }

        if (PersistentEnvironment.Read(probes, "CARGO_HOME", out string? moved, out _) is { } failed)
        {
            return failed;
        }

        string folder = string.IsNullOrWhiteSpace(moved) ? $@"{profile.Value}\.cargo" : moved.Trim().Replace('/', '\\').TrimEnd('\\');
        if (SettingsFiles.FolderExists(probes.Files, folder))
        {
            home = folder;
        }

        return null;
    }

    /// <summary>
    /// A settings file of Cargo's. When both the older name without ".toml" and the newer one
    /// with it exist, Cargo uses the one without, and so does this.
    /// </summary>
    public static SettingsFile? Load(IFileProbe files, string home, string name) =>
        SettingsFiles.Load(files, $@"{home}\{name}", SettingsFormat.Toml) ?? SettingsFiles.Load(files, $@"{home}\{name}.toml", SettingsFormat.Toml);
}

/// <summary>
/// Cargo must keep checking that a server's certificate has not been revoked
/// (<c>http.check-revoke</c>, on by default on Windows) and must not reach a registry over
/// plain HTTP. A replacement for crates.io (a mirror, or vendored sources) is listed, not
/// failed: it is a choice, shown so that it stays one. Cargo has no wait for new releases
/// that could be checked here.
/// </summary>
public sealed class CargoSettingsCheck : ICheck
{
    public const string Id = "sc.cargo.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (CargoHome.Locate(probes, out string? home) is { } failed)
        {
            return failed;
        }

        if (home is null)
        {
            return CheckOutcome.NotApplicable("Cargo is not installed.");
        }

        var problems = new List<Finding>();
        var notes = new List<Finding>();

        // The variable wins over the file.
        if (PersistentEnvironment.Read(probes, "CARGO_HTTP_CHECK_REVOKE", out string? fromVariable, out string? variableSource) is { } unread)
        {
            return unread;
        }

        SettingsFile? file = CargoHome.Load(probes.Files, home, "config");
        if (fromVariable is not null)
        {
            if (Flags.Parse(fromVariable) == false)
            {
                problems.Add(Finding.Problem("Certificate revocation checks", "Off", "On", variableSource));
            }
        }
        else if (file?.Root?.Find("http", "check-revoke") is ConfigScalar { AsBoolean: false } revoke)
        {
            problems.Add(Finding.Problem("Certificate revocation checks", "Off", "On", file.At(revoke)));
        }

        if (file?.Root is { } root)
        {
            foreach ((string name, ConfigNode node) in (root["registries"] as ConfigMap)?.Entries ?? [])
            {
                if ((node as ConfigMap)?["index"] is ConfigScalar index && IsPlainHttp(index.Text))
                {
                    problems.Add(Finding.Problem($"Registry \"{name}\"", "Plain HTTP", "HTTPS", file.At(index)));
                }
            }

            foreach ((string name, ConfigNode node) in (root["source"] as ConfigMap)?.Entries ?? [])
            {
                if (node is not ConfigMap source)
                {
                    continue;
                }

                if (source["registry"] is ConfigScalar address && IsPlainHttp(address.Text))
                {
                    problems.Add(Finding.Problem($"Source \"{name}\"", "Plain HTTP", "HTTPS", file.At(address)));
                }

                if (name == "crates-io" && source["replace-with"] is ConfigScalar { Text.Length: > 0 } replaced)
                {
                    notes.Add(Finding.Note("crates.io", $"Replaced by the source \"{replaced.Text}\"", file.At(replaced)));
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"Cargo: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Cargo has {problems.Count} settings that weaken where it gets crates from.",
                [.. problems, .. notes]);
        }

        // Nothing found. If the settings file could not be read, "nothing wrong" is not known.
        if (file?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Pass(
            notes.Count == 0 ? "Cargo gets crates over HTTPS and checks certificates for revocation." : "Cargo checks certificates; crates.io is replaced by another source.",
            [Finding.Ok("Certificate revocation checks", "On", "On"), .. notes]);
    }

    private static bool IsPlainHttp(string address)
    {
        // Registry addresses may carry a "sparse+" or "registry+" prefix.
        string text = address.Trim();
        int plus = text.IndexOf('+', StringComparison.Ordinal);
        return (plus is > 0 and < 10 ? text[(plus + 1)..] : text).StartsWith("http://", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Cargo must not keep registry tokens in its plain <c>credentials.toml</c> file, which is
/// where <c>cargo login</c> writes them unless a credential provider that uses Windows'
/// own store is configured. Only the registry is named.
/// </summary>
public sealed class CargoCredentialsCheck : ICheck
{
    public const string Id = "sc.cargo.credentials";

    private static readonly string[] SecretKeys = ["token", "secret-key"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (CargoHome.Locate(context.Probes, out string? home) is { } failed)
        {
            return failed;
        }

        if (home is null)
        {
            return CheckOutcome.NotApplicable("Cargo is not installed.");
        }

        var found = new SecretFindings();
        found.SawFile();

        // Tokens used to be allowed in the settings file too; both are read.
        foreach (string name in (string[])["credentials", "config"])
        {
            SettingsFile? file = CargoHome.Load(context.Probes.Files, home, name);
            if (file is null)
            {
                continue;
            }

            if (file.Root is not { } root)
            {
                found.SawFile(file.Problem);
                continue;
            }

            foreach (string key in SecretKeys)
            {
                if (root.Find("registry", key) is { } secret && SecretFindings.IsLiteral(secret))
                {
                    found.Add("Token for crates.io", file.At(secret));
                }

                foreach ((string registry, ConfigNode node) in (root["registries"] as ConfigMap)?.Entries ?? [])
                {
                    if ((node as ConfigMap)?[key] is { } other && SecretFindings.IsLiteral(other))
                    {
                        found.Add($"Token for the registry \"{registry}\"", file.At(other));
                    }
                }
            }
        }

        return found.Outcome("Cargo", "registry tokens", "Cargo is not installed.");
    }
}
