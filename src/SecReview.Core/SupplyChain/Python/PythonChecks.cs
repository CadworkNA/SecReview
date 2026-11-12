using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Python;

/// <summary>pip's settings files for the user, in the order pip prefers them.</summary>
internal static class PipFiles
{
    /// <summary>The pip.ini files that exist. Returns the outcome when something needed to tell could not be read.</summary>
    public static CheckOutcome? Load(SystemProbes probes, out List<SettingsFile> files)
    {
        files = [];
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!profile.IsOk || !roaming.IsOk || !programData.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        if (PersistentEnvironment.Read(probes, "PIP_CONFIG_FILE", out string? configFile, out _) is { } failed)
        {
            return failed;
        }

        string[] paths =
        [
            .. configFile is null ? Array.Empty<string>() : [configFile],
            $@"{roaming.Value}\pip\pip.ini",
            $@"{profile.Value}\pip\pip.ini",
            $@"{programData.Value}\pip\pip.ini",
        ];
        foreach (string path in paths)
        {
            if (SettingsFiles.Load(probes.Files, path, SettingsFormat.PythonIni) is { } file)
            {
                files.Add(file);
            }
        }

        return null;
    }

    /// <summary>Whether an address carries a password ("https://user:password@host/...").</summary>
    public static bool HasPassword(string address) =>
        Uri.TryCreate(address.Trim(), UriKind.Absolute, out Uri? uri) && uri.UserInfo.Contains(':', StringComparison.Ordinal) &&
        uri.UserInfo[(uri.UserInfo.IndexOf(':', StringComparison.Ordinal) + 1)..].Length > 0;
}

/// <summary>
/// pip must take packages from one index, over HTTPS, with TLS checked. An extra index lets a
/// public package with the same name stand in for a private one; a "trusted host" is a host
/// whose certificate pip no longer checks. The pip.ini files and the persistent variables that
/// set the same things are read.
/// </summary>
public sealed class PipSettingsCheck : ICheck
{
    public const string Id = "sc.pip.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (PipFiles.Load(context.Probes, out List<SettingsFile> files) is { } failed)
        {
            return failed;
        }

        var problems = new List<Finding>();
        foreach ((string variable, string item, string found, string expected) in new[]
        {
            ("PIP_TRUSTED_HOST", "Hosts exempt from TLS checks", "Some", "None"),
            ("PIP_EXTRA_INDEX_URL", "Extra package indexes", "Some", "None"),
        })
        {
            if (PersistentEnvironment.Read(context.Probes, variable, out string? value, out string? source) is { } unread)
            {
                return unread;
            }

            if (value is not null)
            {
                problems.Add(Finding.Problem(item, found, expected, source));
            }
        }

        if (files.Count == 0 && problems.Count == 0)
        {
            return CheckOutcome.NotApplicable("There is no pip.ini file.");
        }

        foreach (SettingsFile file in files)
        {
            // pip takes these from [global], and from the section of the command being run.
            foreach ((_, ConfigNode section) in file.Root?.Entries ?? [])
            {
                if (section is not ConfigMap settings)
                {
                    continue;
                }

                if (settings["trusted-host"] is { } trusted && trusted.All().Any(v => v.Text.Length > 0))
                {
                    problems.Add(Finding.Problem("Hosts exempt from TLS checks", "Some", "None", file.At(trusted)));
                }

                if (settings["extra-index-url"] is { } extra && extra.All().Any(v => v.Text.Length > 0))
                {
                    problems.Add(Finding.Problem("Extra package indexes", "Some", "None", file.At(extra)));
                }

                foreach (string key in (string[])["index-url", "extra-index-url", "find-links"])
                {
                    foreach (ConfigScalar address in settings[key].All())
                    {
                        if (address.Text.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                        {
                            problems.Add(Finding.Problem($"Package index ({key})", "Plain HTTP", "HTTPS", file.At(address)));
                        }
                    }
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"pip: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"pip has {problems.Count} settings that weaken where it gets packages from.",
                problems);
        }

        if (files.FirstOrDefault(f => f.Problem is not null)?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Pass(
            "pip gets packages from one index, over HTTPS.",
            Finding.Ok("Extra package indexes", "None", "None"),
            Finding.Ok("Hosts exempt from TLS checks", "None", "None"));
    }
}

/// <summary>
/// Passwords and tokens for Python package indexes must not sit in plain files: the
/// <c>.pypirc</c> that publishing tools read, an index address with a password in pip.ini,
/// and Poetry's <c>auth.toml</c>. Only the file and the index a secret is for are reported.
/// </summary>
public sealed class PythonCredentialsCheck : ICheck
{
    public const string Id = "sc.pypi.credentials";

    private const string Expected = "Not stored as plain text";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (PipFiles.Load(probes, out List<SettingsFile> pipFiles) is { } failed)
        {
            return failed;
        }

        // PipFiles.Load succeeding means these folders are known.
        string profile = probes.Environment.Folder(KnownFolder.UserProfile).Value!;
        string roaming = probes.Environment.Folder(KnownFolder.RoamingAppData).Value!;
        SettingsFile? pypirc = SettingsFiles.Load(probes.Files, $@"{profile}\.pypirc", SettingsFormat.PythonIni);
        SettingsFile? poetry = SettingsFiles.Load(probes.Files, $@"{roaming}\pypoetry\auth.toml", SettingsFormat.Toml);

        if (pypirc is null && poetry is null && pipFiles.Count == 0)
        {
            return CheckOutcome.NotApplicable("There are no Python packaging settings files.");
        }

        var secrets = new List<Finding>();

        // .pypirc: a section per index, each with username and password.
        foreach ((string index, ConfigNode section) in pypirc?.Root?.Entries ?? [])
        {
            // A password may sit on the line below its key, which makes it a continued value.
            if ((section as ConfigMap)?["password"].All().FirstOrDefault(p => p.Text.Length > 0) is { } password)
            {
                secrets.Add(Finding.Problem($"Password for {index}", "Stored as plain text", Expected, pypirc!.At(password)));
            }
        }

        // pip.ini: an index address with the password written into it.
        foreach (SettingsFile file in pipFiles)
        {
            foreach ((_, ConfigNode section) in file.Root?.Entries ?? [])
            {
                foreach (string key in (string[])["index-url", "extra-index-url"])
                {
                    foreach (ConfigScalar address in ((section as ConfigMap)?[key]).All())
                    {
                        if (PipFiles.HasPassword(address.Text))
                        {
                            secrets.Add(Finding.Problem($"Password in an index address ({key})", "Stored as plain text", Expected, file.At(address)));
                        }
                    }
                }
            }
        }

        // Poetry auth.toml: [http-basic.<index>] password, and [pypi-token] <index> = token.
        foreach ((string index, ConfigNode entry) in (poetry?.Root?["http-basic"] as ConfigMap)?.Entries ?? [])
        {
            if ((entry as ConfigMap)?["password"] is ConfigScalar { Text.Length: > 0 } password)
            {
                secrets.Add(Finding.Problem($"Password for {index}", "Stored as plain text", Expected, poetry!.At(password)));
            }
        }

        foreach ((string index, ConfigNode token) in (poetry?.Root?["pypi-token"] as ConfigMap)?.Entries ?? [])
        {
            if (token is ConfigScalar { Text.Length: > 0 })
            {
                secrets.Add(Finding.Problem($"Token for {index}", "Stored as plain text", Expected, poetry!.At(token)));
            }
        }

        if (secrets.Count > 0)
        {
            return CheckOutcome.Fail(
                secrets.Count == 1
                    ? "A Python package index password is stored as plain text."
                    : $"{secrets.Count} Python package index passwords are stored as plain text.",
                secrets);
        }

        string? problem = pypirc?.Problem ?? poetry?.Problem ?? pipFiles.FirstOrDefault(f => f.Problem is not null)?.Problem;
        return problem is not null
            ? CheckOutcome.Error(problem)
            : CheckOutcome.Pass(
                "No Python package index passwords are stored as plain text.",
                Finding.Ok("Index passwords and tokens", "None stored as plain text", Expected));
    }
}
