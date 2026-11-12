using SecReview.Checks;
using SecReview.Config;

namespace SecReview.SupplyChain.Uv;

/// <summary>
/// uv must get packages, and itself, only from sources it can trust: no index strategy that
/// lets a public package stand in for a private one, no host exempt from TLS checks, no plain
/// HTTP index, no private index that falls through to the public one on "access denied", no
/// switched-off integrity checks, and no replaced download source for Python or for uv.
/// Settings files and persistent environment variables are both read. Values that may hold
/// credentials (index URLs) are never shown, only where they are.
/// </summary>
public sealed class UvSourcesCheck : ICheck
{
    public const string Id = "sc.uv.sources";

    /// <summary>Variables that switch a protection off when set to anything.</summary>
    private static readonly (string Name, string Item)[] UnsafeSwitches =
    [
        ("UV_INSECURE_HOST", "Hosts exempt from TLS checks"),
        ("UV_NO_VERIFY_HASHES", "Hash verification"),
        ("UV_INSECURE_NO_ZIP_VALIDATION", "Archive validation"),
        ("UV_SKIP_WHEEL_FILENAME_CHECK", "Package file name check"),
    ];

    /// <summary>Settings and variables that replace where Python, or uv itself, is downloaded from.</summary>
    private static readonly (string? Setting, string Variable, string Item)[] DownloadSources =
    [
        ("python-install-mirror", "UV_PYTHON_INSTALL_MIRROR", "Python download source"),
        ("pypy-install-mirror", "UV_PYPY_INSTALL_MIRROR", "PyPy download source"),
        ("python-downloads-json-url", "UV_PYTHON_DOWNLOADS_JSON_URL", "Python download list"),
        (null, "UV_INSTALLER_GITHUB_BASE_URL", "uv update source"),
        (null, "UV_DOWNLOAD_URL", "uv update source"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (UvLocator.Locate(context.Probes, out UvInstall? uv) is { } failed)
        {
            return failed;
        }

        if (uv is null)
        {
            return CheckOutcome.NotApplicable("uv is not installed.");
        }

        var problems = new List<Finding>();

        // Index strategy: the variable wins over the files.
        if (PersistentEnvironment.Read(context.Probes, "UV_INDEX_STRATEGY", out string? strategy, out string? strategySource) is { } unread)
        {
            return unread;
        }

        if (strategy is null && uv.Find("index-strategy") is { Value: ConfigScalar { Kind: ScalarKind.Text } written } strategyFile)
        {
            (strategy, strategySource) = (written.Text, strategyFile.File.At(written));
        }

        if (strategy is not null && strategy.StartsWith("unsafe-", StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(Finding.Problem("Index strategy", strategy, "first-index", strategySource));
        }

        foreach ((string name, string item) in UnsafeSwitches)
        {
            if (PersistentEnvironment.Read(context.Probes, name, out string? value, out string? source) is { } unreadSwitch)
            {
                return unreadSwitch;
            }

            if (value is not null)
            {
                problems.Add(Finding.Problem(item, name == "UV_INSECURE_HOST" ? "Some" : "Switched off", name == "UV_INSECURE_HOST" ? "None" : "On", source));
            }
        }

        foreach ((string? setting, string variable, string item) in DownloadSources)
        {
            if (PersistentEnvironment.Read(context.Probes, variable, out string? value, out string? source) is { } unreadSource)
            {
                return unreadSource;
            }

            if (value is null && setting is not null && uv.Find(setting) is { } inFile)
            {
                (value, source) = (string.Empty, inFile.File.At(inFile.Value));
            }

            if (value is not null)
            {
                problems.Add(Finding.Problem(item, "Replaced", "uv's own", source));
            }
        }

        // The files: every one uv reads counts, since list settings are joined across them.
        foreach (SettingsFile file in uv.Files)
        {
            if (file.Root is not { } root)
            {
                continue;
            }

            if (root["allow-insecure-host"] is ConfigList { Items.Count: > 0 } hosts)
            {
                problems.Add(Finding.Problem(
                    "Hosts exempt from TLS checks", hosts.Items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), "None", file.At(hosts)));
            }

            foreach ((string key, ConfigNode value) in root.Entries)
            {
                if (key is "index-url" or "extra-index-url" or "find-links")
                {
                    foreach (ConfigScalar url in Scalars(value))
                    {
                        AddUrlProblems(problems, key, url, file);
                    }
                }
            }

            if (root["index"] is ConfigList indexes)
            {
                foreach (ConfigMap index in indexes.Items.OfType<ConfigMap>())
                {
                    string name = index["name"] is ConfigScalar { Kind: ScalarKind.Text } named ? $"Index \"{named.Text}\"" : "An index";
                    if (index["url"] is ConfigScalar url)
                    {
                        AddUrlProblems(problems, name, url, file);
                    }

                    // uv stops at "access denied" from an index. Told to ignore it, uv moves on to
                    // the next index, and a public package can take a private one's place.
                    if (index["ignore-error-codes"] is ConfigList codes &&
                        Scalars(codes).Any(c => c.AsNumber is 401 or 403))
                    {
                        problems.Add(Finding.Problem(name, "Ignores \"access denied\"", "Stops on it", file.At(codes)));
                    }

                    if (index[UvCooldownCheck.Setting] is ConfigScalar { AsBoolean: false } noWait)
                    {
                        problems.Add(Finding.Problem(name, "Exempt from the release wait", "Not exempt", file.At(noWait)));
                    }
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"uv: {Describe(problems[0])}."
                    : $"uv has {problems.Count} settings that weaken where it gets packages from.",
                problems);
        }

        // Nothing found. If a settings file could not be read, "nothing wrong" is not known.
        if (uv.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Pass(
            "uv gets packages only from verified sources.",
            Finding.Ok("Index strategy", strategy ?? "first-index (uv's default)", "first-index", strategySource),
            Finding.Ok("Hosts exempt from TLS checks", "None", "None"),
            Finding.Ok("Download sources for Python and uv", "uv's own", "uv's own"));
    }

    private static string Describe(Finding problem) => $"{Wording.LowerFirst(problem.Item)}: {Wording.LowerFirst(problem.Found)}";

    private static IEnumerable<ConfigScalar> Scalars(ConfigNode node) => node switch
    {
        ConfigScalar scalar => [scalar],
        ConfigList list => list.Items.OfType<ConfigScalar>(),
        _ => [],
    };

    /// <summary>A plain-HTTP address, or one with a user name and password written into it. The address itself is not shown.</summary>
    private static void AddUrlProblems(List<Finding> problems, string item, ConfigScalar url, SettingsFile file)
    {
        string text = url.Text.Trim();
        if (text.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(Finding.Problem(item, "Plain HTTP", "HTTPS", file.At(url)));
        }

        if (Uri.TryCreate(text, UriKind.Absolute, out Uri? address) && address.UserInfo.Contains(':', StringComparison.Ordinal))
        {
            problems.Add(Finding.Problem(item, "A password in the address", "No password in files", file.At(url)));
        }
    }
}
