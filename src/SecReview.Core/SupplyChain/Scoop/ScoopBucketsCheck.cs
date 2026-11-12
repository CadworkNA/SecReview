using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Scoop;

/// <summary>
/// Scoop installs whatever a bucket's manifests say, so where the buckets come from matters.
/// Every bucket should be one of the buckets Scoop itself knows, cloned from the address
/// Scoop lists for it, and Scoop itself should come from its own repository. A bucket from
/// anywhere else is a choice someone made; it is reported so that it stays one.
/// </summary>
public sealed class ScoopBucketsCheck : ICheck
{
    public const string Id = "sc.scoop.buckets";

    internal const string DefaultRepository = "https://github.com/ScoopInstaller/Scoop";

    /// <summary>The buckets Scoop knows by name, with the address it clones each from (Scoop's own buckets.json).</summary>
    internal static readonly IReadOnlyDictionary<string, string> KnownBuckets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["main"] = "https://github.com/ScoopInstaller/Main",
        ["extras"] = "https://github.com/ScoopInstaller/Extras",
        ["versions"] = "https://github.com/ScoopInstaller/Versions",
        ["nirsoft"] = "https://github.com/ScoopInstaller/Nirsoft",
        ["sysinternals"] = "https://github.com/ScoopInstaller/Sysinternals",
        ["php"] = "https://github.com/ScoopInstaller/PHP",
        ["nerd-fonts"] = "https://github.com/matthewjberger/scoop-nerd-fonts",
        ["nonportable"] = "https://github.com/ScoopInstaller/Nonportable",
        ["java"] = "https://github.com/ScoopInstaller/Java",
        ["games"] = "https://github.com/ScoopInstaller/Games",
    };

    private const string Expected = "One of Scoop's known buckets";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Low, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IFileProbe files = context.Probes.Files;

        if (ScoopLocator.Locate(context.Probes, out ScoopInstall? scoop) is { } failed)
        {
            return failed;
        }

        if (scoop is null)
        {
            return CheckOutcome.NotApplicable("Scoop is not installed.");
        }

        ProbeResult<IReadOnlyList<FileEntry>> buckets = files.List($@"{scoop.Root}\buckets");
        if (!buckets.IsOk && buckets.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(buckets, "Scoop's buckets");
        }

        var findings = new List<Finding>();
        int problems = 0;
        string? unread = null;

        foreach (FileEntry bucket in buckets.IsOk ? buckets.Value!.Where(b => b.IsDirectory) : [])
        {
            string gitConfig = $@"{scoop.Root}\buckets\{bucket.Name}\.git\config";
            SettingsFile? config = SettingsFiles.Load(files, gitConfig, SettingsFormat.NpmIni);
            string? address = (config?.Root?.Find("remote \"origin\"", "url") as ConfigScalar)?.Text;
            if (config?.Problem is not null || address is null)
            {
                unread ??= config?.Problem ?? $"Scoop's bucket \"{bucket.Name}\" does not say where it comes from.";
                findings.Add(Finding.Problem($"Bucket \"{bucket.Name}\"", "Origin not readable", Expected, gitConfig));
                continue;
            }

            string shown = WithoutSecrets(address);
            if (!KnownBuckets.TryGetValue(bucket.Name, out string? known))
            {
                problems++;
                findings.Add(Finding.Problem($"Bucket \"{bucket.Name}\"", $"From {shown}", Expected, gitConfig));
            }
            else if (!SameRepository(address, known))
            {
                problems++;
                findings.Add(Finding.Problem($"Bucket \"{bucket.Name}\"", $"From {shown}, not Scoop's own address for it", WithoutSecrets(known), gitConfig));
            }
            else
            {
                findings.Add(Finding.Ok($"Bucket \"{bucket.Name}\"", "Scoop's own", Expected, gitConfig));
            }
        }

        if (scoop.Setting("scoop_repo") is { } repository && !SameRepository(repository, DefaultRepository))
        {
            problems++;
            findings.Add(Finding.Problem("Scoop itself", $"From {WithoutSecrets(repository)}", WithoutSecrets(DefaultRepository), scoop.ConfigPath));
        }

        if (problems > 0)
        {
            return CheckOutcome.Fail(
                problems == 1
                    ? "1 Scoop source is not one of Scoop's own."
                    : $"{problems} Scoop sources are not Scoop's own.",
                findings);
        }

        if (unread is not null)
        {
            return CheckOutcome.Error(unread, findings);
        }

        return CheckOutcome.Pass(
            findings.Count == 0 ? "Scoop has no buckets added." : "Scoop's buckets all come from Scoop's own sources.", findings);
    }

    /// <summary>Whether two repository addresses name the same repository: case, a trailing slash and ".git" do not matter.</summary>
    internal static bool SameRepository(string left, string right) =>
        Normalise(left).Equals(Normalise(right), StringComparison.OrdinalIgnoreCase);

    private static string Normalise(string address)
    {
        string text = WithoutSecrets(address).TrimEnd('/');
        return text.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? text[..^4] : text;
    }

    /// <summary>The address without any user name or token written into it ("https://token@host/..." becomes "https://host/...").</summary>
    internal static string WithoutSecrets(string address)
    {
        // Anything after "?" or "#" is not part of where the repository is, and may be a token.
        string text = address.Trim();
        int extra = text.IndexOfAny(['?', '#']);
        if (extra >= 0)
        {
            text = text[..extra];
        }

        // The user name and password end at the last "@" before the path: a password may
        // itself contain an "@".
        int scheme = text.IndexOf("://", StringComparison.Ordinal);
        int start = scheme < 0 ? 0 : scheme + 3;
        int end = text.IndexOf('/', start);
        if (end < 0)
        {
            end = text.Length;
        }

        int at = end > start ? text.LastIndexOf('@', end - 1, end - start) : -1;
        return at >= start ? text[..start] + text[(at + 1)..] : text;
    }
}
