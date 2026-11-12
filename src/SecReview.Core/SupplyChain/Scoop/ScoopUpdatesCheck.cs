using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Scoop;

/// <summary>
/// Apps installed with Scoop should be at the version their bucket offers, and Scoop should
/// have looked for updates recently: "latest" only means the latest the buckets on this PC
/// know. An app that is held back on purpose (<c>scoop hold</c>) is listed, not failed. Scoop
/// has no automatic updates, so this is the only place an outdated app shows up.
/// </summary>
public sealed class ScoopUpdatesCheck : ICheck
{
    public const string Id = "sc.scoop.updates";

    /// <summary>After this long without a refresh, what the buckets call "latest" is not trusted to be.</summary>
    public static readonly TimeSpan MaximumBucketAge = TimeSpan.FromDays(14);

    private const string Expected = "The version in its bucket";

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

        ProbeResult<IReadOnlyList<ScoopApp>> apps = ScoopLocator.Apps(files, scoop.Root);
        if (!apps.IsOk)
        {
            return ProbeOutcomes.FromFailure(apps, "the apps installed with Scoop");
        }

        var findings = new List<Finding>();
        var behind = new List<string>();
        int compared = 0;
        foreach (ScoopApp app in apps.Value!)
        {
            if (app.Version is not { } installed || app.Bucket is not { } bucket ||
                !ScoopAppsCheck.SafeName(bucket) || !ScoopAppsCheck.SafeName(app.Name))
            {
                continue;
            }

            if (BucketVersion(files, scoop, bucket, app.Name) is not { } offered)
            {
                continue;
            }

            compared++;
            if (string.Equals(installed, offered, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            bool held = app.Install is { ValueKind: JsonValueKind.Object } install &&
                install.TryGetProperty("hold", out JsonElement hold) && hold.ValueKind == JsonValueKind.True;
            if (held)
            {
                findings.Add(Finding.Note(app.Name, $"{installed}, held back on purpose; the bucket has {offered}", app.Folder));
            }
            else
            {
                behind.Add(app.Name);
                findings.Add(Finding.Problem(app.Name, installed, offered, app.Folder));
            }
        }

        // How fresh the buckets are: the last time Scoop fetched any of them.
        DateTimeOffset? refreshed = LastRefresh(files, scoop);
        TimeSpan? age = refreshed is { } when ? context.Clock.GetUtcNow() - when : null;
        bool stale = age is { } known && known > MaximumBucketAge;
        if (age is { } bucketAge)
        {
            string ago = bucketAge < TimeSpan.FromDays(1) ? "Today" : $"{(int)bucketAge.TotalDays} days ago";
            findings.Add(stale
                ? Finding.Problem("Scoop last looked for updates", ago, "Within 14 days")
                : Finding.Ok("Scoop last looked for updates", ago, "Within 14 days"));
        }
        else
        {
            findings.Add(Finding.Note("Scoop last looked for updates", "Not recorded"));
        }

        if (behind.Count > 0)
        {
            return CheckOutcome.Fail(
                behind.Count <= 3
                    ? $"{Wording.JoinWithAnd(behind)} {(behind.Count == 1 ? "has" : "have")} an update waiting in Scoop."
                    : $"{behind.Count} apps have an update waiting in Scoop.",
                findings);
        }

        if (stale)
        {
            return CheckOutcome.Fail(
                $"Scoop has not looked for updates for {(int)age!.Value.TotalDays} days, so it cannot know what is outdated.", findings);
        }

        if (compared == 0)
        {
            return CheckOutcome.Pass("No apps from a bucket are installed with Scoop.", findings);
        }

        findings.Insert(0, Finding.Ok("Apps", $"{compared} at the version their bucket offers", Expected));
        return CheckOutcome.Pass(
            age is null
                ? "Scoop apps match their buckets; when Scoop last looked for updates is not recorded."
                : "Scoop apps are at the versions their buckets offer.",
            findings);
    }

    /// <summary>The version of an app in its bucket's manifest: <c>bucket\app.json</c> if the bucket has that folder, else beside the bucket's root.</summary>
    private static string? BucketVersion(IFileProbe files, ScoopInstall scoop, string bucket, string app)
    {
        string root = $@"{scoop.Root}\buckets\{bucket}";
        foreach (string path in (string[])[$@"{root}\bucket\{app}.json", $@"{root}\{app}.json"])
        {
            if (SettingsFiles.LoadJson(files, path, out _) is { ValueKind: JsonValueKind.Object } manifest &&
                manifest.TryGetProperty("version", out JsonElement version) && version.ValueKind == JsonValueKind.String)
            {
                return version.GetString();
            }
        }

        return null;
    }

    /// <summary>The newest "last fetched" time among the buckets; null if none records one.</summary>
    private static DateTimeOffset? LastRefresh(IFileProbe files, ScoopInstall scoop)
    {
        ProbeResult<IReadOnlyList<FileEntry>> buckets = files.List($@"{scoop.Root}\buckets");
        if (!buckets.IsOk)
        {
            return null;
        }

        DateTimeOffset? newest = null;
        foreach (FileEntry bucket in buckets.Value!.Where(b => b.IsDirectory))
        {
            ProbeResult<IReadOnlyList<FileEntry>> git = files.List($@"{scoop.Root}\buckets\{bucket.Name}\.git");
            FileEntry? fetched = git.IsOk
                ? git.Value!.FirstOrDefault(e => e.Name.Equals("FETCH_HEAD", StringComparison.OrdinalIgnoreCase))
                : null;
            if (fetched is not null && (newest is null || fetched.LastWrite > newest))
            {
                newest = fetched.LastWrite;
            }
        }

        return newest;
    }
}
