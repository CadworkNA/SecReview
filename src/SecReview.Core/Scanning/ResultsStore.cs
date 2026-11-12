using System.Text.Json;
using System.Text.Json.Serialization;
using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Diagnostics;

namespace SecReview.Scanning;

/// <summary>
/// Keeps the last scan in SecReview's data folder, so the window can show it at once while a
/// new scan runs. The results describe this PC's settings and stay on it; user and computer
/// names were already removed from them by the runner. A file that is missing, damaged, from
/// another version of SecReview or that names something this version does not know is not
/// used: the next scan replaces it.
/// </summary>
public sealed class ResultsStore
{
    /// <summary>The file's name in the data folder.</summary>
    public const string FileName = "results.json";

    /// <summary>The shape of the file. A file of another shape is not used.</summary>
    public const int SchemaVersion = 1;

    private const int MaximumBytes = 8 * 1024 * 1024;
    private const int MaximumTextLength = 4000;
    private const int MaximumFindings = 1000;

    private readonly string _path;

    public ResultsStore(string folder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        _path = Path.Combine(folder, FileName);
    }

    /// <summary>Saves a finished scan. False when it could not be written; the scan itself is not affected.</summary>
    public bool Save(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);

        var stored = new StoredScan(
            SchemaVersion,
            ProductInfo.Version,
            scan.FinishedAt,
            scan.Elevated,
            [.. scan.Checks.Select(check => new StoredCheck(
                check.Definition.Id,
                check.Result.Outcome.Status.ToString(),
                Fit(check.Result.Outcome.Summary),
                check.Result.Outcome.ManagedByPolicy,
                check.Result.CheckedAt,
                check.Result.Elevated,
                (long)check.Result.Duration.TotalMilliseconds,
                [.. check.Result.Outcome.Findings.Take(MaximumFindings).Select(f =>
                    new StoredFinding(Fit(f.Item), Fit(f.Found), Fit(f.Expected), f.Status.ToString(), f.Source is null ? null : Fit(f.Source)))]))]);
        try
        {
            AtomicFile.Write(_path, JsonSerializer.SerializeToUtf8Bytes(stored, ResultsJson.Default.StoredScan));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// The last scan, with the wording of this version's catalogue; null when there is none
    /// that can be used.
    /// </summary>
    public ScanResult? Load(IReadOnlyList<ICheck> checks, CheckTexts texts)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(texts);

        StoredScan? stored;
        try
        {
            var file = new FileInfo(_path);
            if (!file.Exists || file.Length > MaximumBytes)
            {
                return null;
            }

            stored = JsonSerializer.Deserialize(File.ReadAllBytes(_path), ResultsJson.Default.StoredScan);
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }

        if (stored is not { SchemaVersion: SchemaVersion, Checks: not null } || stored.AppVersion != ProductInfo.Version)
        {
            return null;
        }

        // A scan that finished before SecReview existed, or after now, was not saved by a
        // working clock: its age would be shown wrongly.
        if (stored.FinishedAt.Year < 2025 || stored.FinishedAt > DateTimeOffset.UtcNow.AddDays(1))
        {
            return null;
        }

        var byId = new Dictionary<string, StoredCheck>(StringComparer.Ordinal);
        foreach (StoredCheck? check in stored.Checks)
        {
            if (check?.Id is null || !byId.TryAdd(check.Id, check))
            {
                return null;
            }
        }

        var scanned = new List<ScannedCheck>();
        foreach (ICheck check in checks)
        {
            string id = check.Definition.Id;
            if (!byId.TryGetValue(id, out StoredCheck? saved))
            {
                continue;
            }

            if (Outcome(saved) is not { } outcome)
            {
                return null;
            }

            scanned.Add(new ScannedCheck(
                check.Definition,
                texts[id],
                new CheckResult(id, outcome, saved.CheckedAt, saved.Elevated, TimeSpan.FromMilliseconds(Math.Clamp(saved.DurationMs, 0, 3_600_000)))));
        }

        return scanned.Count == 0 ? null : new ScanResult(scanned, stored.FinishedAt, stored.Elevated);
    }

    /// <summary>A saved outcome; null when it holds something this version does not know or that cannot be SecReview's.</summary>
    private static CheckOutcome? Outcome(StoredCheck saved)
    {
        if (!Known<CheckStatus>(saved.Status, out CheckStatus status) || !IsText(saved.Summary) || string.IsNullOrWhiteSpace(saved.Summary) ||
            saved.Findings is null || saved.Findings.Count > MaximumFindings)
        {
            return null;
        }

        var findings = new List<Finding>(saved.Findings.Count);
        foreach (StoredFinding? finding in saved.Findings)
        {
            if (finding is null || !Known<FindingStatus>(finding.Status, out FindingStatus findingStatus) ||
                !IsText(finding.Item) || !IsText(finding.Found) || !IsText(finding.Expected) || (finding.Source is not null && !IsText(finding.Source)))
            {
                return null;
            }

            findings.Add(new Finding(finding.Item!, finding.Found!, finding.Expected!, findingStatus, finding.Source));
        }

        return new CheckOutcome(status, saved.Summary!, findings, saved.ManagedByPolicy);
    }

    /// <summary>A value by its exact name. Numbers, signs and padding, which the framework would accept, are not names.</summary>
    private static bool Known<T>(string? name, out T value)
        where T : struct, Enum
    {
        value = default;
        return name is not null && Array.IndexOf(Enum.GetNames<T>(), name) >= 0 && Enum.TryParse(name, ignoreCase: false, out value);
    }

    /// <summary>A text within what <see cref="Load"/> accepts, so that one very long answer cannot make the whole file unusable.</summary>
    private static string Fit(string text) => text.Length <= MaximumTextLength ? text : text[..MaximumTextLength];

    private static bool IsText(string? text) => text is { Length: <= MaximumTextLength };

    internal sealed record StoredScan(int SchemaVersion, string? AppVersion, DateTimeOffset FinishedAt, bool Elevated, IReadOnlyList<StoredCheck?>? Checks);

    internal sealed record StoredCheck(
        string? Id,
        string? Status,
        string? Summary,
        bool ManagedByPolicy,
        DateTimeOffset CheckedAt,
        bool Elevated,
        long DurationMs,
        IReadOnlyList<StoredFinding?>? Findings);

    internal sealed record StoredFinding(string? Item, string? Found, string? Expected, string? Status, string? Source);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, ReadCommentHandling = JsonCommentHandling.Disallow)]
[JsonSerializable(typeof(ResultsStore.StoredScan))]
internal sealed partial class ResultsJson : JsonSerializerContext;
