using System.Text.Json;
using System.Text.Json.Serialization;
using SecReview.Checks;
using SecReview.Scanning;

namespace SecReview.Reporting;

/// <summary>
/// The result of a scan as written to a report file. It describes the PC's settings, so it
/// carries no computer or user name; whoever collects reports knows where each came from.
/// </summary>
public sealed record ScanReport(
    int SchemaVersion,
    string Product,
    string Version,
    DateTimeOffset GeneratedAt,
    bool Elevated,
    ReportCounts Counts,
    IReadOnlyList<ReportCheck> Checks)
{
    /// <summary>Raised when the shape of the report changes in a way readers must know about.</summary>
    public const int CurrentSchemaVersion = 1;
}

public sealed record ReportCounts(int Pass, int Fail, int NeedsAdmin, int NotApplicable, int Error);

public sealed record ReportCheck(
    string Id,
    string Category,
    string Severity,
    string Status,
    string Title,
    string Summary,
    bool ManagedByPolicy,
    DateTimeOffset CheckedAt,
    IReadOnlyList<ReportFinding> Findings);

public sealed record ReportFinding(string Item, string Found, string Expected, string Status, string? Source);

public static class ReportBuilder
{
    /// <summary>Builds the report for a finished scan.</summary>
    public static ScanReport Build(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);

        var reported = new List<ReportCheck>(scan.Checks.Count);
        foreach (ScannedCheck check in scan.Checks)
        {
            CheckOutcome outcome = check.Result.Outcome;
            reported.Add(new ReportCheck(
                Id: check.Definition.Id,
                Category: check.Definition.Category.ToString(),
                Severity: check.Definition.Severity.ToString(),
                Status: outcome.Status.ToString(),
                Title: check.Title,
                Summary: outcome.Summary,
                ManagedByPolicy: outcome.ManagedByPolicy,
                CheckedAt: check.Result.CheckedAt,
                Findings: [.. outcome.Findings.Select(f =>
                    new ReportFinding(f.Item, f.Found, f.Expected, f.Status.ToString(), f.Source))]));
        }

        return new ScanReport(
            ScanReport.CurrentSchemaVersion,
            ProductInfo.Name,
            ProductInfo.Version,
            scan.FinishedAt,
            scan.Elevated,
            new ReportCounts(
                scan.Count(CheckStatus.Pass),
                scan.Count(CheckStatus.Fail),
                scan.Count(CheckStatus.NeedsAdmin),
                scan.Count(CheckStatus.NotApplicable),
                scan.Count(CheckStatus.Error)),
            reported);
    }
}

public static class ReportFile
{
    /// <summary>The report as indented JSON.</summary>
    public static string ToJson(ScanReport report) =>
        JsonSerializer.Serialize(report, ReportJson.Default.ScanReport);

    /// <summary>
    /// Writes the report, replacing any existing file only once the new one is complete, so a
    /// reader never sees half a report.
    /// </summary>
    public static void Write(ScanReport report, string path)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string fullPath = Path.GetFullPath(path);
        string temporary = fullPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllText(temporary, ToJson(report));
            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ScanReport))]
internal sealed partial class ReportJson : JsonSerializerContext;
