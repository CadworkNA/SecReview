using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Scoop;

/// <summary>
/// Every app installed with Scoop should have been downloaded over HTTPS, verified against a
/// hash, and come from a bucket. Scoop installs an app whose manifest has no hash anyway, and
/// skips the check for "nightly" versions, so these are looked for in each app's own record of
/// how it was installed. Apps installed for all users are included. Apps whose manifest runs
/// scripts at install time are counted, for information: many legitimate apps do.
/// </summary>
public sealed class ScoopAppsCheck : ICheck
{
    public const string Id = "sc.scoop.apps";

    private const string Expected = "Verified download from a bucket";

    private static readonly string[] ScriptProperties = ["pre_install", "post_install", "pre_uninstall", "post_uninstall", "psmodule"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

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

        var apps = new List<ScoopApp>();
        foreach (string root in (string[])[scoop.Root, scoop.GlobalRoot])
        {
            ProbeResult<IReadOnlyList<ScoopApp>> found = ScoopLocator.Apps(files, root);
            if (!found.IsOk)
            {
                return ProbeOutcomes.FromFailure(found, "the apps installed with Scoop");
            }

            apps.AddRange(found.Value!);
        }

        if (apps.Count == 0)
        {
            return CheckOutcome.Pass("No apps are installed with Scoop.", Finding.Ok("Apps", "None", Expected));
        }

        var findings = new List<Finding>();
        int withProblems = 0;
        int unread = 0;
        int withScripts = 0;
        foreach (ScoopApp app in apps)
        {
            if (app.Manifest is not { ValueKind: JsonValueKind.Object } manifest || app.Install is not { ValueKind: JsonValueKind.Object } install)
            {
                unread++;
                findings.Add(Finding.Problem(app.Name, "Its install record could not be read", Expected, app.Folder));
                continue;
            }

            List<string> problems = Problems(manifest, install, IsDeprecated(files, scoop, app));
            if (problems.Count > 0)
            {
                withProblems++;
                findings.Add(Finding.Problem(app.Name, Wording.JoinWithAnd(problems), Expected, app.Folder));
            }

            if (RunsScripts(manifest))
            {
                withScripts++;
            }
        }

        if (withScripts > 0)
        {
            findings.Add(Finding.Note("Apps whose manifest runs scripts at install time", $"{withScripts} of {apps.Count}"));
        }

        if (withProblems > 0)
        {
            return CheckOutcome.Fail(
                withProblems == 1
                    ? "1 Scoop app has a weakness in how it was downloaded or where it comes from."
                    : $"{withProblems} Scoop apps have a weakness in how they were downloaded or where they come from.",
                findings);
        }

        if (unread > 0)
        {
            return CheckOutcome.Error(
                unread == 1 ? "The install record of 1 Scoop app could not be read." : $"The install records of {unread} Scoop apps could not be read.",
                findings);
        }

        findings.Insert(0, Finding.Ok("Apps", $"{apps.Count}, all verified and from a bucket", Expected));
        return CheckOutcome.Pass(
            apps.Count == 1 ? "The app installed with Scoop was verified and comes from a bucket." : $"All {apps.Count} apps installed with Scoop were verified and come from a bucket.",
            findings);
    }

    /// <summary>What is wrong with how an app was installed, in words; empty when nothing is.</summary>
    private static List<string> Problems(JsonElement manifest, JsonElement install, bool deprecated)
    {
        var problems = new List<string>(3);
        string? version = Text(manifest, "version");
        bool nightly = string.Equals(version, "nightly", StringComparison.OrdinalIgnoreCase);

        // The download address and hash are at the top, or per processor type under "architecture".
        JsonElement source = manifest;
        if (manifest.TryGetProperty("architecture", out JsonElement architectures) && architectures.ValueKind == JsonValueKind.Object &&
            Text(install, "architecture") is { } architecture &&
            architectures.TryGetProperty(architecture, out JsonElement forThisPc) && forThisPc.ValueKind == JsonValueKind.Object &&
            forThisPc.TryGetProperty("url", out _))
        {
            source = forThisPc;
        }

        if (nightly)
        {
            problems.Add("a nightly build, which Scoop does not verify");
        }
        else if (!HasValue(source, "hash") && HasValue(source, "url"))
        {
            problems.Add("no hash, so the download was not verified");
        }

        if (Texts(source, "url").Any(u => u.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
        {
            problems.Add("downloaded over plain HTTP");
        }

        if (Text(install, "bucket") is null)
        {
            problems.Add("not from a bucket");
        }

        if (deprecated)
        {
            problems.Add("marked as deprecated in its bucket");
        }

        return problems;
    }

    private static bool RunsScripts(JsonElement manifest) =>
        ScriptProperties.Any(name => HasValue(manifest, name)) ||
        (manifest.TryGetProperty("installer", out JsonElement installer) && installer.ValueKind == JsonValueKind.Object && HasValue(installer, "script")) ||
        (manifest.TryGetProperty("uninstaller", out JsonElement uninstaller) && uninstaller.ValueKind == JsonValueKind.Object && HasValue(uninstaller, "script"));

    /// <summary>Whether the app's bucket has moved its manifest to the "deprecated" folder.</summary>
    private static bool IsDeprecated(IFileProbe files, ScoopInstall scoop, ScoopApp app) =>
        app.Bucket is { } bucket && SafeName(bucket) && SafeName(app.Name) &&
        SettingsFiles.Exists(files, $@"{scoop.Root}\buckets\{bucket}\deprecated", app.Name + ".json");

    /// <summary>A name that is one folder or file name and nothing else, so it cannot lead out of Scoop's folder.</summary>
    internal static bool SafeName(string name) =>
        name.Length is > 0 and < 200 && name is not ("." or "..") && name.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) < 0;

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>A property that is one text or a list of texts, as texts.</summary>
    private static IEnumerable<string> Texts(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value))
        {
            yield break;
        }

        if (value.ValueKind == JsonValueKind.String)
        {
            yield return value.GetString()!;
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    yield return item.GetString()!;
                }
            }
        }
    }

    /// <summary>Whether a property is there with something in it: a non-empty text, list or object.</summary>
    private static bool HasValue(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind switch
        {
            JsonValueKind.String => value.GetString()!.Length > 0,
            JsonValueKind.Array => value.GetArrayLength() > 0,
            JsonValueKind.Object => value.EnumerateObject().Any(),
            _ => false,
        };
}
