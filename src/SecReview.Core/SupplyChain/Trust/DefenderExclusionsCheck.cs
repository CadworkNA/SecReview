using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Trust;

/// <summary>
/// What Microsoft Defender is told to skip, it does not scan. An exclusion that covers a
/// whole drive, a user's folders (downloads, source code, package caches all live there) or
/// a kind of file that can run is where a bad package goes unseen; these fail. Other
/// exclusions are listed. Windows shows the list to administrators only, so without an
/// elevated scan the answer is "needs administrator", never "none".
/// </summary>
public sealed class DefenderExclusionsCheck : ICheck
{
    public const string Id = "sc.defender.exclusions";

    internal const string LocalKey = @"SOFTWARE\Microsoft\Windows Defender\Exclusions";
    internal const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions";

    private const int Most = 10;

    /// <summary>File types that run, or are run by something, when opened.</summary>
    private static readonly string[] RunnableTypes =
        ["exe", "dll", "sys", "scr", "com", "msi", "bat", "cmd", "ps1", "psm1", "vbs", "js", "jse", "wsf", "hta", "jar", "py", "lnk"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.Yes, CheckScope.Machine);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Windows refuses the list to anyone else; an empty answer without rights would read as "none".
        if (!context.IsElevated)
        {
            return CheckOutcome.NeedsAdmin("Microsoft Defender shows its exclusions to administrators only.");
        }

        var problems = new List<Finding>();
        var notes = new List<Finding>();
        bool byPolicy = false;

        foreach ((string key, bool policy) in new[] { (LocalKey, false), (PolicyKey, true) })
        {
            foreach (string kind in (string[])["Paths", "Extensions", "Processes"])
            {
                ProbeResult<IReadOnlyList<string>> names = context.Probes.Registry.GetValueNames(RegistryRoot.LocalMachine, $@"{key}\{kind}");
                if (names.Status == ProbeStatus.NotFound)
                {
                    continue;
                }

                if (!names.IsOk)
                {
                    return ProbeOutcomes.FromFailure(names, "Microsoft Defender's exclusions");
                }

                string source = $@"HKLM\{key}\{kind}";
                foreach (string name in names.Value!.Where(n => n.Trim().Length > 0))
                {
                    (string Item, string? Why) judged = kind switch
                    {
                        "Paths" => ($"Excluded folder or file: {name}", WhyAPathIsTooWide(name)),
                        "Extensions" => ($"Excluded file type: {name.TrimStart('.', '*')}", RunnableTypes.Contains(name.TrimStart('.', '*').ToLowerInvariant()) ? "Files of this type can run" : null),
                        _ => ($"Excluded program: {name}", null),
                    };

                    if (judged.Why is { } why)
                    {
                        byPolicy |= policy;
                        problems.Add(Finding.Problem(judged.Item, why, "Not excluded", source));
                    }
                    else
                    {
                        notes.Add(Finding.Note(judged.Item, policy ? "Not scanned (set by your organisation)" : "Not scanned", source));
                    }
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? "Microsoft Defender skips a place where downloaded code lands."
                    : $"Microsoft Defender skips {problems.Count} places or file types where downloaded code lands.",
                [.. problems, .. notes.Take(Most)]) with { ManagedByPolicy = byPolicy };
        }

        if (notes.Count == 0)
        {
            return CheckOutcome.Pass("Microsoft Defender has no exclusions.", Finding.Ok("Exclusions", "None", "None, or narrow ones"));
        }

        List<Finding> shown = [.. notes.Take(Most)];
        if (notes.Count > Most)
        {
            shown.Add(Finding.Note("More exclusions", $"{notes.Count - Most} more"));
        }

        return CheckOutcome.Pass(
            notes.Count == 1
                ? "Microsoft Defender has 1 exclusion; it does not cover a drive, user folders or files that run."
                : $"Microsoft Defender has {notes.Count} exclusions; none covers a drive, user folders or files that run.",
            shown);
    }

    /// <summary>Why an excluded path is too wide; null when it is not.</summary>
    internal static string? WhyAPathIsTooWide(string excluded)
    {
        string path = excluded.Trim().Replace('/', '\\').TrimEnd('\\', '*');

        // "C:" or "C:\": a whole drive. A lone wildcard or variable-only path is no narrower.
        if (path.Length <= 2 || (path.Length == 3 && path[1] == ':'))
        {
            return "A whole drive is not scanned";
        }

        string lower = path.ToLowerInvariant();
        if (lower.Contains(@"\users", StringComparison.Ordinal) || lower.StartsWith("%userprofile%", StringComparison.Ordinal) ||
            lower.StartsWith("%appdata%", StringComparison.Ordinal) || lower.StartsWith("%localappdata%", StringComparison.Ordinal))
        {
            return "Folders a user's programs can write to are not scanned";
        }

        if (lower.EndsWith(@"\temp", StringComparison.Ordinal) || lower.Contains(@"\temp\", StringComparison.Ordinal) ||
            lower.StartsWith("%temp%", StringComparison.Ordinal) || lower.StartsWith("%tmp%", StringComparison.Ordinal))
        {
            return "A temporary folder is not scanned";
        }

        return null;
    }
}
