using SecReview.Checks;

namespace SecReview.SupplyChain.NuGet;

/// <summary>
/// NuGet must get packages over HTTPS with certificate checks on, and when it has more than
/// one source on the network, each package must be tied to a source (package source mapping).
/// Without that, any source may supply any package, and a public package can take the place
/// of a private one of the same name. Folders on this PC are not counted as sources to confuse.
/// </summary>
public sealed class NuGetSourcesCheck : ICheck
{
    public const string Id = "sc.nuget.sources";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (NuGetLocator.Locate(context.Probes, out NuGetInstall? nuget) is { } failed)
        {
            return failed;
        }

        if (nuget is null)
        {
            return CheckOutcome.NotApplicable("NuGet is not installed.");
        }

        var problems = new List<Finding>();
        foreach (NuGetSource source in nuget.Sources)
        {
            if (source.IsPlainHttp)
            {
                problems.Add(Finding.Problem($"Source \"{source.Name}\"", "Plain HTTP", "HTTPS", source.Source));
            }

            if (source.SkipsTlsChecks)
            {
                problems.Add(Finding.Problem($"TLS certificate checks for source \"{source.Name}\"", "Off", "On", source.Source));
            }
        }

        int remote = nuget.Sources.Count(s => s.IsRemote);
        if (remote > 1 && !nuget.HasSourceMapping)
        {
            problems.Add(Finding.Problem(
                "Package source mapping", $"Not set, with {remote} sources: any of them can supply any package", "Each package tied to a source"));
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"NuGet: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"NuGet has {problems.Count} settings that weaken where it gets packages from.",
                problems);
        }

        // Nothing found. If a settings file could not be read, "nothing wrong" is not known.
        if (nuget.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        if (remote == 0)
        {
            return CheckOutcome.Pass("NuGet has no source on the network.", Finding.Ok("Sources on the network", "None", "HTTPS"));
        }

        return CheckOutcome.Pass(
            remote == 1 ? "NuGet gets packages from one source, over HTTPS." : $"NuGet gets packages from {remote} sources over HTTPS, each package tied to one.",
            Finding.Ok("Sources on the network", remote == 1 ? "1, over HTTPS" : $"{remote}, over HTTPS", "HTTPS"),
            Finding.Ok("Package source mapping", nuget.HasSourceMapping ? "Set" : "Not needed with one source", "Each package tied to a source"));
    }
}

/// <summary>
/// NuGet must not keep a source's password as plain text (<c>ClearTextPassword</c>). NuGet can
/// store it encrypted for the user instead. Only the source's name and the file are reported.
/// </summary>
public sealed class NuGetCredentialsCheck : ICheck
{
    public const string Id = "sc.nuget.credentials";

    private const string Expected = "Encrypted, or not stored";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (NuGetLocator.Locate(context.Probes, out NuGetInstall? nuget) is { } failed)
        {
            return failed;
        }

        if (nuget is null)
        {
            return CheckOutcome.NotApplicable("NuGet is not installed.");
        }

        if (nuget.PlainPasswords.Count > 0)
        {
            return CheckOutcome.Fail(
                nuget.PlainPasswords.Count == 1
                    ? "NuGet keeps a source's password as plain text."
                    : $"NuGet keeps the passwords of {nuget.PlainPasswords.Count} sources as plain text.",
                [.. nuget.PlainPasswords.Select(p => Finding.Problem($"Password for source \"{p.SourceName}\"", "Stored as plain text", Expected, p.Where))]);
        }

        return nuget.Problem is { } problem
            ? CheckOutcome.Error(problem)
            : CheckOutcome.Pass("NuGet keeps no passwords as plain text.", Finding.Ok("Source passwords", "None stored as plain text", Expected));
    }
}

/// <summary>
/// NuGet should wait a week before it picks a newly published version by itself
/// (<c>minPublishAgeHours</c> on each source, from .NET SDK 11.0.100). The wait covers versions
/// NuGet chooses (a range, a floating version, an update); a version a project names exactly
/// is still restored at once, which is said in the result.
/// </summary>
public sealed class NuGetCooldownCheck : ICheck
{
    public const string Id = "sc.nuget.cooldown";

    private const long WeekInHours = 168;
    private const string Expected = "168 hours or more";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Low, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (NuGetLocator.Locate(context.Probes, out NuGetInstall? nuget) is { } failed)
        {
            return failed;
        }

        if (nuget is null)
        {
            return CheckOutcome.NotApplicable("NuGet is not installed.");
        }

        if (nuget.SdkVersion is { } old && old < NuGetLocator.CooldownFrom)
        {
            return CheckOutcome.Fail(
                $".NET SDK {old} cannot wait before picking new package versions; update the SDK.",
                Finding.Problem(".NET SDK version", old.ToString(), $"{NuGetLocator.CooldownFrom} or later"));
        }

        if (nuget.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        var findings = new List<Finding>();
        int tooShort = 0;
        foreach (NuGetSource source in nuget.Sources.Where(s => s.IsRemote))
        {
            if (source.MinimumAgeHours is { } hours && hours >= WeekInHours)
            {
                findings.Add(Finding.Ok($"Wait for source \"{source.Name}\"", Hours(hours), Expected, source.Source));
            }
            else
            {
                tooShort++;
                findings.Add(Finding.Problem(
                    $"Wait for source \"{source.Name}\"", source.MinimumAgeHours is { } few ? Hours(few) : "Not set", Expected, source.Source));
            }
        }

        if (findings.Count == 0)
        {
            return CheckOutcome.Pass("NuGet has no source on the network.", Finding.Ok("Sources on the network", "None", "None"));
        }

        findings.Add(nuget.SdkVersion is { } version
            ? Finding.Ok(".NET SDK version", version.ToString(), $"{NuGetLocator.CooldownFrom} or later")
            : Finding.Note(".NET SDK version", $"Not found; the wait is honoured from .NET SDK {NuGetLocator.CooldownFrom}"));

        if (tooShort > 0)
        {
            return CheckOutcome.Fail("NuGet picks new package versions the moment they are published.", findings);
        }

        findings.Add(Finding.Note("What the wait covers", "Versions NuGet picks by itself; a version named exactly is restored at once"));
        return CheckOutcome.Pass("NuGet waits a week before it picks a new package version by itself.", findings);
    }

    private static string Hours(long hours) => hours == 1 ? "1 hour" : $"{hours} hours";
}
