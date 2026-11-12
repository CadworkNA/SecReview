using SecReview.Checks;

namespace SecReview.Scanning;

/// <summary>Where a check stands for the user. Every screen and count uses this one answer.</summary>
public enum Standing
{
    /// <summary>
    /// Could not be completed. This is the zero value on purpose: a standing nobody worked out
    /// reads as "could not check", never as fine.
    /// </summary>
    CouldNotCheck = 0,

    /// <summary>Failing, and it counts: something to fix.</summary>
    NeedsAttention,

    /// <summary>Waiting for administrator rights.</summary>
    NeedsAdmin,

    /// <summary>Not as recommended, but only worth knowing (<see cref="Severity.Info"/>): never counted as failing.</summary>
    WorthKnowing,

    Passed,

    DoesNotApply,
}

/// <summary>How a scan is put in front of the user: the order of the checks and the headline.</summary>
public static class ScanPresentation
{
    /// <summary>Where one check stands.</summary>
    public static Standing StandingOf(ScannedCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);

        return check.Result.Outcome.Status switch
        {
            CheckStatus.Fail when check.Definition.Severity == Severity.Info => Standing.WorthKnowing,
            CheckStatus.Fail => Standing.NeedsAttention,
            CheckStatus.NeedsAdmin => Standing.NeedsAdmin,
            CheckStatus.Pass => Standing.Passed,
            CheckStatus.NotApplicable => Standing.DoesNotApply,
            _ => Standing.CouldNotCheck,
        };
    }

    /// <summary>
    /// Things to fix first (most severe first), then checks that could not be completed, then
    /// those waiting for administrator rights, then things only worth knowing, then passes, then
    /// checks that do not apply. Within a group the catalogue order is kept, so rows do not jump
    /// around between scans.
    /// </summary>
    public static IReadOnlyList<ScannedCheck> InDisplayOrder(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);

        return [.. scan.Checks
            .Select((check, index) => (check, index, standing: StandingOf(check)))
            .OrderBy(x => Group(x.standing))
            .ThenByDescending(x => x.standing == Standing.NeedsAttention ? (int)x.check.Definition.Severity : 0)
            .ThenBy(x => x.index)
            .Select(x => x.check)];
    }

    /// <summary>One sentence that says how the PC is doing.</summary>
    public static string Headline(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);

        int failing = Count(scan, Standing.NeedsAttention);
        int errors = Count(scan, Standing.CouldNotCheck);

        if (failing > 0)
        {
            return failing == 1 ? "1 thing needs attention" : $"{failing} things need attention";
        }

        if (errors > 0)
        {
            return errors == 1 ? "1 check could not be completed" : $"{errors} checks could not be completed";
        }

        if (Count(scan, Standing.NeedsAdmin) > 0)
        {
            return "No problems found so far";
        }

        return scan.Checks.Count == 0 ? "No checks were run" : "Everything checked is in order";
    }

    /// <summary>The counts behind the headline, for the line under it.</summary>
    public static string Counts(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);

        // Something only worth knowing is neither a pass nor a failure, so it is left out of
        // "N of M pass" and named on its own.
        int worthKnowing = Count(scan, Standing.WorthKnowing);
        int counted = scan.Checks.Count - Count(scan, Standing.DoesNotApply) - worthKnowing;
        string text = $"{Count(scan, Standing.Passed)} of {counted} checks pass";

        int needAdmin = Count(scan, Standing.NeedsAdmin);
        if (needAdmin > 0)
        {
            text += needAdmin == 1
                ? ", 1 needs administrator rights"
                : $", {needAdmin} need administrator rights";
        }

        if (worthKnowing > 0)
        {
            text += worthKnowing == 1 ? ", 1 thing worth knowing" : $", {worthKnowing} things worth knowing";
        }

        return text;
    }

    private static int Count(ScanResult scan, Standing standing) => scan.Checks.Count(c => StandingOf(c) == standing);

    private static int Group(Standing standing) => standing switch
    {
        Standing.NeedsAttention => 0,
        Standing.CouldNotCheck => 1,
        Standing.NeedsAdmin => 2,
        Standing.WorthKnowing => 3,
        Standing.Passed => 4,
        _ => 5,
    };
}
