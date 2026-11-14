using System.Globalization;
using System.Text;
using SecReview.Checks;
using SecReview.Settings;

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

    /// <summary>Left out of every count by the user, with a reason. Still checked and still shown.</summary>
    Ignored,
}

/// <summary>Which checks the window shows.</summary>
public enum ScanFilter
{
    All,

    /// <summary>What needs fixing: the same checks the headline counts.</summary>
    NeedsAttention,

    NeedsAdmin,

    Passed,

    Ignored,
}

/// <summary>A group of checks under one heading.</summary>
/// <param name="Title">The heading, for example "Needs attention" or "Firewall and sharing".</param>
/// <param name="Detail">A few words beside it, for example "7 of 8 pass"; may be empty.</param>
/// <param name="Checks">The checks, in the order they are shown.</param>
public sealed record ScanSection(string Title, string Detail, IReadOnlyList<ScannedCheck> Checks);

/// <summary>How a scan is put in front of the user: the order of the checks, the groups and the headline.</summary>
public static class ScanPresentation
{
    private static readonly IReadOnlySet<string> NothingIgnored = new HashSet<string>();

    /// <summary>Where one check stands.</summary>
    public static Standing StandingOf(ScannedCheck check, IReadOnlySet<string>? ignored = null)
    {
        ArgumentNullException.ThrowIfNull(check);

        if (ignored is not null && ignored.Contains(check.Definition.Id))
        {
            return Standing.Ignored;
        }

        return check.Shown.Outcome.Status switch
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
    /// checks that do not apply, then the ignored ones. Within a group the catalogue order is
    /// kept, so rows do not jump around between scans.
    /// </summary>
    public static IReadOnlyList<ScannedCheck> InDisplayOrder(ScanResult scan, IReadOnlySet<string>? ignored = null)
    {
        ArgumentNullException.ThrowIfNull(scan);

        return [.. scan.Checks
            .Select((check, index) => (check, index, standing: StandingOf(check, ignored)))
            .OrderBy(x => Group(x.standing))
            .ThenByDescending(x => x.standing == Standing.NeedsAttention ? (int)x.check.Definition.Severity : 0)
            .ThenBy(x => x.index)
            .Select(x => x.check)];
    }

    /// <summary>
    /// The checks a filter shows, grouped. With no filter: what needs attention (most severe
    /// first), what could not be checked, then everything else by category, then the ignored
    /// checks. Groups without checks are left out.
    /// </summary>
    public static IReadOnlyList<ScanSection> Sections(ScanResult scan, IReadOnlySet<string>? ignored = null, ScanFilter filter = ScanFilter.All)
    {
        ArgumentNullException.ThrowIfNull(scan);
        ignored ??= NothingIgnored;

        List<(ScannedCheck Check, Standing Standing)> all = [.. scan.Checks.Select(check => (check, StandingOf(check, ignored)))];
        var sections = new List<ScanSection>();

        void Add(string title, string detail, IEnumerable<ScannedCheck> checks)
        {
            ScannedCheck[] shown = [.. checks];
            if (shown.Length > 0)
            {
                sections.Add(new ScanSection(title, detail, shown));
            }
        }

        if (filter is ScanFilter.All or ScanFilter.NeedsAttention)
        {
            Add(
                "Needs attention",
                string.Empty,
                all.Where(x => x.Standing == Standing.NeedsAttention).OrderByDescending(x => (int)x.Check.Definition.Severity).Select(x => x.Check));
        }

        if (filter is ScanFilter.All)
        {
            Add("Could not be checked", string.Empty, all.Where(x => x.Standing == Standing.CouldNotCheck).Select(x => x.Check));
        }

        if (filter is ScanFilter.All or ScanFilter.NeedsAdmin or ScanFilter.Passed)
        {
            foreach (CheckCategory category in Enum.GetValues<CheckCategory>())
            {
                List<(ScannedCheck Check, Standing Standing)> inCategory = [.. all.Where(x => x.Check.Definition.Category == category)];
                int counted = inCategory.Count(x => x.Standing is not (Standing.DoesNotApply or Standing.WorthKnowing or Standing.Ignored));
                int passed = inCategory.Count(x => x.Standing == Standing.Passed);
                Add(
                    CategoryName(category),
                    $"{passed} of {counted} pass",
                    inCategory
                        .Where(x => filter switch
                        {
                            ScanFilter.NeedsAdmin => x.Standing == Standing.NeedsAdmin,
                            ScanFilter.Passed => x.Standing == Standing.Passed,
                            _ => x.Standing is Standing.NeedsAdmin or Standing.WorthKnowing or Standing.Passed or Standing.DoesNotApply,
                        })
                        .OrderBy(x => Group(x.Standing))
                        .Select(x => x.Check));
            }
        }

        if (filter is ScanFilter.All or ScanFilter.Ignored)
        {
            Add("Ignored", "not counted", all.Where(x => x.Standing == Standing.Ignored).Select(x => x.Check));
        }

        return sections;
    }

    /// <summary>How many checks a filter shows.</summary>
    public static int CountFor(ScanResult scan, IReadOnlySet<string>? ignored, ScanFilter filter)
    {
        ArgumentNullException.ThrowIfNull(scan);
        return filter switch
        {
            ScanFilter.All => scan.Checks.Count,
            ScanFilter.NeedsAttention => Count(scan, ignored, Standing.NeedsAttention),
            ScanFilter.NeedsAdmin => Count(scan, ignored, Standing.NeedsAdmin),
            ScanFilter.Passed => Count(scan, ignored, Standing.Passed),
            _ => Count(scan, ignored, Standing.Ignored),
        };
    }

    /// <summary>One sentence that says how the PC is doing.</summary>
    public static string Headline(ScanResult scan, IReadOnlySet<string>? ignored = null)
    {
        ArgumentNullException.ThrowIfNull(scan);

        int failing = Count(scan, ignored, Standing.NeedsAttention);
        int errors = Count(scan, ignored, Standing.CouldNotCheck);

        if (failing > 0)
        {
            return failing == 1 ? "1 thing needs attention" : $"{failing} things need attention";
        }

        if (errors > 0)
        {
            return errors == 1 ? "1 check could not be completed" : $"{errors} checks could not be completed";
        }

        if (Count(scan, ignored, Standing.NeedsAdmin) > 0)
        {
            return "No problems found so far";
        }

        return scan.Checks.Count == 0 ? "No checks were run" : "Everything checked is in order";
    }

    /// <summary>The counts behind the headline, for the line under it.</summary>
    public static string Counts(ScanResult scan, IReadOnlySet<string>? ignored = null)
    {
        ArgumentNullException.ThrowIfNull(scan);

        // Something only worth knowing is neither a pass nor a failure, so it is left out of
        // "N of M pass" and named on its own. So is what the user chose to ignore.
        int worthKnowing = Count(scan, ignored, Standing.WorthKnowing);
        int ignoredCount = Count(scan, ignored, Standing.Ignored);
        int counted = scan.Checks.Count - Count(scan, ignored, Standing.DoesNotApply) - worthKnowing - ignoredCount;
        string text = $"{Count(scan, ignored, Standing.Passed)} of {counted} checks pass";

        int errors = Count(scan, ignored, Standing.CouldNotCheck);
        if (errors > 0)
        {
            text += $", {errors} could not be checked";
        }

        int needAdmin = Count(scan, ignored, Standing.NeedsAdmin);
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

        if (ignoredCount > 0)
        {
            text += $", {ignoredCount} ignored";
        }

        return text;
    }

    /// <summary>
    /// The headline and the line under it while the very first results come in. Nothing is said
    /// about how the PC is doing until every check has answered: the first three passes are
    /// not "everything is in order".
    /// </summary>
    public static (string Headline, string Detail) Progress(int answered, int total) =>
        ("Checking this PC…", string.Create(CultureInfo.InvariantCulture, $"{answered} of {total} checks answered"));

    /// <summary>
    /// Whether a row starts open when it is (re)drawn. A check that needs attention starts
    /// open, so the reason is visible without a click; everything else starts closed. A row
    /// that was on screen keeps the state the user left it in, unless it has just been
    /// ignored or brought back: then it starts over.
    /// </summary>
    /// <param name="shown">Whether the row was on screen before, and how.</param>
    /// <param name="isIgnored">Whether the check is ignored now.</param>
    /// <param name="standing">Where the check stands now, leaving aside that it may be ignored.</param>
    public static bool StartsExpanded((bool WasIgnored, bool WasExpanded)? shown, bool isIgnored, Standing standing)
    {
        if (shown is { } before && before.WasIgnored == isIgnored)
        {
            return before.WasExpanded;
        }

        return !isIgnored && standing == Standing.NeedsAttention;
    }

    /// <summary>An answer kept beside a newer one of the other kind (with or without administrator rights) is kept this long.</summary>
    public static readonly TimeSpan AdministratorAnswerLifetime = TimeSpan.FromDays(30);

    /// <summary>
    /// What to show for a check when a new answer arrives. For a check that administrator
    /// rights tell more about, the two kinds of answer are kept side by side: the new one
    /// replaces only the earlier answer of its own kind (with or without administrator
    /// rights), and the other stays, with its own date, until it is older than
    /// <see cref="AdministratorAnswerLifetime"/>. So an ordinary scan after the administrator
    /// checks changes nothing that it did not read itself, and the other way round.
    /// <see cref="ScannedCheck.Shown"/> says which of the two decides where the check stands.
    /// </summary>
    /// <remarks>
    /// An earlier answer dated after now is not kept: its age cannot be trusted. A check that
    /// administrator rights add nothing to keeps only the new answer.
    /// </remarks>
    /// <param name="shown">What is on screen; null when there is none.</param>
    /// <param name="arrived">The answer that just came in.</param>
    /// <param name="now">The current time.</param>
    public static ScannedCheck Newer(ScannedCheck? shown, ScannedCheck arrived, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(arrived);

        if (shown is null || arrived.Definition.NeedsAdmin == AdminNeed.No)
        {
            return arrived;
        }

        bool elevated = arrived.Result.Elevated;
        CheckResult? ordinary = elevated ? Kept(OrdinaryOf(shown), now) : arrived.Result;
        CheckResult? administrator = elevated ? arrived.Result : Kept(AdministratorOf(shown), now);
        return Assemble(arrived, ordinary, administrator);
    }

    /// <summary>
    /// Takes into what one process knows the answers another process saved since: for each
    /// check and each kind of answer (with or without administrator rights), the newer one by
    /// the time the check ran. Answers known and not in <paramref name="saved"/> stay. Returns
    /// whether anything changed.
    /// </summary>
    public static bool TakeNewer(IDictionary<string, ScannedCheck> known, ScanResult saved, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(known);
        ArgumentNullException.ThrowIfNull(saved);

        bool changed = false;
        foreach (ScannedCheck check in saved.Checks)
        {
            string id = check.Definition.Id;
            if (!known.TryGetValue(id, out ScannedCheck? have))
            {
                known[id] = check;
                changed = true;
                continue;
            }

            if (check.Definition.NeedsAdmin == AdminNeed.No)
            {
                if (check.Result.CheckedAt > have.Result.CheckedAt)
                {
                    known[id] = check;
                    changed = true;
                }

                continue;
            }

            CheckResult? ordinary = Later(OrdinaryOf(have), OrdinaryOf(check));
            CheckResult? administrator = Later(AdministratorOf(have), AdministratorOf(check));
            if (!ReferenceEquals(ordinary, OrdinaryOf(have)) || !ReferenceEquals(administrator, AdministratorOf(have)))
            {
                // The newest answer always stays; the other only while it may be kept beside it.
                CheckResult? newest = Later(ordinary, administrator);
                known[id] = Assemble(
                    check,
                    ReferenceEquals(ordinary, newest) ? ordinary : Kept(ordinary, now),
                    ReferenceEquals(administrator, newest) ? administrator : Kept(administrator, now));
                changed = true;
            }
        }

        return changed;
    }

    /// <summary>The answer read without administrator rights; null when there is only one read with them.</summary>
    private static CheckResult? OrdinaryOf(ScannedCheck check) => check.Result.Elevated ? null : check.Result;

    /// <summary>The answer read with administrator rights; null when there is none.</summary>
    private static CheckResult? AdministratorOf(ScannedCheck check) => check.Administrator ?? (check.Result.Elevated ? check.Result : null);

    /// <summary>An earlier answer, if it may still be shown beside a newer one: not too old, and not dated after now.</summary>
    private static CheckResult? Kept(CheckResult? earlier, DateTimeOffset now)
    {
        if (earlier is null)
        {
            return null;
        }

        TimeSpan age = now - earlier.CheckedAt;
        return age >= -ClockTolerance && age <= AdministratorAnswerLifetime ? earlier : null;
    }

    /// <summary>The later of two answers by when they were read; the first when they tie, so that reading the same answers again changes nothing.</summary>
    private static CheckResult? Later(CheckResult? first, CheckResult? second) =>
        first is null ? second : second is null ? first : second.CheckedAt > first.CheckedAt ? second : first;

    /// <summary>One check with its answers in their places.</summary>
    private static ScannedCheck Assemble(ScannedCheck check, CheckResult? ordinary, CheckResult? administrator) =>
        ordinary is null
            ? new ScannedCheck(check.Definition, check.Text, administrator ?? check.Result)
            : new ScannedCheck(check.Definition, check.Text, ordinary) { Administrator = administrator };

    /// <summary>How far a saved time may lie ahead of the clock before it is not believed.</summary>
    private static readonly TimeSpan ClockTolerance = TimeSpan.FromMinutes(5);

    /// <summary>How long ago a scan finished, in words: "just now", "5 minutes ago", "1 day ago", "3 days ago".</summary>
    public static string Age(DateTimeOffset finishedAt, DateTimeOffset now)
    {
        TimeSpan age = now - finishedAt;
        return age.TotalMinutes switch
        {
            < 1 => "just now",
            < 2 => "1 minute ago",
            < 60 => string.Create(CultureInfo.InvariantCulture, $"{(int)age.TotalMinutes} minutes ago"),
            < 120 => "1 hour ago",
            < 24 * 60 => string.Create(CultureInfo.InvariantCulture, $"{(int)age.TotalHours} hours ago"),
            < 48 * 60 => "1 day ago",
            _ => string.Create(CultureInfo.InvariantCulture, $"{(int)age.TotalDays} days ago"),
        };
    }

    /// <summary>A category's name as shown.</summary>
    public static string CategoryName(CheckCategory category) => category switch
    {
        CheckCategory.Access => "Access",
        CheckCategory.Updates => "Updates",
        CheckCategory.FirewallAndSharing => "Firewall and sharing",
        CheckCategory.SystemIntegrity => "System integrity",
        CheckCategory.Hardening => "Hardening",
        CheckCategory.SupplyChain => "Developer supply chain",
        _ => "Other",
    };

    /// <summary>Where a check stands, in words.</summary>
    public static string StandingName(Standing standing) => standing switch
    {
        Standing.Passed => "Passed",
        Standing.NeedsAttention => "Needs attention",
        Standing.WorthKnowing => "Worth knowing",
        Standing.NeedsAdmin => "Needs administrator rights",
        Standing.DoesNotApply => "Does not apply to this PC",
        Standing.Ignored => "Ignored",
        _ => "Could not be checked",
    };

    /// <summary>
    /// Everything about one check as plain text, for "Copy details": what it found, where, why
    /// it matters and how to fix it. Nothing in it that is not on screen.
    /// </summary>
    public static string Details(ScannedCheck check, IgnoredCheck? ignored = null)
    {
        ArgumentNullException.ThrowIfNull(check);

        CheckOutcome outcome = check.Shown.Outcome;
        Standing standing = StandingOf(check);
        var text = new StringBuilder();
        text.AppendLine(check.Title);
        text.Append(StandingName(standing));
        if (standing is Standing.NeedsAttention or Standing.WorthKnowing)
        {
            text.Append(" (").Append(check.Definition.Severity.ToString().ToLowerInvariant()).Append(')');
        }

        text.AppendLine(CultureInfo.InvariantCulture, $" · {CategoryName(check.Definition.Category)} · {check.Definition.Id}");
        text.AppendLine(outcome.Summary);
        if (ignored is not null)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"Ignored: {(ignored.Reason.Length > 0 ? ignored.Reason : "no reason given")}");
        }

        if (outcome.ManagedByPolicy)
        {
            text.AppendLine("This setting is managed by your organisation.");
        }

        if (check.Administrator is { } administrator)
        {
            foreach (CheckResult answer in new[] { check.Result, administrator })
            {
                text.AppendLine();
                text.AppendLine(AnswerHeading(answer));
                text.AppendLine(answer.Outcome.Summary);
                AppendFindings(text, answer.Outcome.Findings);
            }
        }
        else if (outcome.Findings.Count > 0)
        {
            text.AppendLine();
            AppendFindings(text, outcome.Findings);
        }

        text.AppendLine();
        text.AppendLine(CultureInfo.InvariantCulture, $"Why it matters: {check.Text.Why}");
        if (standing is Standing.NeedsAttention or Standing.WorthKnowing && outcome.ManagedByPolicy)
        {
            text.AppendLine("How to fix: this setting is set by a policy, so it cannot be changed on this PC. Ask your IT department.");
        }
        else if (standing is Standing.NeedsAttention or Standing.WorthKnowing)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"How to fix (about {check.Text.TimeToFix}):");
            for (int i = 0; i < check.Text.Fix.Count; i++)
            {
                text.AppendLine(CultureInfo.InvariantCulture, $"{i + 1}. {check.Text.Fix[i]}");
            }
        }

        return text.ToString().TrimEnd();
    }

    /// <summary>
    /// The heading of one of a check's two answers: "Without administrator rights · checked
    /// 13 Nov 2026, 13:56", or "With administrator rights · …".
    /// </summary>
    public static string AnswerHeading(CheckResult answer)
    {
        ArgumentNullException.ThrowIfNull(answer);
        return string.Create(
            CultureInfo.CurrentCulture,
            $"{(answer.Elevated ? "With" : "Without")} administrator rights · checked {answer.CheckedAt.ToLocalTime():d MMM yyyy, HH:mm}");
    }

    private static void AppendFindings(StringBuilder text, IReadOnlyList<Finding> findings)
    {
        foreach (Finding finding in findings)
        {
            text.Append(finding.Status switch { FindingStatus.Ok => "[ok] ", FindingStatus.Problem => "[!!] ", _ => "[i]  " });
            text.Append(finding.Item).Append(": ").Append(finding.Found);
            if (finding.Status != FindingStatus.Note)
            {
                text.Append(" (expected: ").Append(finding.Expected).Append(')');
            }

            if (!string.IsNullOrEmpty(finding.Source))
            {
                text.Append(" — ").Append(finding.Source);
            }

            text.AppendLine();
        }
    }

    private static int Count(ScanResult scan, IReadOnlySet<string>? ignored, Standing standing) =>
        scan.Checks.Count(c => StandingOf(c, ignored) == standing);

    private static int Group(Standing standing) => standing switch
    {
        Standing.NeedsAttention => 0,
        Standing.CouldNotCheck => 1,
        Standing.NeedsAdmin => 2,
        Standing.WorthKnowing => 3,
        Standing.Passed => 4,
        Standing.DoesNotApply => 5,
        _ => 6,
    };
}
