using System.Globalization;
using SecReview.Scanning;
using SecReview.Settings;

namespace SecReview.Tray;

/// <summary>What the notification-area icon shows.</summary>
public enum TrayState
{
    /// <summary>
    /// Nothing is known yet, or something could not be checked. The zero value on purpose:
    /// an icon nobody worked out is grey, never green.
    /// </summary>
    Unknown = 0,

    /// <summary>Everything checked is in order.</summary>
    Fine,

    /// <summary>Something needs attention.</summary>
    NeedsAttention,

    /// <summary>The checks are paused.</summary>
    Snoozed,
}

/// <summary>
/// The rules of the notification-area icon, apart from Windows: when the checks run again,
/// what the icon and its tooltip say, and when a notification is due. A notification is shown
/// only when a check starts failing, never for one that was already failing or that is seen
/// for the first time.
/// </summary>
public static class TrayLogic
{
    /// <summary>After starting, the icon waits this long before its first run, so signing in is not slowed down.</summary>
    public static readonly TimeSpan StartDelay = TimeSpan.FromMinutes(1);

    /// <summary>A pause longer than this was not set by SecReview's menu (an hour or a day) and is not believed.</summary>
    public static readonly TimeSpan LongestSnooze = TimeSpan.FromDays(1) + TimeSpan.FromMinutes(5);

    /// <summary>Windows cuts a tooltip off after this many characters.</summary>
    public const int MaximumTooltipLength = 127;

    private const int MaximumNotificationTitle = 63;
    private const int MaximumNotificationText = 200;

    /// <summary>Whether the checks and notifications are paused right now.</summary>
    public static bool IsSnoozed(AppSettings settings, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return settings.SnoozedUntil is { } until && until > now && until - now <= LongestSnooze;
    }

    /// <summary>
    /// When the checks are due to run again by themselves: one interval after the last scan
    /// finished, not before the icon has been up for <see cref="StartDelay"/>, and not while
    /// paused. A last scan dated after now counts as "just now".
    /// </summary>
    /// <param name="lastFinished">When the last scan finished; null when there is none.</param>
    /// <param name="settings">The interval and the pause.</param>
    /// <param name="now">The current time.</param>
    /// <param name="started">When the icon was started.</param>
    public static DateTimeOffset NextRun(DateTimeOffset? lastFinished, AppSettings settings, DateTimeOffset now, DateTimeOffset started)
    {
        ArgumentNullException.ThrowIfNull(settings);

        DateTimeOffset earliest = started + StartDelay;
        DateTimeOffset due = lastFinished is { } last
            ? (last > now ? now : last) + TimeSpan.FromHours(AppSettings.RecheckChoices.Contains(settings.RecheckHours) ? settings.RecheckHours : AppSettings.DefaultRecheckHours)
            : earliest;
        if (due < earliest)
        {
            due = earliest;
        }

        return IsSnoozed(settings, now) && settings.SnoozedUntil!.Value > due ? settings.SnoozedUntil.Value : due;
    }

    /// <summary>
    /// Whether the last scan is too old to vouch for the PC as it is now: older than two
    /// intervals, and than a day. The checks then did not run when they were due (they keep
    /// failing to run, or the PC was off), and "in order" would be a guess.
    /// </summary>
    public static bool IsStale(ScanResult scan, AppSettings settings, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(scan);
        ArgumentNullException.ThrowIfNull(settings);
        int hours = AppSettings.RecheckChoices.Contains(settings.RecheckHours) ? settings.RecheckHours : AppSettings.DefaultRecheckHours;
        return now - scan.FinishedAt > TimeSpan.FromHours(Math.Max(2 * hours, 24));
    }

    /// <summary>What the icon shows for the last scan.</summary>
    /// <param name="scan">The last scan; null when there is none.</param>
    /// <param name="ignored">The checks the user ignores.</param>
    /// <param name="snoozed">Whether the checks are paused.</param>
    /// <param name="stale">Whether the scan is too old to call the PC in order (<see cref="IsStale"/>).</param>
    public static TrayState State(ScanResult? scan, IReadOnlySet<string>? ignored, bool snoozed, bool stale = false)
    {
        if (snoozed)
        {
            return TrayState.Snoozed;
        }

        if (scan is null || scan.Checks.Count == 0)
        {
            return TrayState.Unknown;
        }

        if (scan.Checks.Any(check => ScanPresentation.StandingOf(check, ignored) == Standing.NeedsAttention))
        {
            return TrayState.NeedsAttention;
        }

        // Green is a claim about now. What needed attention when last checked is still worth saying.
        return stale || scan.Checks.Any(check => ScanPresentation.StandingOf(check, ignored) == Standing.CouldNotCheck) ? TrayState.Unknown : TrayState.Fine;
    }

    /// <summary>The icon's tooltip: the headline and how old it is, within what Windows shows.</summary>
    public static string Tooltip(ScanResult? scan, IReadOnlySet<string>? ignored, AppSettings settings, DateTimeOffset now, bool scanning)
    {
        ArgumentNullException.ThrowIfNull(settings);

        string text;
        if (scan is null || scan.Checks.Count == 0)
        {
            text = scanning ? "SecReview: checking this PC…" : "SecReview: not checked yet";
        }
        else
        {
            text = $"SecReview: {ScanPresentation.Headline(scan, ignored)}, checked {ScanPresentation.Age(scan.FinishedAt, now)}";
            if (scanning)
            {
                text += ", checking again…";
            }
        }

        if (!scanning && IsSnoozed(settings, now))
        {
            text += string.Create(CultureInfo.InvariantCulture, $" (paused until {settings.SnoozedUntil!.Value.ToLocalTime():HH:mm})");
        }

        return text.Length <= MaximumTooltipLength ? text : text[..(MaximumTooltipLength - 1)] + "…";
    }

    /// <summary>
    /// The checks that started failing between two scans: failing now and counted (not
    /// ignored, not merely worth knowing), and known not to be failing before. A check that
    /// had no earlier answer is not "new": the first scan of a PC is a baseline, not news.
    /// </summary>
    public static IReadOnlyList<ScannedCheck> NewFailures(ScanResult? before, ScanResult after, IReadOnlySet<string>? ignored)
    {
        ArgumentNullException.ThrowIfNull(after);
        if (before is null)
        {
            return [];
        }

        Dictionary<string, ScannedCheck> earlier = before.Checks.ToDictionary(check => check.Definition.Id, StringComparer.Ordinal);
        return
        [
            .. after.Checks.Where(check =>
                ScanPresentation.StandingOf(check, ignored) == Standing.NeedsAttention &&
                earlier.TryGetValue(check.Definition.Id, out ScannedCheck? was) &&
                ScanPresentation.StandingOf(was) != Standing.NeedsAttention),
        ];
    }

    /// <summary>
    /// The notification for checks that started failing, with the check a click opens when
    /// there is one; null when there are none.
    /// </summary>
    public static TrayNotification? Notification(IReadOnlyList<ScannedCheck> newFailures)
    {
        ArgumentNullException.ThrowIfNull(newFailures);
        return newFailures.Count switch
        {
            0 => null,
            1 => new TrayNotification(
                Cut(newFailures[0].Title, MaximumNotificationTitle),
                Cut(newFailures[0].Shown.Outcome.Summary, MaximumNotificationText),
                newFailures[0].Definition.Id),
            _ => new TrayNotification(
                string.Create(CultureInfo.InvariantCulture, $"{newFailures.Count} checks started failing"),
                Cut(string.Join("; ", newFailures.Take(3).Select(check => check.Title)) + (newFailures.Count > 3 ? "; and more" : string.Empty), MaximumNotificationText),
                CheckId: null),
        };
    }

    /// <summary>
    /// A new scan as it is kept: its answers, each beside the answer of the other kind
    /// (with or without administrator rights) that came earlier (see
    /// <see cref="ScanPresentation.Newer"/>).
    /// </summary>
    public static ScanResult Merge(ScanResult? before, ScanResult after, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(after);
        if (before is null)
        {
            return after;
        }

        Dictionary<string, ScannedCheck> earlier = before.Checks.ToDictionary(check => check.Definition.Id, StringComparer.Ordinal);
        return after with { Checks = [.. after.Checks.Select(check => ScanPresentation.Newer(earlier.GetValueOrDefault(check.Definition.Id), check, now))] };
    }

    private static string Cut(string text, int maximum) => text.Length <= maximum ? text : text[..(maximum - 1)] + "…";
}
