using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Scanning;
using SecReview.Settings;
using SecReview.Tray;

namespace SecReview.Tests.Tray;

[TestClass]
public sealed class TrayLogicTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 12, 14, 0, 0, TimeSpan.Zero);
    private static readonly CheckTexts Texts = CheckTexts.Load();

    private static ScannedCheck Check(string id, CheckOutcome outcome, Severity severity = Severity.Medium, AdminNeed needsAdmin = AdminNeed.No, bool elevated = false, DateTimeOffset? checkedAt = null) => new(
        new CheckDefinition(id, CheckCategory.Access, severity, needsAdmin),
        Texts[FirewallCheck.Id],
        new CheckResult(id, outcome, checkedAt ?? Now, elevated, TimeSpan.Zero));

    private static ScanResult Scan(DateTimeOffset finished, params ScannedCheck[] checks) => new(checks, finished, Elevated: false);

    private static readonly AppSettings Defaults = new();

    [TestMethod]
    public void TheChecksRunAgain_OneIntervalAfterTheLastScan()
    {
        DateTimeOffset started = Now.AddHours(-10);

        Assert.AreEqual(Now.AddHours(3), TrayLogic.NextRun(Now.AddHours(-1), Defaults, Now, started), "four hours by default");
        Assert.AreEqual(Now, TrayLogic.NextRun(Now.AddHours(-1), Defaults with { RecheckHours = 1 }, Now, started));
        Assert.AreEqual(Now.AddHours(23), TrayLogic.NextRun(Now.AddHours(-1), Defaults with { RecheckHours = 24 }, Now, started));
        Assert.AreEqual(Now.AddHours(3), TrayLogic.NextRun(Now.AddHours(-1), Defaults with { RecheckHours = 0 }, Now, started), "an interval that is not a choice means the default");
        Assert.AreEqual(Now.AddHours(-2), TrayLogic.NextRun(Now.AddHours(-6), Defaults, Now, started), "overdue: it is due at once");
    }

    [TestMethod]
    public void AfterSigningIn_TheFirstRunWaitsAMinute()
    {
        DateTimeOffset started = Now;

        Assert.AreEqual(Now.AddMinutes(1), TrayLogic.NextRun(null, Defaults, Now, started), "nothing checked yet");
        Assert.AreEqual(Now.AddMinutes(1), TrayLogic.NextRun(Now.AddDays(-3), Defaults, Now, started), "long overdue, but not in the first minute");
        Assert.AreEqual(Now.AddHours(3), TrayLogic.NextRun(Now.AddHours(-1), Defaults, Now, started));
    }

    [TestMethod]
    public void ALastScanDatedAfterNow_CountsAsJustNow()
    {
        Assert.AreEqual(Now.AddHours(4), TrayLogic.NextRun(Now.AddDays(30), Defaults, Now, Now.AddHours(-1)), "a clock that was set back must not stop the checks for a month");
    }

    [TestMethod]
    public void WhilePaused_NothingRuns_AndAPauseNobodySetIsNotBelieved()
    {
        DateTimeOffset started = Now.AddHours(-10);
        AppSettings hour = Defaults with { SnoozedUntil = Now.AddMinutes(40) };
        AppSettings day = Defaults with { SnoozedUntil = Now.AddHours(23) };

        Assert.IsTrue(TrayLogic.IsSnoozed(hour, Now));
        Assert.AreEqual(Now.AddMinutes(40), TrayLogic.NextRun(Now.AddHours(-6), hour, Now, started), "overdue, but paused");
        Assert.AreEqual(Now.AddHours(3), TrayLogic.NextRun(Now.AddHours(-1), hour, Now, started), "the pause ends before the next run anyway");
        Assert.AreEqual(Now.AddHours(23), TrayLogic.NextRun(Now.AddHours(-1), day, Now, started));

        Assert.IsFalse(TrayLogic.IsSnoozed(Defaults, Now));
        Assert.IsFalse(TrayLogic.IsSnoozed(Defaults with { SnoozedUntil = Now.AddMinutes(-1) }, Now), "over");
        Assert.IsFalse(TrayLogic.IsSnoozed(Defaults with { SnoozedUntil = Now.AddYears(5) }, Now), "the menu pauses for an hour or a day, never for years");
        Assert.AreEqual(Now.AddHours(-2), TrayLogic.NextRun(Now.AddHours(-6), Defaults with { SnoozedUntil = Now.AddYears(5) }, Now, started));
    }

    [TestMethod]
    public void TheIcon_IsGreenOnlyWhenEverythingCheckedIsInOrder()
    {
        ScannedCheck pass = Check("a", CheckOutcome.Pass("x"));
        ScannedCheck fail = Check("b", CheckOutcome.Fail("x"));
        ScannedCheck error = Check("c", CheckOutcome.Error("x"));
        ScannedCheck asks = Check("d", CheckOutcome.NeedsAdmin("x"));
        ScannedCheck info = Check("e", CheckOutcome.Fail("x"), Severity.Info);

        Assert.AreEqual(TrayState.Unknown, TrayLogic.State(null, null, snoozed: false));
        Assert.AreEqual(TrayState.Unknown, TrayLogic.State(Scan(Now), null, snoozed: false));
        Assert.AreEqual(TrayState.Fine, TrayLogic.State(Scan(Now, pass, asks, info), null, snoozed: false));
        Assert.AreEqual(TrayState.NeedsAttention, TrayLogic.State(Scan(Now, pass, fail, error), null, snoozed: false));
        Assert.AreEqual(TrayState.Unknown, TrayLogic.State(Scan(Now, pass, error), null, snoozed: false), "could not check is not green");
        Assert.AreEqual(TrayState.Fine, TrayLogic.State(Scan(Now, pass, fail), new HashSet<string> { "b" }, snoozed: false), "an ignored failure does not count");
        Assert.AreEqual(TrayState.Snoozed, TrayLogic.State(Scan(Now, pass, fail), null, snoozed: true));
        Assert.AreEqual(0, (int)TrayState.Unknown);
    }

    [TestMethod]
    public void AScanTooOldToVouchForNow_IsNotGreen_ButStillSaysWhatNeededAttention()
    {
        ScanResult fine = Scan(Now.AddHours(-30), Check("a", CheckOutcome.Pass("x")));
        ScanResult failing = Scan(Now.AddHours(-30), Check("a", CheckOutcome.Fail("x")));

        Assert.IsFalse(TrayLogic.IsStale(Scan(Now.AddHours(-23), Check("a", CheckOutcome.Pass("x"))), Defaults, Now), "a night off is not stale");
        Assert.IsTrue(TrayLogic.IsStale(fine, Defaults, Now));
        Assert.IsFalse(TrayLogic.IsStale(fine, Defaults with { RecheckHours = 24 }, Now), "two intervals when checking once a day");
        Assert.IsTrue(TrayLogic.IsStale(Scan(Now.AddHours(-49), Check("a", CheckOutcome.Pass("x"))), Defaults with { RecheckHours = 24 }, Now));
        Assert.IsFalse(TrayLogic.IsStale(Scan(Now.AddDays(3), Check("a", CheckOutcome.Pass("x"))), Defaults, Now), "dated after now: the schedule deals with it");

        Assert.AreEqual(TrayState.Unknown, TrayLogic.State(fine, null, snoozed: false, stale: true));
        Assert.AreEqual(TrayState.NeedsAttention, TrayLogic.State(failing, null, snoozed: false, stale: true));
        Assert.AreEqual(TrayState.Snoozed, TrayLogic.State(fine, null, snoozed: true, stale: true));
    }

    [TestMethod]
    public void TheTooltip_SaysHowThePcIsDoing_AndFitsWhatWindowsShows()
    {
        ScanResult scan = Scan(Now.AddMinutes(-5), Check("a", CheckOutcome.Pass("x")), Check("b", CheckOutcome.Fail("x")));

        Assert.AreEqual("SecReview: not checked yet", TrayLogic.Tooltip(null, null, Defaults, Now, scanning: false));
        Assert.AreEqual("SecReview: checking this PC…", TrayLogic.Tooltip(null, null, Defaults, Now, scanning: true));
        Assert.AreEqual("SecReview: 1 thing needs attention, checked 5 minutes ago", TrayLogic.Tooltip(scan, null, Defaults, Now, scanning: false));
        Assert.AreEqual("SecReview: 1 thing needs attention, checked 5 minutes ago, checking again…", TrayLogic.Tooltip(scan, null, Defaults, Now, scanning: true));
        Assert.AreEqual(
            "SecReview: Everything checked is in order, checked 5 minutes ago", TrayLogic.Tooltip(scan, new HashSet<string> { "b" }, Defaults, Now, scanning: false));

        string paused = TrayLogic.Tooltip(scan, null, Defaults with { SnoozedUntil = Now.AddMinutes(30) }, Now, scanning: false);
        StringAssert.StartsWith(paused, "SecReview: 1 thing needs attention, checked 5 minutes ago (paused until ");

        ScanResult many = Scan(Now, [.. Enumerable.Range(0, 2000).Select(i => Check($"c{i}", CheckOutcome.Fail("x")))]);
        Assert.IsTrue(TrayLogic.Tooltip(many, null, Defaults with { SnoozedUntil = Now.AddMinutes(30) }, Now, scanning: false).Length <= TrayLogic.MaximumTooltipLength);
    }

    [TestMethod]
    public void OnlyAChangeToFailing_IsNews()
    {
        ScanResult before = Scan(
            Now.AddHours(-4),
            Check("was-fine", CheckOutcome.Pass("x")),
            Check("was-failing", CheckOutcome.Fail("x")),
            Check("was-unknown", CheckOutcome.Error("x")),
            Check("was-asking", CheckOutcome.NeedsAdmin("x")),
            Check("stays-fine", CheckOutcome.Pass("x")),
            Check("ignored", CheckOutcome.Pass("x")),
            Check("only-information", CheckOutcome.Pass("x"), Severity.Info));
        ScanResult after = Scan(
            Now,
            Check("was-fine", CheckOutcome.Fail("x")),
            Check("was-failing", CheckOutcome.Fail("x")),
            Check("was-unknown", CheckOutcome.Fail("x")),
            Check("was-asking", CheckOutcome.Fail("x")),
            Check("stays-fine", CheckOutcome.Pass("x")),
            Check("ignored", CheckOutcome.Fail("x")),
            Check("only-information", CheckOutcome.Fail("x"), Severity.Info),
            Check("never-seen-before", CheckOutcome.Fail("x")));

        string[] news = [.. TrayLogic.NewFailures(before, after, new HashSet<string> { "ignored" }).Select(check => check.Definition.Id)];

        CollectionAssert.AreEqual(new[] { "was-fine", "was-unknown", "was-asking" }, news);
    }

    [TestMethod]
    public void TheFirstScanOfAPc_IsABaseline_NotNews()
    {
        ScanResult first = Scan(Now, Check("a", CheckOutcome.Fail("x")), Check("b", CheckOutcome.Fail("x")));

        Assert.AreEqual(0, TrayLogic.NewFailures(null, first, null).Count);
        Assert.IsNull(TrayLogic.Notification([]));
    }

    [TestMethod]
    public void ANotification_NamesTheCheck_OrCountsThem()
    {
        ScannedCheck one = Check("a", CheckOutcome.Fail("Windows Firewall is off for the Public network."));

        (string title, string text, string? checkId) = TrayLogic.Notification([one])!;
        Assert.AreEqual(Texts[FirewallCheck.Id].TitleFail, title);
        Assert.AreEqual("Windows Firewall is off for the Public network.", text);
        Assert.AreEqual(one.Definition.Id, checkId, "a click opens the window on it");

        (string manyTitle, string manyText, string? manyId) = TrayLogic.Notification([one, one, one, one, one])!;
        Assert.AreEqual("5 checks started failing", manyTitle);
        StringAssert.EndsWith(manyText, "; and more");
        Assert.IsNull(manyId, "several: the window as it is");

        ScannedCheck wordy = Check("a", CheckOutcome.Fail(new string('w', 900)));
        Assert.IsTrue(TrayLogic.Notification([wordy])!.Text.Length <= 200);
    }

    [TestMethod]
    public void WhatIsKept_IsTheNewScan_WithAdministratorAnswersItCouldNotRead()
    {
        ScannedCheck fromAdministrator = Check("audit", CheckOutcome.Fail("Auditing is off."), needsAdmin: AdminNeed.Yes, elevated: true, checkedAt: Now.AddDays(-2));
        ScanResult before = Scan(Now.AddHours(-4), fromAdministrator, Check("firewall", CheckOutcome.Pass("On.")));
        ScannedCheck asks = Check("audit", CheckOutcome.NeedsAdmin("This check needs administrator rights."), needsAdmin: AdminNeed.Yes);
        ScannedCheck firewallNow = Check("firewall", CheckOutcome.Fail("Off."));
        ScanResult after = Scan(Now, asks, firewallNow);

        ScanResult kept = TrayLogic.Merge(before, after, Now);

        Assert.AreSame(fromAdministrator, kept.Checks[0]);
        Assert.AreSame(firewallNow, kept.Checks[1]);
        Assert.AreEqual(Now, kept.FinishedAt);
        Assert.AreSame(after, TrayLogic.Merge(null, after, Now));

        // The kept failure was already known: it is not news again.
        Assert.AreEqual("firewall", TrayLogic.NewFailures(before, kept, null).Single().Definition.Id);
    }
}
