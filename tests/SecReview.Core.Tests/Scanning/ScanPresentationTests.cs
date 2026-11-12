using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Scanning;
using SecReview.Settings;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Scanning;

[TestClass]
public sealed class ScanPresentationTests
{
    private static readonly DateTimeOffset When = new(2026, 11, 12, 8, 30, 0, TimeSpan.Zero);
    private static readonly CheckTexts Texts = CheckTexts.Load();

    private static ScannedCheck Check(string id, CheckOutcome outcome, Severity severity = Severity.Medium, CheckCategory category = CheckCategory.Access) => new(
        new CheckDefinition(id, category, severity),
        Texts[FirewallCheck.Id],
        new CheckResult(id, outcome, When, Elevated: false, TimeSpan.Zero));

    /// <summary>One check of every standing, across three categories.</summary>
    private static ScanResult Mixed() => new(
        [
            Check("access-pass", CheckOutcome.Pass("x")),
            Check("access-low", CheckOutcome.Fail("x"), Severity.Low),
            Check("access-admin", CheckOutcome.NeedsAdmin("x")),
            Check("updates-high", CheckOutcome.Fail("x"), Severity.High, CheckCategory.Updates),
            Check("updates-error", CheckOutcome.Error("x"), category: CheckCategory.Updates),
            Check("updates-pass", CheckOutcome.Pass("x"), category: CheckCategory.Updates),
            Check("updates-na", CheckOutcome.NotApplicable("x"), category: CheckCategory.Updates),
            Check("chain-info", CheckOutcome.Fail("x"), Severity.Info, CheckCategory.SupplyChain),
            Check("chain-pass", CheckOutcome.Pass("x"), category: CheckCategory.SupplyChain),
            Check("chain-fail", CheckOutcome.Fail("x"), Severity.Medium, CheckCategory.SupplyChain),
        ],
        When,
        Elevated: false);

    private static string[] Shape(IReadOnlyList<ScanSection> sections) =>
        [.. sections.Select(s => $"{s.Title} [{s.Detail}]: {string.Join(", ", s.Checks.Select(c => c.Definition.Id))}")];

    [TestMethod]
    public void Everything_IsGrouped_FailuresFirstThenByCategory()
    {
        CollectionAssert.AreEqual(
            new[]
            {
                "Needs attention []: updates-high, chain-fail, access-low",
                "Could not be checked []: updates-error",
                "Access [1 of 3 pass]: access-admin, access-pass",
                "Updates [1 of 3 pass]: updates-pass, updates-na",
                "Developer supply chain [1 of 2 pass]: chain-info, chain-pass",
            },
            Shape(ScanPresentation.Sections(Mixed())));
    }

    [TestMethod]
    public void EachFilter_ShowsItsChecksOnly()
    {
        ScanResult scan = Mixed();

        CollectionAssert.AreEqual(
            new[] { "Needs attention []: updates-high, chain-fail, access-low" },
            Shape(ScanPresentation.Sections(scan, null, ScanFilter.NeedsAttention)));
        CollectionAssert.AreEqual(
            new[] { "Access [1 of 3 pass]: access-admin" }, Shape(ScanPresentation.Sections(scan, null, ScanFilter.NeedsAdmin)));
        CollectionAssert.AreEqual(
            new[]
            {
                "Access [1 of 3 pass]: access-pass",
                "Updates [1 of 3 pass]: updates-pass",
                "Developer supply chain [1 of 2 pass]: chain-pass",
            },
            Shape(ScanPresentation.Sections(scan, null, ScanFilter.Passed)));
        Assert.AreEqual(0, ScanPresentation.Sections(scan, null, ScanFilter.Ignored).Count);

        Assert.AreEqual(10, ScanPresentation.CountFor(scan, null, ScanFilter.All));
        Assert.AreEqual(3, ScanPresentation.CountFor(scan, null, ScanFilter.NeedsAttention), "the same number the headline says");
        Assert.AreEqual("3 things need attention", ScanPresentation.Headline(scan));
        Assert.AreEqual(1, ScanPresentation.CountFor(scan, null, ScanFilter.NeedsAdmin));
        Assert.AreEqual(3, ScanPresentation.CountFor(scan, null, ScanFilter.Passed));
        Assert.AreEqual(0, ScanPresentation.CountFor(scan, null, ScanFilter.Ignored));
    }

    [TestMethod]
    public void AnIgnoredCheck_LeavesEveryCount_AndIsStillShown()
    {
        ScanResult scan = Mixed();
        IReadOnlySet<string> ignored = new HashSet<string> { "updates-high", "access-pass", "not-a-check" };

        Assert.AreEqual(Standing.Ignored, ScanPresentation.StandingOf(scan.Checks[3], ignored));
        Assert.AreEqual(Standing.NeedsAttention, ScanPresentation.StandingOf(scan.Checks[3]));

        Assert.AreEqual("2 things need attention", ScanPresentation.Headline(scan, ignored));
        Assert.AreEqual("3 things need attention", ScanPresentation.Headline(scan));
        Assert.AreEqual("2 of 6 checks pass, 1 could not be checked, 1 needs administrator rights, 1 thing worth knowing, 2 ignored", ScanPresentation.Counts(scan, ignored));

        CollectionAssert.AreEqual(
            new[]
            {
                "Needs attention []: chain-fail, access-low",
                "Could not be checked []: updates-error",
                "Access [0 of 2 pass]: access-admin",
                "Updates [1 of 2 pass]: updates-pass, updates-na",
                "Developer supply chain [1 of 2 pass]: chain-info, chain-pass",
                "Ignored [not counted]: access-pass, updates-high",
            },
            Shape(ScanPresentation.Sections(scan, ignored)));
        CollectionAssert.AreEqual(
            new[] { "Ignored [not counted]: access-pass, updates-high" }, Shape(ScanPresentation.Sections(scan, ignored, ScanFilter.Ignored)));
        Assert.AreEqual(2, ScanPresentation.CountFor(scan, ignored, ScanFilter.Ignored));
        Assert.AreEqual(2, ScanPresentation.CountFor(scan, ignored, ScanFilter.NeedsAttention));
        Assert.AreEqual("updates-high", ScanPresentation.InDisplayOrder(scan, ignored)[^1].Definition.Id);
    }

    [TestMethod]
    public void IgnoringTheOnlyFailure_DoesNotMakeEverythingFine_WhileSomethingElseIsOpen()
    {
        var scan = new ScanResult(
            [Check("a", CheckOutcome.Fail("x"), Severity.High), Check("b", CheckOutcome.Error("x")), Check("c", CheckOutcome.Pass("x"))], When, false);

        Assert.AreEqual("1 check could not be completed", ScanPresentation.Headline(scan, new HashSet<string> { "a" }));
        Assert.AreEqual("Everything checked is in order", ScanPresentation.Headline(scan, new HashSet<string> { "a", "b" }));
    }

    [TestMethod]
    [DataRow(0, "just now")]
    [DataRow(59, "just now")]
    [DataRow(60, "1 minute ago")]
    [DataRow(5 * 60, "5 minutes ago")]
    [DataRow(59 * 60, "59 minutes ago")]
    [DataRow(60 * 60, "1 hour ago")]
    [DataRow(3 * 3600, "3 hours ago")]
    [DataRow(23 * 3600, "23 hours ago")]
    [DataRow(24 * 3600, "1 day ago")]
    [DataRow(47 * 3600, "1 day ago")]
    [DataRow(48 * 3600, "2 days ago")]
    [DataRow(3 * 86400, "3 days ago")]
    [DataRow(-600, "just now")]
    public void TheAgeOfAScan_IsSaidInWords(int secondsAgo, string expected)
    {
        Assert.AreEqual(expected, ScanPresentation.Age(When.AddSeconds(-secondsAgo), When));
    }

    [TestMethod]
    public void TheDetailsOfACheck_AreEverythingOnScreen_AsPlainText()
    {
        ScannedCheck check = new(
            new FirewallCheck().Definition,
            Texts[FirewallCheck.Id],
            new CheckResult(
                FirewallCheck.Id,
                new CheckOutcome(
                    CheckStatus.Fail,
                    "Windows Firewall is off for the Public network.",
                    [Finding.Ok("Private network", "On", "On"), Finding.Problem("Public network", "Off", "On", "made-up source"), Finding.Note("Rules", "12")],
                    ManagedByPolicy: true),
                When,
                Elevated: false,
                TimeSpan.Zero));

        string details = ScanPresentation.Details(check, new IgnoredCheck(FirewallCheck.Id, "lab PC", When));
        string[] lines = details.Split(Environment.NewLine);

        Assert.AreEqual(Texts[FirewallCheck.Id].TitleFail, lines[0]);
        Assert.AreEqual("Needs attention (high) · Firewall and sharing · firewall.enabled", lines[1]);
        Assert.AreEqual("Windows Firewall is off for the Public network.", lines[2]);
        Assert.AreEqual("Ignored: lab PC", lines[3]);
        Assert.AreEqual("This setting is managed by your organisation.", lines[4]);
        CollectionAssert.Contains(lines, "[ok] Private network: On (expected: On)");
        CollectionAssert.Contains(lines, "[!!] Public network: Off (expected: On) — made-up source");
        CollectionAssert.Contains(lines, "[i]  Rules: 12");
        CollectionAssert.Contains(lines, "Why it matters: " + Texts[FirewallCheck.Id].Why);
        CollectionAssert.Contains(lines, "How to fix: this setting is set by a policy, so it cannot be changed on this PC. Ask your IT department.");
        Assert.IsFalse(details.Contains("1. ", StringComparison.Ordinal), "steps the user cannot take are not listed, as in the window");

        string unmanaged = ScanPresentation.Details(new ScannedCheck(
            check.Definition, check.Text, new CheckResult(FirewallCheck.Id, CheckOutcome.Fail("Off."), When, false, TimeSpan.Zero)));
        CollectionAssert.Contains(unmanaged.Split(Environment.NewLine), "1. " + Texts[FirewallCheck.Id].Fix[0]);

        string passing = ScanPresentation.Details(new ScannedCheck(
            check.Definition, check.Text, new CheckResult(FirewallCheck.Id, CheckOutcome.Pass("On for every network."), When, false, TimeSpan.Zero)));
        Assert.IsFalse(passing.Contains("How to fix", StringComparison.Ordinal), "a passing check has nothing to fix");
        StringAssert.Contains(passing, "Passed · Firewall and sharing · firewall.enabled");
    }

    private static ScannedCheck Answer(CheckOutcome outcome, bool elevated, DateTimeOffset checkedAt) => new(
        new CheckDefinition("made-up.check", CheckCategory.Hardening, Severity.Medium, AdminNeed.Yes),
        Texts[FirewallCheck.Id],
        new CheckResult("made-up.check", outcome, checkedAt, elevated, TimeSpan.Zero));

    [TestMethod]
    public void AnAdministratorAnswer_IsKept_WhenAnOrdinaryScanCanOnlyAsk()
    {
        ScannedCheck fromAdministrator = Answer(CheckOutcome.Fail("Auditing is off."), elevated: true, When.AddDays(-3));
        ScannedCheck ordinary = Answer(CheckOutcome.NeedsAdmin("This check needs administrator rights."), elevated: false, When);

        Assert.AreSame(fromAdministrator, ScanPresentation.Newer(fromAdministrator, ordinary, When), "the earlier answer says more, and keeps its date");
        Assert.AreSame(ordinary, ScanPresentation.Newer(null, ordinary, When));
    }

    [TestMethod]
    public void ANewAnswer_AlwaysReplacesTheOldOne_Otherwise()
    {
        ScannedCheck asks = Answer(CheckOutcome.NeedsAdmin("x"), elevated: false, When);
        ScannedCheck ordinaryPass = Answer(CheckOutcome.Pass("x"), elevated: false, When);
        ScannedCheck oldOrdinary = Answer(CheckOutcome.Fail("x"), elevated: false, When.AddDays(-1));
        ScannedCheck oldAdministrator = Answer(CheckOutcome.Fail("x"), elevated: true, When.AddDays(-1));
        ScannedCheck newAdministrator = Answer(CheckOutcome.Pass("x"), elevated: true, When);
        ScannedCheck administratorAsked = Answer(CheckOutcome.NeedsAdmin("x"), elevated: true, When.AddDays(-1));

        // An ordinary scan that has an answer of its own shows it.
        Assert.AreSame(ordinaryPass, ScanPresentation.Newer(oldAdministrator, ordinaryPass, When));

        // An old ordinary answer is not kept alive by a scan that can only ask.
        Assert.AreSame(asks, ScanPresentation.Newer(oldOrdinary, asks, When));

        // A new run of the administrator checks replaces the old one, whatever it says.
        Assert.AreSame(newAdministrator, ScanPresentation.Newer(oldAdministrator, newAdministrator, When));

        // An "administrator" run that itself could not read (started without rights) is nothing to keep.
        Assert.AreSame(asks, ScanPresentation.Newer(administratorAsked, asks, When));
    }

    [TestMethod]
    public void WhereAnOrdinaryScanReadsSomething_ItsAnswerIsShown_NotAnOlderPass()
    {
        // Drive encryption: the administrator run said "on". Days later an ordinary scan finds
        // that Windows no longer confirms it. That is a reading, and it must not be hidden.
        ScannedCheck Partly(CheckOutcome outcome, bool elevated, DateTimeOffset checkedAt) => new(
            new CheckDefinition("made-up.partly", CheckCategory.SystemIntegrity, Severity.High, AdminNeed.ForFullDetail),
            Texts[FirewallCheck.Id],
            new CheckResult("made-up.partly", outcome, checkedAt, elevated, TimeSpan.Zero));

        ScannedCheck wasOn = Partly(CheckOutcome.Pass("On for every drive."), elevated: true, When.AddDays(-3));
        ScannedCheck notConfirmed = Partly(CheckOutcome.NeedsAdmin("Windows does not confirm that C: is fully protected."), elevated: false, When);

        Assert.AreSame(notConfirmed, ScanPresentation.Newer(wasOn, notConfirmed, When));
    }

    [TestMethod]
    public void AnAnswerDatedAfterNow_IsNotKept()
    {
        ScannedCheck asks = Answer(CheckOutcome.NeedsAdmin("x"), elevated: false, When);
        ScannedCheck fromTheFuture = Answer(CheckOutcome.Pass("x"), elevated: true, When.AddYears(70));
        ScannedCheck aMinuteAhead = Answer(CheckOutcome.Pass("x"), elevated: true, When.AddMinutes(1));

        Assert.AreSame(asks, ScanPresentation.Newer(fromTheFuture, asks, When), "an answer that never ages would be kept for ever");
        Assert.AreSame(aMinuteAhead, ScanPresentation.Newer(aMinuteAhead, asks, When), "a clock a minute off is still a clock");
    }

    [TestMethod]
    public void AnAdministratorAnswer_IsNotKeptForever()
    {
        ScannedCheck asks = Answer(CheckOutcome.NeedsAdmin("x"), elevated: false, When);
        ScannedCheck thirtyDays = Answer(CheckOutcome.Pass("x"), elevated: true, When - ScanPresentation.AdministratorAnswerLifetime);
        ScannedCheck older = Answer(CheckOutcome.Pass("x"), elevated: true, When - ScanPresentation.AdministratorAnswerLifetime - TimeSpan.FromMinutes(1));

        Assert.AreSame(thirtyDays, ScanPresentation.Newer(thirtyDays, asks, When));
        Assert.AreSame(asks, ScanPresentation.Newer(older, asks, When), "after a month the PC may be set up differently: it asks again");
    }

    [TestMethod]
    public void WhileTheFirstScanRuns_NothingIsSaidAboutHowThePcIsDoing()
    {
        (string headline, string detail) = ScanPresentation.Progress(3, 126);

        Assert.AreEqual("Checking this PC…", headline);
        Assert.AreEqual("3 of 126 checks answered", detail);
    }

    [TestMethod]
    public void ARow_StartsOpenOnlyWhenItNeedsAttention_AndThenStaysAsTheUserLeftIt()
    {
        // New on screen.
        Assert.IsTrue(ScanPresentation.StartsExpanded(null, isIgnored: false, Standing.NeedsAttention));
        Assert.IsFalse(ScanPresentation.StartsExpanded(null, isIgnored: false, Standing.Passed));
        Assert.IsFalse(ScanPresentation.StartsExpanded(null, isIgnored: false, Standing.CouldNotCheck));
        Assert.IsFalse(ScanPresentation.StartsExpanded(null, isIgnored: true, Standing.NeedsAttention));

        // Redrawn: as the user left it, whatever the new result.
        Assert.IsFalse(ScanPresentation.StartsExpanded((WasIgnored: false, WasExpanded: false), isIgnored: false, Standing.NeedsAttention));
        Assert.IsTrue(ScanPresentation.StartsExpanded((WasIgnored: false, WasExpanded: true), isIgnored: false, Standing.Passed));
        Assert.IsTrue(ScanPresentation.StartsExpanded((WasIgnored: true, WasExpanded: true), isIgnored: true, Standing.NeedsAttention), "an open ignored row stays open");

        // Just ignored, or just brought back: it starts over.
        Assert.IsFalse(ScanPresentation.StartsExpanded((WasIgnored: false, WasExpanded: true), isIgnored: true, Standing.NeedsAttention));
        Assert.IsTrue(ScanPresentation.StartsExpanded((WasIgnored: true, WasExpanded: false), isIgnored: false, Standing.NeedsAttention));
    }

    [TestMethod]
    public async Task TheResultHandedOverAndTheOneInTheFinishedScan_AreTheSameAnswer()
    {
        // The window keeps a row on screen when its answer is the same object.
        var scanner = new Scanner(new FakeProbes().Build(), TimeProvider.System);
        var arrived = new System.Collections.Concurrent.ConcurrentDictionary<string, ScannedCheck>();

        ScanResult scan = await scanner.RunAsync(CheckSelection.All, isElevated: false, check => arrived[check.Definition.Id] = check);

        Assert.IsTrue(scan.Checks.All(check => ReferenceEquals(check.Result, arrived[check.Definition.Id].Result)));
    }

    [TestMethod]
    public async Task ResultsAreHandedOver_AsEachCheckAnswers_AndOneCheckCanBeRunAgain()
    {
        var scanner = new Scanner(new FakeProbes().Build(), TimeProvider.System);
        var arrived = new System.Collections.Concurrent.ConcurrentBag<string>();

        ScanResult scan = await scanner.RunAsync(CheckSelection.All, isElevated: false, check => arrived.Add(check.Definition.Id));

        CollectionAssert.AreEquivalent(scan.Checks.Select(c => c.Definition.Id).ToArray(), arrived.ToArray());

        ScannedCheck again = await scanner.RunOneAsync(FirewallCheck.Id, isElevated: false);
        Assert.AreEqual(FirewallCheck.Id, again.Definition.Id);
        Assert.AreEqual(scan.Checks.Single(c => c.Definition.Id == FirewallCheck.Id).Result.Outcome.Status, again.Result.Outcome.Status);

        await Assert.ThrowsExactlyAsync<ArgumentException>(() => scanner.RunOneAsync("no.such.check", isElevated: false));
    }

    [TestMethod]
    public void WhatTheOtherProcessSaved_IsTakenInWhereItIsNewer()
    {
        DateTimeOffset now = new(2026, 11, 12, 15, 0, 0, TimeSpan.Zero);
        static ScannedCheck At(string id, CheckOutcome outcome, DateTimeOffset when, AdminNeed needsAdmin = AdminNeed.No, bool elevated = false) => new(
            new CheckDefinition(id, CheckCategory.Access, Severity.Medium, needsAdmin),
            Texts[FirewallCheck.Id],
            new CheckResult(id, outcome, when, elevated, TimeSpan.Zero));

        ScannedCheck mineOlder = At("firewall", CheckOutcome.Pass("On."), now.AddHours(-5));
        ScannedCheck mineNewer = At("logon", CheckOutcome.Fail("On."), now.AddMinutes(-1));
        ScannedCheck mineAdministrator = At("audit", CheckOutcome.Fail("Off."), now.AddDays(-2), AdminNeed.Yes, elevated: true);
        var known = new Dictionary<string, ScannedCheck>(StringComparer.Ordinal)
        {
            ["firewall"] = mineOlder,
            ["logon"] = mineNewer,
            ["audit"] = mineAdministrator,
        };

        ScannedCheck theirsNewer = At("firewall", CheckOutcome.Fail("Off."), now.AddMinutes(-10));
        ScannedCheck theirsOlder = At("logon", CheckOutcome.Pass("Off."), now.AddHours(-1));
        ScannedCheck theirsAsking = At("audit", CheckOutcome.NeedsAdmin("Needs administrator rights."), now.AddMinutes(-10), AdminNeed.Yes);
        ScannedCheck theirsOnly = At("new", CheckOutcome.Pass("Fine."), now.AddMinutes(-10));
        var saved = new ScanResult([theirsNewer, theirsOlder, theirsAsking, theirsOnly], now.AddMinutes(-10), Elevated: false);

        Assert.IsTrue(ScanPresentation.TakeNewer(known, saved, now));

        Assert.AreSame(theirsNewer, known["firewall"], "the icon found it off after this window last looked");
        Assert.AreSame(mineNewer, known["logon"], "this window's answer is the newer one");
        Assert.AreSame(mineAdministrator, known["audit"], "an administrator answer is not lost to 'needs administrator'");
        Assert.AreSame(theirsOnly, known["new"]);
        Assert.IsFalse(ScanPresentation.TakeNewer(known, saved, now), "nothing new the second time");
    }
}
