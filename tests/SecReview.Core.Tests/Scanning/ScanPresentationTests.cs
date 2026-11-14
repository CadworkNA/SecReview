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

    private static ScannedCheck Answer(CheckOutcome outcome, bool elevated, DateTimeOffset checkedAt, AdminNeed needsAdmin = AdminNeed.Yes, bool keeps = false) => new(
        new CheckDefinition("made-up.check", CheckCategory.Hardening, Severity.Medium, needsAdmin, KeepsAdministratorAnswer: keeps),
        Texts[FirewallCheck.Id],
        new CheckResult("made-up.check", outcome, checkedAt, elevated, TimeSpan.Zero));

    /// <summary>The answers a check holds, and which one decides.</summary>
    private static void AssertHolds(ScannedCheck check, ScannedCheck ordinary, ScannedCheck? administrator, ScannedCheck decides, string message = "")
    {
        Assert.AreSame(ordinary.Result, check.Result, $"the answer without administrator rights. {message}");
        Assert.AreSame(administrator?.Result, check.Administrator, $"the answer with administrator rights. {message}");
        Assert.AreSame(decides.Result, check.Shown, $"the answer that decides. {message}");
    }

    [TestMethod]
    public void AnAdministratorAnswer_StaysBesideALaterOrdinaryOne_AndDecidesWhereTheOrdinaryCanOnlyAsk()
    {
        ScannedCheck fromAdministrator = Answer(CheckOutcome.Fail("Auditing is off."), elevated: true, When.AddDays(-3));
        ScannedCheck ordinary = Answer(CheckOutcome.NeedsAdmin("This check needs administrator rights."), elevated: false, When);

        ScannedCheck kept = ScanPresentation.Newer(fromAdministrator, ordinary, When);

        AssertHolds(kept, ordinary, fromAdministrator, decides: fromAdministrator);
        Assert.AreEqual(Standing.NeedsAttention, ScanPresentation.StandingOf(kept));
        Assert.AreEqual(Texts[FirewallCheck.Id].TitleFail, kept.Title, "the title follows the answer that decides");
        Assert.AreSame(ordinary, ScanPresentation.Newer(null, ordinary, When));
    }

    [TestMethod]
    public void EachAnswer_ReplacesOnlyTheEarlierAnswerOfItsOwnKind()
    {
        ScannedCheck asks = Answer(CheckOutcome.NeedsAdmin("x"), elevated: false, When);
        ScannedCheck oldOrdinary = Answer(CheckOutcome.Fail("x"), elevated: false, When.AddDays(-1));
        ScannedCheck oldAdministrator = Answer(CheckOutcome.Fail("x"), elevated: true, When.AddDays(-1));
        ScannedCheck newAdministrator = Answer(CheckOutcome.Pass("x"), elevated: true, When);

        // An ordinary answer replaces the ordinary one; nothing from the administrator is invented.
        AssertHolds(ScanPresentation.Newer(oldOrdinary, asks, When), asks, null, decides: asks);

        // A new run of the administrator checks replaces the old one, whatever it says.
        ScannedCheck both = ScanPresentation.Newer(oldOrdinary, oldAdministrator, When);
        AssertHolds(ScanPresentation.Newer(both, newAdministrator, When), oldOrdinary, newAdministrator, decides: oldOrdinary);
        Assert.AreSame(newAdministrator.Result, ScanPresentation.Newer(oldAdministrator, newAdministrator, When).Result);
        Assert.IsNull(ScanPresentation.Newer(oldAdministrator, newAdministrator, When).Administrator, "one administrator answer, not two");

        // A check administrator rights add nothing to keeps only the new answer.
        ScannedCheck plainOld = Answer(CheckOutcome.Pass("x"), elevated: true, When.AddDays(-1), AdminNeed.No);
        ScannedCheck plainNew = Answer(CheckOutcome.Fail("x"), elevated: false, When, AdminNeed.No);
        Assert.AreSame(plainNew, ScanPresentation.Newer(plainOld, plainNew, When));
    }

    [TestMethod]
    public void AfterTheAdministratorChecks_AnOrdinaryScanNoLongerSwapsTheList()
    {
        // The report of #54: the same three problems, but the ordinary scan also lists what it
        // could not read. Neither answer may replace the other.
        ScannedCheck List(CheckOutcome outcome, bool elevated, DateTimeOffset checkedAt) =>
            Answer(outcome, elevated, checkedAt, AdminNeed.ForFullDetail, keeps: true);
        Finding[] problems = [Finding.Problem("A", "Users can change it", "Only administrators"), Finding.Problem("B", "Users can change it", "Only administrators")];
        ScannedCheck ordinary = List(new CheckOutcome(CheckStatus.Fail, "2 are not protected.", [.. problems, Finding.Note("C", "Needs administrator rights to read")]), elevated: false, When.AddHours(-2));
        ScannedCheck administrator = List(new CheckOutcome(CheckStatus.Fail, "2 are not protected.", problems), elevated: true, When.AddHours(-1));
        ScannedCheck ordinaryAgain = List(ordinary.Result.Outcome, elevated: false, When);

        ScannedCheck afterAdministrator = ScanPresentation.Newer(ordinary, administrator, When);
        ScannedCheck afterOrdinary = ScanPresentation.Newer(afterAdministrator, ordinaryAgain, When);

        AssertHolds(afterAdministrator, ordinary, administrator, decides: ordinary, "both fail: the newer ordinary answer decides");
        AssertHolds(afterOrdinary, ordinaryAgain, administrator, decides: ordinaryAgain, "the administrator answer is still there");
    }

    [TestMethod]
    public void WhereAnOrdinaryScanReadsSomething_ItsAnswerIsShown_NotAnOlderPass()
    {
        // Drive encryption: the administrator run said "on". Days later an ordinary scan finds
        // that Windows no longer confirms it. That is a reading, and it must not be hidden.
        ScannedCheck Partly(CheckOutcome outcome, bool elevated, DateTimeOffset checkedAt) =>
            Answer(outcome, elevated, checkedAt, AdminNeed.ForFullDetail);

        ScannedCheck wasOn = Partly(CheckOutcome.Pass("On for every drive."), elevated: true, When.AddDays(-3));
        ScannedCheck notConfirmed = Partly(CheckOutcome.NeedsAdmin("Windows does not confirm that C: is fully protected."), elevated: false, When);
        ScannedCheck suspended = Partly(CheckOutcome.Fail("BitLocker is suspended on C:."), elevated: true, When.AddDays(-3));

        AssertHolds(ScanPresentation.Newer(wasOn, notConfirmed, When), notConfirmed, wasOn, decides: notConfirmed);
        AssertHolds(ScanPresentation.Newer(suspended, notConfirmed, When), notConfirmed, suspended, decides: suspended, "a failure read with the rights is not hidden either");
    }

    [TestMethod]
    public void ACheckThatReadsMostOfAListItself_ShowsTheAnswerThatSaysMore()
    {
        ScannedCheck List(CheckOutcome outcome, bool elevated, DateTimeOffset checkedAt) =>
            Answer(outcome, elevated, checkedAt, AdminNeed.ForFullDetail, keeps: true);

        ScannedCheck allRead = List(CheckOutcome.Pass("All 40 are protected."), elevated: true, When.AddDays(-3));
        ScannedCheck someUnread = List(CheckOutcome.NeedsAdmin("No problem in 38; 2 more need administrator rights to read."), elevated: false, When);
        ScannedCheck problem = List(CheckOutcome.Fail("1 is not protected."), elevated: false, When);
        ScannedCheck unreadable = List(CheckOutcome.Error("Could not read the list."), elevated: false, When);
        ScannedCheck ordinaryPass = List(CheckOutcome.Pass("All 38 are protected."), elevated: false, When);
        ScannedCheck administratorProblem = List(CheckOutcome.Fail("1 more is not protected."), elevated: true, When.AddDays(-3));
        ScannedCheck tooOld = List(CheckOutcome.Pass("x"), elevated: true, When - ScanPresentation.AdministratorAnswerLifetime - TimeSpan.FromMinutes(1));
        ScannedCheck oldOrdinary = List(CheckOutcome.Pass("x"), elevated: false, When.AddDays(-1));

        AssertHolds(ScanPresentation.Newer(allRead, someUnread, When), someUnread, allRead, decides: allRead, "the administrator's answer covers the whole list");
        AssertHolds(ScanPresentation.Newer(allRead, problem, When), problem, allRead, decides: problem, "a problem found now is always shown");
        AssertHolds(ScanPresentation.Newer(allRead, unreadable, When), unreadable, allRead, decides: unreadable);
        AssertHolds(ScanPresentation.Newer(allRead, ordinaryPass, When), ordinaryPass, allRead, decides: ordinaryPass);
        AssertHolds(ScanPresentation.Newer(administratorProblem, ordinaryPass, When), ordinaryPass, administratorProblem, decides: administratorProblem, "a problem only the administrator can see");
        AssertHolds(ScanPresentation.Newer(tooOld, someUnread, When), someUnread, null, decides: someUnread, "after a month it asks again");
        AssertHolds(ScanPresentation.Newer(oldOrdinary, someUnread, When), someUnread, null, decides: someUnread);
    }

    [TestMethod]
    public void AnAnswerDatedAfterNow_IsNotKept()
    {
        ScannedCheck asks = Answer(CheckOutcome.NeedsAdmin("x"), elevated: false, When);
        ScannedCheck fromTheFuture = Answer(CheckOutcome.Pass("x"), elevated: true, When.AddYears(70));
        ScannedCheck aMinuteAhead = Answer(CheckOutcome.Pass("x"), elevated: true, When.AddMinutes(1));

        AssertHolds(ScanPresentation.Newer(fromTheFuture, asks, When), asks, null, decides: asks, "an answer that never ages would be kept for ever");
        AssertHolds(ScanPresentation.Newer(aMinuteAhead, asks, When), asks, aMinuteAhead, decides: aMinuteAhead, "a clock a minute off is still a clock");
    }

    [TestMethod]
    public void AnAdministratorAnswer_IsNotKeptForever()
    {
        ScannedCheck asks = Answer(CheckOutcome.NeedsAdmin("x"), elevated: false, When);
        ScannedCheck thirtyDays = Answer(CheckOutcome.Pass("x"), elevated: true, When - ScanPresentation.AdministratorAnswerLifetime);
        ScannedCheck older = Answer(CheckOutcome.Pass("x"), elevated: true, When - ScanPresentation.AdministratorAnswerLifetime - TimeSpan.FromMinutes(1));

        AssertHolds(ScanPresentation.Newer(thirtyDays, asks, When), asks, thirtyDays, decides: thirtyDays);
        AssertHolds(ScanPresentation.Newer(older, asks, When), asks, null, decides: asks, "after a month the PC may be set up differently: it asks again");
    }

    [TestMethod]
    public void TheDetails_ShowBothAnswers_EachWithItsHeading()
    {
        ScannedCheck ordinary = Answer(new CheckOutcome(CheckStatus.Fail, "Seen now.", [Finding.Note("C", "Needs administrator rights to read")]), elevated: false, When);
        ScannedCheck administrator = Answer(new CheckOutcome(CheckStatus.Fail, "Seen with the rights.", [Finding.Problem("C", "Users can change it", "Only administrators")]), elevated: true, When.AddDays(-1));

        string[] lines = ScanPresentation.Details(ScanPresentation.Newer(administrator, ordinary, When)).Split(Environment.NewLine);

        CollectionAssert.Contains(lines, ScanPresentation.AnswerHeading(ordinary.Result));
        CollectionAssert.Contains(lines, ScanPresentation.AnswerHeading(administrator.Result));
        CollectionAssert.Contains(lines, "[i]  C: Needs administrator rights to read");
        CollectionAssert.Contains(lines, "[!!] C: Users can change it (expected: Only administrators)");
        StringAssert.StartsWith(ScanPresentation.AnswerHeading(ordinary.Result), "Without administrator rights · checked ");
        StringAssert.StartsWith(ScanPresentation.AnswerHeading(administrator.Result), "With administrator rights · checked ");
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
        Assert.AreSame(theirsAsking.Result, known["audit"].Result, "their newer answer without administrator rights is taken");
        Assert.AreSame(mineAdministrator.Result, known["audit"].Administrator, "an administrator answer is not lost to 'needs administrator'");
        Assert.AreSame(mineAdministrator.Result, known["audit"].Shown);
        Assert.AreSame(theirsOnly, known["new"]);
        Assert.IsFalse(ScanPresentation.TakeNewer(known, saved, now), "nothing new the second time");
    }
}
