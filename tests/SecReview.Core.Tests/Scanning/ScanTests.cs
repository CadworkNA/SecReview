using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Scanning;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Scanning;

[TestClass]
public sealed class ScanTests
{
    private static readonly DateTimeOffset When = new(2026, 1, 15, 8, 30, 0, TimeSpan.Zero);
    private static readonly CheckTexts Texts = CheckTexts.Load();

    private static ScanResult Scan(params (string Id, CheckOutcome Outcome, Severity Severity)[] checks) => new(
        [.. checks.Select(c => new ScannedCheck(
            new CheckDefinition(c.Id, CheckCategory.SystemIntegrity, c.Severity),
            Texts[FirewallCheck.Id],
            new CheckResult(c.Id, c.Outcome, When, Elevated: false, TimeSpan.Zero)))],
        When,
        Elevated: false);

    [TestMethod]
    public void DisplayOrder_FailuresBySeverity_ThenErrors_ThenNeedsAdmin_ThenPasses_ThenNotApplicable()
    {
        ScanResult scan = Scan(
            ("pass", CheckOutcome.Pass("x"), Severity.High),
            ("na", CheckOutcome.NotApplicable("x"), Severity.High),
            ("fail-low", CheckOutcome.Fail("x"), Severity.Low),
            ("admin", CheckOutcome.NeedsAdmin("x"), Severity.High),
            ("fail-high", CheckOutcome.Fail("x"), Severity.High),
            ("error", CheckOutcome.Error("x"), Severity.High),
            ("fail-medium", CheckOutcome.Fail("x"), Severity.Medium));

        string[] order = [.. ScanPresentation.InDisplayOrder(scan).Select(c => c.Definition.Id)];

        CollectionAssert.AreEqual(
            new[] { "fail-high", "fail-medium", "fail-low", "error", "admin", "pass", "na" }, order);
    }

    [TestMethod]
    public void DisplayOrder_KeepsCatalogueOrderWithinAGroup()
    {
        ScanResult scan = Scan(
            ("b", CheckOutcome.Pass("x"), Severity.Low),
            ("a", CheckOutcome.Pass("x"), Severity.High),
            ("c", CheckOutcome.Pass("x"), Severity.Medium));

        CollectionAssert.AreEqual(
            new[] { "b", "a", "c" }, ScanPresentation.InDisplayOrder(scan).Select(c => c.Definition.Id).ToArray());
    }

    [TestMethod]
    public void Headline_CountsFailures()
    {
        Assert.AreEqual(
            "1 thing needs attention",
            ScanPresentation.Headline(Scan(("a", CheckOutcome.Fail("x"), Severity.High), ("b", CheckOutcome.Pass("x"), Severity.High))));
        Assert.AreEqual(
            "2 things need attention",
            ScanPresentation.Headline(Scan(("a", CheckOutcome.Fail("x"), Severity.High), ("b", CheckOutcome.Fail("x"), Severity.Low))));
    }

    [TestMethod]
    public void InformationalFailures_AreWorthKnowing_InHeadlineCountsAndOrderAlike()
    {
        ScanResult scan = Scan(
            ("pass", CheckOutcome.Pass("x"), Severity.High),
            ("info", CheckOutcome.Fail("x"), Severity.Info),
            ("admin", CheckOutcome.NeedsAdmin("x"), Severity.High));

        Assert.AreEqual(Standing.WorthKnowing, ScanPresentation.StandingOf(scan.Checks[1]));
        Assert.AreEqual("No problems found so far", ScanPresentation.Headline(scan));
        Assert.AreEqual(
            "1 of 2 checks pass, 1 needs administrator rights, 1 thing worth knowing", ScanPresentation.Counts(scan));
        CollectionAssert.AreEqual(
            new[] { "admin", "info", "pass" },
            ScanPresentation.InDisplayOrder(scan).Select(c => c.Definition.Id).ToArray());
    }

    [TestMethod]
    public void InformationalFailures_NeverOutrankARealFailure()
    {
        ScanResult scan = Scan(("info", CheckOutcome.Fail("x"), Severity.Info), ("low", CheckOutcome.Fail("x"), Severity.Low));

        Assert.AreEqual("1 thing needs attention", ScanPresentation.Headline(scan));
        Assert.AreEqual("0 of 1 checks pass, 1 thing worth knowing", ScanPresentation.Counts(scan));
        Assert.AreEqual("low", ScanPresentation.InDisplayOrder(scan)[0].Definition.Id);
    }

    [TestMethod]
    public void Standing_FollowsTheStatus_AndAnUnfilledOneIsCouldNotCheck()
    {
        ScanResult scan = Scan(
            ("a", CheckOutcome.Pass("x"), Severity.High),
            ("b", CheckOutcome.Fail("x"), Severity.Low),
            ("c", CheckOutcome.Error("x"), Severity.Info),
            ("d", CheckOutcome.NeedsAdmin("x"), Severity.Info),
            ("e", CheckOutcome.NotApplicable("x"), Severity.High));

        CollectionAssert.AreEqual(
            new[] { Standing.Passed, Standing.NeedsAttention, Standing.CouldNotCheck, Standing.NeedsAdmin, Standing.DoesNotApply },
            scan.Checks.Select(check => ScanPresentation.StandingOf(check)).ToArray());

        // A slot nobody filled in, as it would be at run time.
        var unfilled = new Standing[1];
        Assert.AreEqual(Standing.CouldNotCheck, unfilled[0]);
    }

    [TestMethod]
    public void Headline_WhenAChecksCouldNotBeCompleted_NeverClaimsAllIsWell()
    {
        ScanResult scan = Scan(("a", CheckOutcome.Error("x"), Severity.High), ("b", CheckOutcome.Pass("x"), Severity.High));

        Assert.AreEqual("1 check could not be completed", ScanPresentation.Headline(scan));
    }

    [TestMethod]
    public void Headline_WhenChecksStillNeedAdministrator_SaysSoFar_NotAllIsWell()
    {
        ScanResult scan = Scan(("a", CheckOutcome.NeedsAdmin("x"), Severity.High), ("b", CheckOutcome.Pass("x"), Severity.High));

        Assert.AreEqual("No problems found so far", ScanPresentation.Headline(scan));
        Assert.AreEqual("1 of 2 checks pass, 1 needs administrator rights", ScanPresentation.Counts(scan));
    }

    [TestMethod]
    public void Headline_AllPass()
    {
        ScanResult scan = Scan(("a", CheckOutcome.Pass("x"), Severity.High), ("b", CheckOutcome.NotApplicable("x"), Severity.High));

        Assert.AreEqual("Everything checked is in order", ScanPresentation.Headline(scan));
        Assert.AreEqual("1 of 1 checks pass", ScanPresentation.Counts(scan));
    }

    [TestMethod]
    public void Headline_NothingRun_DoesNotClaimAllIsWell()
    {
        Assert.AreEqual("No checks were run", ScanPresentation.Headline(Scan()));
    }

    [TestMethod]
    public void ScannedCheck_TitleMatchesTheOutcome_AndIsNeutralWhenThereIsNoAnswer()
    {
        ScanResult scan = Scan(
            ("a", CheckOutcome.Pass("x"), Severity.High),
            ("b", CheckOutcome.Fail("x"), Severity.High),
            ("c", CheckOutcome.Error("x"), Severity.High),
            ("d", CheckOutcome.NeedsAdmin("x"), Severity.High),
            ("e", CheckOutcome.NotApplicable("x"), Severity.High));

        Assert.AreEqual("Firewall is on", scan.Checks[0].Title);
        Assert.AreEqual("Firewall is off", scan.Checks[1].Title);
        Assert.IsTrue(scan.Checks.Skip(2).All(c => c.Title == "Firewall"), "no verdict may be implied without an answer");
    }

    [TestMethod]
    public async Task Scanner_RunsTheCatalogue_AndPairsEachResultWithItsWording()
    {
        // Nothing set up, and the registry, services and files unreadable too: every reading fails.
        var probes = new FakeProbes
        {
            RegistryFailure = ProbeFailure.Failed("Reading the registry failed."),
            ServicesFailure = ProbeFailure.Failed("Reading services failed."),
            FilesFailure = ProbeFailure.Failed("Reading files failed."),
        };
        var scanner = new Scanner(probes.Build(), TimeProvider.System);

        ScanResult scan = await scanner.RunAsync(CheckSelection.All, isElevated: false);

        Assert.AreEqual(CheckCatalogue.Checks.Count, scan.Checks.Count);
        Assert.IsFalse(scan.Elevated);

        // A check that only an administrator scan can answer waits for one; everything else
        // could not be checked. Nothing passes, fails or "does not apply".
        string[] answered = [.. scan.Checks
            .Where(c => c.Result.Outcome.Status != (c.Definition.NeedsAdmin == AdminNeed.Yes ? CheckStatus.NeedsAdmin : CheckStatus.Error))
            .Select(c => $"{c.Definition.Id}: {c.Result.Outcome.Status}")];
        Assert.AreEqual(0, answered.Length, "unreadable is never a pass: " + string.Join(", ", answered));
        Assert.IsTrue(scan.Checks.All(c => c.Text.Name == c.Title), "an unanswered check is named neutrally");
    }

    [TestMethod]
    public void DemoScan_CoversEveryCheck_AndSeveralKindsOfOutcome()
    {
        ScanResult demo = DemoScan.Create(TimeProvider.System);

        CollectionAssert.AreEquivalent(
            CheckCatalogue.Checks.Select(c => c.Definition.Id).ToArray(),
            demo.Checks.Select(c => c.Definition.Id).ToArray());
        Assert.IsTrue(demo.Checks.Select(c => c.Result.Outcome.Status).Distinct().Count() >= 4);
        Assert.IsTrue(demo.Checks.All(c => !string.IsNullOrWhiteSpace(c.Result.Outcome.Summary)));
    }
}
