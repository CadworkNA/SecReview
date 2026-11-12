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
            new[] { "Needs attention []: updates-high, chain-fail, access-low", "Could not be checked []: updates-error" },
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
        Assert.AreEqual(4, ScanPresentation.CountFor(scan, null, ScanFilter.NeedsAttention));
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
        Assert.AreEqual("2 of 6 checks pass, 1 needs administrator rights, 1 thing worth knowing, 2 ignored", ScanPresentation.Counts(scan, ignored));

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
        Assert.AreEqual(3, ScanPresentation.CountFor(scan, ignored, ScanFilter.NeedsAttention));
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
    [DataRow(30 * 3600, "yesterday")]
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
        CollectionAssert.Contains(lines, "1. " + Texts[FirewallCheck.Id].Fix[0]);

        string passing = ScanPresentation.Details(new ScannedCheck(
            check.Definition, check.Text, new CheckResult(FirewallCheck.Id, CheckOutcome.Pass("On for every network."), When, false, TimeSpan.Zero)));
        Assert.IsFalse(passing.Contains("How to fix", StringComparison.Ordinal), "a passing check has nothing to fix");
        StringAssert.Contains(passing, "Passed · Firewall and sharing · firewall.enabled");
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
}
