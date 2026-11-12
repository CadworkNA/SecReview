using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Diagnostics;
using SecReview.Probing;
using SecReview.Scanning;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Diagnostics;

[TestClass]
public sealed class ErrorReportsTests
{
    private const string Address = "https://made-up-key@reports.example.test/1";

    private static readonly PrivacyFilter Privacy = new(@"C:\Users\tester", "tester", "TESTPC01");

    private static readonly ErrorReportsChoice Yes = new(SwitchOn: true, SettingsWereRead: true, NoticeSeen: true);

    private static readonly IRegistryProbe NoPolicy = new FakeProbes().Build().Registry;

    private static IRegistryProbe Policy(RegistryValue value) =>
        new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, ErrorReports.PolicyKey, ErrorReports.PolicyValue, value).Build().Registry;

    [TestMethod]
    public void ABuildWithNowhereToSend_SendsNothing_WhateverElseIsSet()
    {
        foreach (string? address in new[] { null, "", "   " })
        {
            Assert.AreEqual(ErrorReportsState.NoAddress, ErrorReports.State(address, Yes, NoPolicy));
        }

        Assert.AreEqual(0, (int)ErrorReportsState.NoAddress, "a state nobody worked out sends nothing");
    }

    [TestMethod]
    public void TheUsersSwitchDecides_WhenTheOrganisationSaysNothing()
    {
        Assert.AreEqual(ErrorReportsState.On, ErrorReports.State(Address, Yes, NoPolicy));
        Assert.AreEqual(ErrorReportsState.OffBySetting, ErrorReports.State(Address, Yes with { SwitchOn = false }, NoPolicy));
        Assert.AreEqual(ErrorReportsState.On, ErrorReports.State(Address, Yes, Policy(RegistryValue.FromNumber(0))));
    }

    [TestMethod]
    public void NothingIsSent_WhileTheUsersChoiceIsNotKnown()
    {
        // The settings file could not be read: the switch shown is only the default.
        Assert.AreEqual(ErrorReportsState.NotYetKnown, ErrorReports.State(Address, Yes with { SettingsWereRead = false }, NoPolicy));

        // The notice that says errors are reported has not been closed yet.
        Assert.AreEqual(ErrorReportsState.NotYetKnown, ErrorReports.State(Address, Yes with { NoticeSeen = false }, NoPolicy));

        // Not known, and it would have been off anyway: still not known.
        Assert.AreEqual(
            ErrorReportsState.NotYetKnown, ErrorReports.State(Address, new ErrorReportsChoice(SwitchOn: false, SettingsWereRead: false, NoticeSeen: true), NoPolicy));
    }

    [TestMethod]
    public void TheOrganisationsNo_Wins_AndSoDoesAPolicyThatCannotBeRead()
    {
        Assert.AreEqual(ErrorReportsState.OffByPolicy, ErrorReports.State(Address, Yes, Policy(RegistryValue.FromNumber(1))));
        Assert.AreEqual(ErrorReportsState.OffByPolicy, ErrorReports.State(Address, Yes, Policy(RegistryValue.FromNumber(7))));
        Assert.AreEqual(
            ErrorReportsState.OffByPolicy, ErrorReports.State(Address, Yes, Policy(RegistryValue.FromText("0"))), "a value of the wrong kind is not a clear yes");
        Assert.AreEqual(
            ErrorReportsState.OffByPolicy, ErrorReports.State(Address, Yes with { NoticeSeen = false }, Policy(RegistryValue.FromNumber(1))), "the policy is said first");

        var unreadable = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied("no") };
        Assert.AreEqual(ErrorReportsState.OffByPolicy, ErrorReports.State(Address, Yes, unreadable.Build().Registry));
    }

    [TestMethod]
    public void EveryState_IsSaidInASentence()
    {
        string[] sentences = [.. Enum.GetValues<ErrorReportsState>().Select(ErrorReports.Describe)];

        Assert.IsTrue(sentences.All(sentence => !string.IsNullOrWhiteSpace(sentence)));
        Assert.AreEqual(sentences.Length, sentences.Distinct().Count());
    }

    [TestMethod]
    public void WhatTheUserTypes_LosesTheNames_AndStaysWithinALimit()
    {
        string text = ErrorReports.Text("  It crashed on TESTPC01 when I opened\r\nC:\\Users\\tester\\notes.txt  ", Privacy, 2000);

        Assert.IsFalse(text.Contains("tester", StringComparison.OrdinalIgnoreCase), text);
        Assert.IsFalse(text.Contains("TESTPC01", StringComparison.OrdinalIgnoreCase), text);
        StringAssert.StartsWith(text, "It crashed on");
        StringAssert.Contains(text, "notes.txt");
        Assert.IsTrue(text.Contains('\n', StringComparison.Ordinal), "what the user wrote keeps its lines");

        Assert.AreEqual(50, ErrorReports.Text(new string('x', 500), Privacy, 50).Length);
        Assert.AreEqual(string.Empty, ErrorReports.Text(null, Privacy, 50));
    }

    [TestMethod]
    [DataRow("firewall.enabled", true)]
    [DataRow("sc.uv.cooldown", true)]
    [DataRow("cis_smb1-client.2", true)]
    [DataRow("", false)]
    [DataRow(null, false)]
    [DataRow("has space", false)]
    [DataRow(@"C:\Users\tester\file", false)]
    [DataRow("name@example.test", false)]
    public void OnlyACheckIdentifier_IsSentAsOne(string? value, bool expected)
    {
        Assert.AreEqual(expected, ErrorReports.IsCheckId(value));
        Assert.IsFalse(ErrorReports.IsCheckId(new string('a', 101)));
    }

    private static Exception Thrown(Exception error)
    {
        try
        {
            throw error;
        }
        catch (Exception caught) when (ReferenceEquals(caught, error))
        {
            return caught;
        }
    }

    private static ArgumentNullException FromAHelperOfTheFramework()
    {
        try
        {
            ArgumentNullException.ThrowIfNull((object?)null, "made-up");
            throw new InvalidOperationException("not reached");
        }
        catch (ArgumentNullException exception)
        {
            return exception;
        }
    }

    private static ArgumentNullException FromTheSameHelper_SomewhereElse()
    {
        try
        {
            ArgumentNullException.ThrowIfNull((object?)null, "made-up");
            throw new InvalidOperationException("not reached");
        }
        catch (ArgumentNullException exception)
        {
            return exception;
        }
    }

    [TestMethod]
    public void TheSameBug_IsOneBug_WhateverItsMessage()
    {
        string first = ErrorReports.Fingerprint(Thrown(new InvalidOperationException("on one PC")));

        Assert.AreEqual(first, ErrorReports.Fingerprint(Thrown(new InvalidOperationException("on another PC"))));
        Assert.AreNotEqual(first, ErrorReports.Fingerprint(Thrown(new FormatException("on one PC"))));
        Assert.AreNotEqual(first, ErrorReports.Fingerprint(new InvalidOperationException("never thrown")));
        StringAssert.StartsWith(first, "System.InvalidOperationException|");
    }

    [TestMethod]
    public void TwoBugsThatEndInTheSameFrameworkHelper_AreToldApartByWhereSecReviewCalledIt()
    {
        string here = ErrorReports.Fingerprint(FromAHelperOfTheFramework());
        string there = ErrorReports.Fingerprint(FromTheSameHelper_SomewhereElse());

        Assert.AreNotEqual(here, there);
        StringAssert.Contains(here, nameof(FromAHelperOfTheFramework));
        Assert.AreEqual(here, ErrorReports.Fingerprint(FromAHelperOfTheFramework()));
    }

    [TestMethod]
    public void ResultsThatGoWithFeedback_AreIdentifiersAndOutcomes_NothingElse()
    {
        CheckTexts texts = CheckTexts.Load();
        ScannedCheck Scanned(ICheck check, CheckOutcome outcome) => new(
            check.Definition, texts[check.Definition.Id], new CheckResult(check.Definition.Id, outcome, DateTimeOffset.UnixEpoch, false, TimeSpan.Zero));
        var scan = new ScanResult(
            [
                Scanned(new FirewallCheck(), CheckOutcome.Fail("Off for the made-up network.", Finding.Problem("made-up item", "made-up found", "x"))),
                Scanned(new AutomaticLogonCheck(), CheckOutcome.Pass("Off.")),
                Scanned(new AntivirusCheck(), CheckOutcome.Error("The made-up service did not answer.")),
            ],
            DateTimeOffset.UnixEpoch,
            Elevated: false);

        string text = ErrorReports.ResultsForFeedback(scan);

        Assert.AreEqual(
            $"1 checks pass. Not passing:{Environment.NewLine}firewall.enabled: Fail{Environment.NewLine}antivirus.active: Error", text);
        Assert.IsFalse(text.Contains("made-up", StringComparison.Ordinal), "no summary and no finding");

        var allPass = new ScanResult([Scanned(new AutomaticLogonCheck(), CheckOutcome.Pass("Off."))], DateTimeOffset.UnixEpoch, false);
        Assert.AreEqual("1 checks pass; none fail.", ErrorReports.ResultsForFeedback(allPass));
    }
}

[TestClass]
public sealed class ErrorReportBudgetTests
{
    private string _folder = string.Empty;

    [TestInitialize]
    public void CreateFolder() => _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));

    [TestCleanup]
    public void DeleteFolder()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    /// <summary>A clock that shows whatever day it is set to.</summary>
    private sealed class Calendar(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static readonly DateTimeOffset Monday = new(2026, 11, 9, 10, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void ABugIsReportedOnce_AndOnlySoManyDifferentOnes()
    {
        var budget = new ErrorReportBudget(null, new Calendar(Monday), maximum: 3);

        Assert.IsTrue(budget.Allow("a"));
        Assert.IsFalse(budget.Allow("a"));
        Assert.IsTrue(budget.Allow("b"));
        Assert.IsTrue(budget.Allow("c"));
        Assert.IsFalse(budget.Allow("d"), "the fourth different bug of a day is not sent");
        Assert.IsFalse(budget.Allow("a"));
    }

    [TestMethod]
    public void WhatWasReportedToday_IsRememberedAcrossStarts_AndForgottenTheNextDay()
    {
        var clock = new Calendar(Monday);

        Assert.IsTrue(new ErrorReportBudget(_folder, clock, maximum: 2).Allow("a bug with a stack that could hold anything"));
        Assert.IsFalse(new ErrorReportBudget(_folder, clock, maximum: 2).Allow("a bug with a stack that could hold anything"), "SecReview was started again");
        Assert.IsTrue(new ErrorReportBudget(_folder, clock, maximum: 2).Allow("b"));
        Assert.IsFalse(new ErrorReportBudget(_folder, clock, maximum: 2).Allow("c"), "the day's limit holds across starts");

        string file = File.ReadAllText(Path.Combine(_folder, ErrorReportBudget.FileName));
        Assert.IsFalse(file.Contains("stack", StringComparison.Ordinal), "the file holds the day and hashes, not what the bug was");
        StringAssert.StartsWith(file, "2026-11-09");

        clock.Now = Monday.AddDays(1);
        Assert.IsTrue(new ErrorReportBudget(_folder, clock, maximum: 2).Allow("a bug with a stack that could hold anything"), "a new day");
    }

    [TestMethod]
    public void TheSameBudget_CarriesOverMidnight()
    {
        var clock = new Calendar(Monday);
        var budget = new ErrorReportBudget(_folder, clock, maximum: 1);
        Assert.IsTrue(budget.Allow("a"));
        Assert.IsFalse(budget.Allow("b"));

        clock.Now = Monday.AddDays(1);

        Assert.IsTrue(budget.Allow("b"));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("not a day\nabcdef0123456789\n")]
    [DataRow("2026-11-09\nnot-a-hash\n\n????\n")]
    public void AFileThatMakesNoSense_MeansNothingWasReportedYet(string contents)
    {
        Directory.CreateDirectory(_folder);
        File.WriteAllText(Path.Combine(_folder, ErrorReportBudget.FileName), contents);

        Assert.IsTrue(new ErrorReportBudget(_folder, new Calendar(Monday)).Allow("a"));
    }
}

[TestClass]
public sealed class RunMarkerTests
{
    private string _folder = string.Empty;

    [TestInitialize]
    public void CreateFolder() => _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));

    [TestCleanup]
    public void DeleteFolder()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private RunMarker Marker(int processId, params int[] running) => new(_folder, processId, running.Contains);

    [TestMethod]
    public void ARunThatClosesDown_LeavesNothingBehind()
    {
        RunMarker first = Marker(100);
        Assert.IsFalse(first.Begin(), "the very first run has nothing before it");
        Assert.AreEqual(1, Directory.GetFiles(_folder).Length);
        first.End();
        Assert.AreEqual(0, Directory.GetFiles(_folder).Length);

        Assert.IsFalse(Marker(101).Begin());
    }

    [TestMethod]
    public void ARunThatNeverClosedDown_IsNoticedOnce()
    {
        Marker(100).Begin(); // and then it crashed: End is never called

        Assert.IsTrue(Marker(101).Begin(), "process 100 is gone and left its marker");
        Assert.IsFalse(Marker(102, running: 101).Begin(), "it was said; the window of process 101 is simply still open");
    }

    [TestMethod]
    public void AnotherWindowThatIsStillOpen_IsNotACrash_AndKeepsItsMarker()
    {
        Marker(100).Begin();

        Assert.IsFalse(Marker(101, running: 100).Begin());
        Assert.AreEqual(2, Directory.GetFiles(_folder).Length);
    }

    [TestMethod]
    public void AMarkerWithThisProcesssOwnNumber_IsFromAnEarlierRun()
    {
        Marker(100).Begin();

        Assert.IsTrue(Marker(100).Begin(), "process numbers come round again; this marker cannot be this run's");
        Assert.AreEqual(1, Directory.GetFiles(_folder).Length);
    }

    [TestMethod]
    public void FilesThatAreNotMarkers_AreLeftAlone_AndOddOnesAreCleared()
    {
        Directory.CreateDirectory(_folder);
        File.WriteAllText(Path.Combine(_folder, "settings.json"), "{}");
        File.WriteAllText(Path.Combine(_folder, "running-abc.marker"), string.Empty);

        Assert.IsFalse(Marker(100).Begin());

        CollectionAssert.AreEquivalent(
            new[] { "running-100.marker", "settings.json" }, Directory.GetFiles(_folder).Select(Path.GetFileName).ToArray());
    }

    [TestMethod]
    public void EndingTwice_OrWithoutBeginning_IsHarmless()
    {
        RunMarker marker = Marker(100);
        marker.End();
        marker.Begin();
        marker.End();
        marker.End();

        Assert.AreEqual(0, Directory.GetFiles(_folder).Length);
    }
}
