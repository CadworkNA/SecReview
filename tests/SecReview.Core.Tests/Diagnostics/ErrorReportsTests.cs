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

    private static FakeProbes Policy(RegistryValue value) =>
        new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, ErrorReports.PolicyKey, ErrorReports.PolicyValue, value);

    [TestMethod]
    public void ABuildWithNowhereToSend_SendsNothing_WhateverElseIsSet()
    {
        foreach (string? address in new[] { null, "", "   " })
        {
            Assert.AreEqual(ErrorReportsState.NoAddress, ErrorReports.State(address, settingOn: true, new FakeProbes().Build().Registry));
        }

        Assert.AreEqual(0, (int)ErrorReportsState.NoAddress, "a state nobody worked out sends nothing");
    }

    [TestMethod]
    public void TheUsersSwitchDecides_WhenTheOrganisationSaysNothing()
    {
        IRegistryProbe registry = new FakeProbes().Build().Registry;

        Assert.AreEqual(ErrorReportsState.On, ErrorReports.State(Address, settingOn: true, registry));
        Assert.AreEqual(ErrorReportsState.OffBySetting, ErrorReports.State(Address, settingOn: false, registry));
        Assert.AreEqual(ErrorReportsState.On, ErrorReports.State(Address, settingOn: true, Policy(RegistryValue.FromNumber(0)).Build().Registry));
    }

    [TestMethod]
    public void TheOrganisationsNo_Wins_AndSoDoesAPolicyThatCannotBeRead()
    {
        Assert.AreEqual(ErrorReportsState.OffByPolicy, ErrorReports.State(Address, settingOn: true, Policy(RegistryValue.FromNumber(1)).Build().Registry));
        Assert.AreEqual(ErrorReportsState.OffByPolicy, ErrorReports.State(Address, settingOn: true, Policy(RegistryValue.FromNumber(7)).Build().Registry));
        Assert.AreEqual(
            ErrorReportsState.OffByPolicy,
            ErrorReports.State(Address, settingOn: true, Policy(RegistryValue.FromText("0")).Build().Registry),
            "a value of the wrong kind is not a clear yes");

        var unreadable = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied("no") };
        Assert.AreEqual(ErrorReportsState.OffByPolicy, ErrorReports.State(Address, settingOn: true, unreadable.Build().Registry));
    }

    [TestMethod]
    public void EveryState_IsSaidInASentence()
    {
        foreach (ErrorReportsState state in Enum.GetValues<ErrorReportsState>())
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(ErrorReports.Describe(state)));
        }
    }

    [TestMethod]
    public void AnErrorInsideACheck_SaysNothingButItsType()
    {
        var error = new InvalidOperationException(@"Could not read C:\Users\tester\.npmrc: token npm_made_up_secret is malformed");

        Assert.IsNull(ErrorReports.Message(error, Privacy, fromCheck: true));
    }

    [TestMethod]
    public void AnyOtherError_KeepsItsMessage_WithoutNames_AndWithinALimit()
    {
        var error = new InvalidOperationException("Could not open C:\\Users\\tester\\AppData\\Local\\SecReview\\settings.json on TESTPC01\r\n  for tester");

        string message = ErrorReports.Message(error, Privacy, fromCheck: false)!;

        Assert.IsFalse(message.Contains("tester", StringComparison.OrdinalIgnoreCase), message);
        Assert.IsFalse(message.Contains("TESTPC01", StringComparison.OrdinalIgnoreCase), message);
        Assert.IsFalse(message.Contains('\n', StringComparison.Ordinal));
        StringAssert.Contains(message, "settings.json");

        string longMessage = ErrorReports.Message(new InvalidOperationException(new string('x', 5000)), Privacy, fromCheck: false)!;
        Assert.AreEqual(ErrorReports.MaximumMessageLength, longMessage.Length);
    }

    [TestMethod]
    public void TheSameErrorFromTheSamePlace_IsOneError_WhateverItsMessage()
    {
        static Exception Thrown(string message)
        {
            try
            {
                throw new InvalidOperationException(message);
            }
            catch (InvalidOperationException exception)
            {
                return exception;
            }
        }

        string first = ErrorReports.Fingerprint(Thrown("on one PC"), "firewall.enabled");

        Assert.AreEqual(first, ErrorReports.Fingerprint(Thrown("on another PC"), "firewall.enabled"));
        Assert.AreNotEqual(first, ErrorReports.Fingerprint(Thrown("on one PC"), "disk.encryption"));
        Assert.AreNotEqual(first, ErrorReports.Fingerprint(new InvalidOperationException("never thrown"), "firewall.enabled"));
        StringAssert.StartsWith(first, "System.InvalidOperationException|");
    }

    [TestMethod]
    public void AnErrorIsReportedOnce_AndOnlySoManyInOneRun()
    {
        var budget = new ErrorReportBudget(maximum: 3);

        Assert.IsTrue(budget.Allow("a"));
        Assert.IsFalse(budget.Allow("a"));
        Assert.IsTrue(budget.Allow("b"));
        Assert.IsTrue(budget.Allow("c"));
        Assert.IsFalse(budget.Allow("d"), "the fourth different error of a run is not sent");
        Assert.IsFalse(budget.Allow("a"));
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
