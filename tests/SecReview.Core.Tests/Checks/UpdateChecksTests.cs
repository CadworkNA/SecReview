using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class UpdateChecksTests
{
    private static readonly DateTimeOffset Now = CheckTesting.Now;

    private static FakeProbes Updates(
        AutomaticUpdateMode mode = AutomaticUpdateMode.Scheduled,
        bool serviceAvailable = true,
        bool rebootRequired = false,
        DateTimeOffset? lastInstall = null,
        bool neverInstalled = false) => new()
        {
            WindowsUpdate = ProbeResult<WindowsUpdateStatus>.Ok(new WindowsUpdateStatus(
                mode,
                serviceAvailable,
                rebootRequired,
                LastSuccessfulSearch: Now.AddHours(-3),
                LastSuccessfulInstall: neverInstalled ? null : lastInstall ?? Now.AddDays(-2))),
        };

    // Automatic updates

    [TestMethod]
    public void Automatic_OnAndNotPaused_Passes()
    {
        CheckOutcome outcome = new AutomaticUpdatesCheck().Run(Updates());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        CollectionAssert.AreEqual(
            new[] { "Automatic updates: On (expected On) [ok]", "Security updates paused: No (expected No) [ok]" },
            outcome.Rows());
    }

    [TestMethod]
    [DataRow(AutomaticUpdateMode.Disabled)]
    [DataRow(AutomaticUpdateMode.NotifyBeforeDownload)]
    public void Automatic_OffOrOnlyNotifying_Fails(AutomaticUpdateMode mode)
    {
        CheckOutcome outcome = new AutomaticUpdatesCheck().Run(Updates(mode));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows does not install updates by itself.", outcome.Summary);
    }

    [TestMethod]
    [DataRow(AutomaticUpdateMode.NotifyBeforeInstall)]
    [DataRow(AutomaticUpdateMode.NotConfigured)]
    public void Automatic_DownloadingByItself_Passes(AutomaticUpdateMode mode)
    {
        Assert.AreEqual(CheckStatus.Pass, new AutomaticUpdatesCheck().Run(Updates(mode)).Status);
    }

    [TestMethod]
    public void Automatic_ServiceNotAvailable_Fails()
    {
        CheckOutcome outcome = new AutomaticUpdatesCheck().Run(Updates(serviceAvailable: false));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("The Windows Update service is not available.", outcome.Summary);
    }

    [TestMethod]
    public void Automatic_SecurityUpdatesPaused_Fails()
    {
        FakeProbes probes = Updates().WithRegistryNumber(
            RegistryRoot.LocalMachine, AutomaticUpdatesCheck.PauseStatusKey, AutomaticUpdatesCheck.QualityPaused, 1);

        CheckOutcome outcome = new AutomaticUpdatesCheck().Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Updates are paused.", outcome.Summary);
    }

    [TestMethod]
    public void Automatic_PausedInSettings_Fails_WithTheDate()
    {
        FakeProbes probes = Updates().WithRegistryValue(
            RegistryRoot.LocalMachine,
            AutomaticUpdatesCheck.SettingsKey,
            AutomaticUpdatesCheck.PauseExpiry,
            RegistryValue.FromText("2026-11-25T09:00:00Z"));

        CheckOutcome outcome = new AutomaticUpdatesCheck().Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Yes, until 25 November 2026", outcome.Findings[1].Found);
    }

    [TestMethod]
    [DataRow("2026-11-01T09:00:00Z")]
    [DataRow("not a date")]
    public void Automatic_APauseThatHasEnded_OrIsNotADate_DoesNotCount(string expiry)
    {
        FakeProbes probes = Updates().WithRegistryValue(
            RegistryRoot.LocalMachine, AutomaticUpdatesCheck.SettingsKey, AutomaticUpdatesCheck.PauseExpiry, RegistryValue.FromText(expiry));

        Assert.AreEqual(CheckStatus.Pass, new AutomaticUpdatesCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Automatic_OnlyFeatureUpdatesPaused_Passes_AndIsListed()
    {
        FakeProbes probes = Updates()
            .WithRegistryNumber(RegistryRoot.LocalMachine, AutomaticUpdatesCheck.PauseStatusKey, AutomaticUpdatesCheck.QualityPaused, 0)
            .WithRegistryNumber(RegistryRoot.LocalMachine, AutomaticUpdatesCheck.PauseStatusKey, AutomaticUpdatesCheck.FeaturePaused, 1);

        CheckOutcome outcome = new AutomaticUpdatesCheck().Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Feature updates paused: Yes [note]", outcome.Rows()[2]);
    }

    [TestMethod]
    public void Automatic_OffAndPaused_SaysBoth()
    {
        FakeProbes probes = Updates(AutomaticUpdateMode.Disabled).WithRegistryNumber(
            RegistryRoot.LocalMachine, AutomaticUpdatesCheck.PauseStatusKey, AutomaticUpdatesCheck.QualityPaused, 1);

        Assert.AreEqual("Automatic updates are off and updates are paused.", new AutomaticUpdatesCheck().Run(probes).Summary);
    }

    [TestMethod]
    public void Automatic_Unreadable_IsNeverAPass()
    {
        Assert.AreEqual(CheckStatus.Error, new AutomaticUpdatesCheck().Run(new FakeProbes()).Status);

        FakeProbes registryFails = Updates();
        registryFails.RegistryFailure = ProbeFailure.Failed("Reading the registry failed.");
        Assert.AreEqual(CheckStatus.Error, new AutomaticUpdatesCheck().Run(registryFails).Status);
    }

    // Recent updates

    [TestMethod]
    public void Recent_InstalledLately_Passes()
    {
        CheckOutcome outcome = new RecentUpdatesCheck().Run(Updates(lastInstall: Now.AddDays(-2)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Windows installed an update 2 days ago.", outcome.Summary);
    }

    [TestMethod]
    public void Recent_Today_AndExactlyAtTheLimit_Pass()
    {
        Assert.AreEqual("Windows installed an update today.", new RecentUpdatesCheck().Run(Updates(lastInstall: Now.AddHours(-5))).Summary);
        Assert.AreEqual(CheckStatus.Pass, new RecentUpdatesCheck().Run(Updates(lastInstall: Now - RecentUpdatesCheck.MaximumAge)).Status);
        Assert.AreEqual(CheckStatus.Pass, new RecentUpdatesCheck().Run(Updates(lastInstall: Now.AddHours(2))).Status, "a clock slightly off");
    }

    [TestMethod]
    public void Recent_LongAgo_Fails()
    {
        CheckOutcome outcome = new RecentUpdatesCheck().Run(Updates(lastInstall: Now.AddDays(-36)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows last installed an update 36 days ago.", outcome.Summary);
    }

    [TestMethod]
    public void Recent_NoDate_OrUnreadable_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new RecentUpdatesCheck().Run(Updates(neverInstalled: true)).Status);
        Assert.AreEqual(CheckStatus.Error, new RecentUpdatesCheck().Run(new FakeProbes()).Status);
    }

    // Restart

    private static FakeProbes Running(double days, bool rebootRequired = false)
    {
        FakeProbes probes = Updates(rebootRequired: rebootRequired);
        probes.Uptime = ProbeResult<TimeSpan>.Ok(TimeSpan.FromDays(days));
        return probes;
    }

    [TestMethod]
    public void Restart_Recent_Passes()
    {
        CheckOutcome outcome = new RestartCheck().Run(Running(3));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("This PC was restarted 3 days ago and no update is waiting.", outcome.Summary);
    }

    [TestMethod]
    public void Restart_LongRunning_Fails()
    {
        CheckOutcome outcome = new RestartCheck().Run(Running(15));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("This PC has not been restarted for 15 days.", outcome.Summary);
        Assert.AreEqual(CheckStatus.Pass, new RestartCheck().Run(Running(14)).Status, "exactly at the limit");
    }

    [TestMethod]
    public void Restart_UpdateWaiting_Fails_HoweverRecentTheLastRestart()
    {
        CheckOutcome outcome = new RestartCheck().Run(Running(0.1, rebootRequired: true));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("An update is waiting for a restart.", outcome.Summary);
    }

    [TestMethod]
    public void Restart_Unreadable_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new RestartCheck().Run(Updates()).Status, "uptime not readable");

        var noUpdates = new FakeProbes { Uptime = ProbeResult<TimeSpan>.Ok(TimeSpan.FromDays(1)) };
        Assert.AreEqual(CheckStatus.Error, new RestartCheck().Run(noUpdates).Status);
    }

    // Windows version

    private static readonly WindowsServicing List = new(
        Verified: new DateOnly(2026, 11, 11),
        Source: "https://example.test/list",
        Releases:
        [
            new WindowsRelease(30000, "Windows 11, version X", new DateOnly(2027, 10, 12), new DateOnly(2028, 10, 10)),
            new WindowsRelease(20000, "Windows 11, version W", new DateOnly(2026, 10, 13), new DateOnly(2027, 10, 12)),
        ],
        LongTerm: [new WindowsLongTermRelease(20000, "Windows 11 LTSC W", new DateOnly(2029, 10, 9), new DateOnly(2034, 10, 10))]);

    private static FakeProbes Windows(string? build, string? edition = "Professional", string? installation = "Client")
    {
        var probes = new FakeProbes();
        Set(WindowsSupportedCheck.BuildValue, build);
        Set(WindowsSupportedCheck.EditionValue, edition);
        Set(WindowsSupportedCheck.InstallationValue, installation);
        return probes;

        void Set(string name, string? value)
        {
            if (value is not null)
            {
                probes.WithRegistryValue(RegistryRoot.LocalMachine, WindowsSupportedCheck.VersionKey, name, RegistryValue.FromText(value));
            }
        }
    }

    private static CheckOutcome Supported(FakeProbes probes, DateTimeOffset? now = null) =>
        new WindowsSupportedCheck(List).Run(probes, now: now);

    [TestMethod]
    public void Supported_ACurrentRelease_Passes_WithItsEndDate()
    {
        CheckOutcome outcome = Supported(Windows("30000"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Windows 11, version X gets security updates until 12 October 2027.", outcome.Summary);
        Assert.AreEqual("https://example.test/list", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Supported_AnEndedRelease_Fails()
    {
        CheckOutcome outcome = Supported(Windows("20000"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows 11, version W stopped getting security updates on 13 October 2026.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("Enterprise")]
    [DataRow("Education")]
    [DataRow("IoTEnterprise")]
    public void Supported_EnterpriseEditions_GetTheLaterDate(string edition)
    {
        CheckOutcome outcome = Supported(Windows("20000", edition));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        StringAssert.Contains(outcome.Summary, "12 October 2027");
    }

    [TestMethod]
    public void Supported_AnUnknownEdition_GetsTheEarlierDate()
    {
        Assert.AreEqual(CheckStatus.Fail, Supported(Windows("20000", "SomethingNew")).Status);
        Assert.AreEqual(CheckStatus.Fail, Supported(Windows("20000", edition: null)).Status);
    }

    [TestMethod]
    public void Supported_LongTermEditions_HaveTheirOwnDates()
    {
        StringAssert.Contains(Supported(Windows("20000", "EnterpriseS")).Summary, "Windows 11 LTSC W gets security updates until 9 October 2029");
        StringAssert.Contains(Supported(Windows("20000", "IoTEnterpriseS")).Summary, "10 October 2034");
        Assert.AreEqual(CheckStatus.Error, Supported(Windows("30000", "EnterpriseS")).Status, "no long-term release with that build");
    }

    [TestMethod]
    public void Supported_TheLastDayStillCounts()
    {
        var lastDay = new DateTimeOffset(2026, 10, 13, 23, 0, 0, TimeSpan.Zero);

        Assert.AreEqual(CheckStatus.Pass, Supported(Windows("20000"), lastDay).Status);
        Assert.AreEqual(CheckStatus.Fail, Supported(Windows("20000"), lastDay.AddDays(1)).Status);
    }

    [TestMethod]
    public void Supported_ABuildNotOnTheList_IsCouldNotCheck_NeverAPass()
    {
        CheckOutcome newer = Supported(Windows("31000"));
        Assert.AreEqual(CheckStatus.Error, newer.Status);
        StringAssert.Contains(newer.Summary, "newer than SecReview's list of 11 November 2026");

        CheckOutcome other = Supported(Windows("25000"));
        Assert.AreEqual(CheckStatus.Error, other.Status);
        StringAssert.Contains(other.Summary, "not on SecReview's list");
    }

    [TestMethod]
    public void Supported_WindowsServer_DoesNotApply()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Supported(Windows("20000", "ServerDatacenter", "Server")).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Supported(Windows("20000", "ServerStandard", "Server Core")).Status);
    }

    [TestMethod]
    public void Supported_NoBuildNumber_OrUnreadable_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, Supported(Windows(build: null)).Status);
        Assert.AreEqual(CheckStatus.Error, Supported(Windows("not a number")).Status);
        Assert.AreEqual(
            CheckStatus.Error, Supported(new FakeProbes { RegistryFailure = ProbeFailure.Failed("Reading the registry failed.") }).Status);
    }

    [TestMethod]
    public void TheShippedList_IsWellFormed()
    {
        WindowsServicing shipped = WindowsServicing.Current;

        Assert.IsTrue(shipped.Releases.Count >= 5);
        Assert.AreEqual(shipped.Releases.Count, shipped.Releases.Select(r => r.Build).Distinct().Count(), "a build is listed twice");
        Assert.AreEqual(shipped.LongTerm.Count, shipped.LongTerm.Select(r => r.Build).Distinct().Count());
        Assert.IsTrue(shipped.Releases.All(r => r.Enterprise >= r.HomePro), "Enterprise never ends before Home and Pro");
        Assert.IsTrue(shipped.Releases.All(r => r.Name.StartsWith("Windows 1", StringComparison.Ordinal)));
        Assert.IsTrue(shipped.Source.StartsWith("https://learn.microsoft.com/", StringComparison.Ordinal));
        Assert.IsTrue(shipped.Verified > new DateOnly(2026, 1, 1));
    }
}
