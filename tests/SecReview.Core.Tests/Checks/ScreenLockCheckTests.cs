using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class ScreenLockCheckTests
{
    private static readonly ScreenLockCheck Check = new();

    private static PowerSourceSettings Source(int? displayOff, int? sleep, bool passwordOnWake = true) => new(
        displayOff is { } d ? TimeSpan.FromMinutes(d) : null,
        sleep is { } s ? TimeSpan.FromMinutes(s) : null,
        passwordOnWake);

    private static FakeProbes Pc(
        PowerSourceSettings pluggedIn, PowerSourceSettings? onBattery = null, bool modernStandby = false) => new()
        {
            Power = ProbeResult<PowerSettings>.Ok(new PowerSettings(
                pluggedIn, onBattery ?? pluggedIn, HasBattery: onBattery is not null, modernStandby)),
        };

    private static FakeProbes WithScreenSaver(
        FakeProbes probes, string active = "1", string secure = "1", string timeoutSeconds = "600", string? program = @"C:\Windows\system32\scrnsave.scr")
    {
        Set("ScreenSaveActive", active);
        Set("ScreenSaverIsSecure", secure);
        Set("ScreenSaveTimeOut", timeoutSeconds);
        if (program is not null)
        {
            Set("SCRNSAVE.EXE", program);
        }

        return probes;

        void Set(string name, string value) =>
            probes.WithRegistryValue(RegistryRoot.CurrentUser, ScreenLockCheck.DesktopKey, name, RegistryValue.FromText(value));
    }

    private static FakeProbes WithInactivityLimit(FakeProbes probes, long seconds) => probes.WithRegistryNumber(
        RegistryRoot.LocalMachine, ScreenLockCheck.SystemPolicyKey, ScreenLockCheck.InactivityValue, seconds);

    [TestMethod]
    public void ReadsTheUsersOwnSettings_SoNeverRunsElevated()
    {
        Assert.AreEqual(CheckScope.User, Check.Definition.Scope);
    }

    [TestMethod]
    public void SleepWithSignIn_WithinTheLimit_Passes()
    {
        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: 5, sleep: 10)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("This PC locks after 10 min without use.", outcome.Summary);
        Assert.AreEqual("When idle: Locks after 10 min (sleep) (expected 15 min or less) [ok]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void ExactlyTheLimit_Passes_OneMinuteMore_Fails()
    {
        Assert.AreEqual(CheckStatus.Pass, Check.Run(Pc(Source(displayOff: null, sleep: 15))).Status);

        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: null, sleep: 16)));
        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("This PC locks only after 16 min without use.", outcome.Summary);
    }

    [TestMethod]
    public void NothingEverLocks_Fails()
    {
        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: null, sleep: null)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("This PC never locks by itself.", outcome.Summary);
        Assert.AreEqual("When idle: Never locks (expected 15 min or less) [problem]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void SleepWithoutSignInOnWake_DoesNotCount()
    {
        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: 5, sleep: 10, passwordOnWake: false)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.IsTrue(outcome.Rows().Contains("Sign-in when the PC wakes: Not required [note]"));
    }

    [TestMethod]
    public void TheDisplayTurningOff_AloneDoesNotLockAnOrdinaryPc()
    {
        Assert.AreEqual(CheckStatus.Fail, Check.Run(Pc(Source(displayOff: 5, sleep: null))).Status);
    }

    [TestMethod]
    public void OnAModernStandbyPc_TheDisplayTurningOffLocks()
    {
        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: 5, sleep: null), modernStandby: true));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("When idle: Locks after 5 min (display turns off) (expected 15 min or less) [ok]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void OnAModernStandbyPc_TheUsersSignInDelayIsAdded()
    {
        FakeProbes probes = Pc(Source(displayOff: 5, sleep: null), modernStandby: true)
            .WithRegistryNumber(RegistryRoot.CurrentUser, ScreenLockCheck.DesktopKey, ScreenLockCheck.DelayValue, 900);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("This PC locks only after 20 min without use.", outcome.Summary);
    }

    [TestMethod]
    public void OnAModernStandbyPc_WithoutSignInOnWake_TheDisplayTurningOffDoesNotCount()
    {
        Assert.AreEqual(
            CheckStatus.Fail,
            Check.Run(Pc(Source(displayOff: 5, sleep: null, passwordOnWake: false), modernStandby: true)).Status);
    }

    [TestMethod]
    public void ALaptop_MustLockOnBothPowerSources()
    {
        // Like many laptops: generous while plugged in, strict on battery.
        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: null, sleep: null), Source(displayOff: 3, sleep: 3)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("When plugged in, this PC never locks by itself.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "Plugged in: Never locks (expected 15 min or less) [problem]",
                "On battery: Locks after 3 min (sleep) (expected 15 min or less) [ok]",
            },
            outcome.Rows()[..2]);
    }

    [TestMethod]
    public void ALaptop_SlowOnBatteryOnly_SaysSo()
    {
        CheckOutcome outcome = Check.Run(Pc(Source(displayOff: 5, sleep: 10), Source(displayOff: 5, sleep: 30)));

        Assert.AreEqual("On battery, this PC locks only after 30 min without use.", outcome.Summary);
    }

    [TestMethod]
    public void ALaptop_SlowOnBoth_NamesBoth_OrOnceWhenTheSame()
    {
        Assert.AreEqual(
            "This PC locks only after 20 min without use when plugged in and locks only after 30 min without use on battery.",
            Check.Run(Pc(Source(null, 20), Source(null, 30))).Summary);
        Assert.AreEqual("This PC never locks by itself.", Check.Run(Pc(Source(null, null), Source(null, null))).Summary);
    }

    [TestMethod]
    public void ALaptop_ThatPasses_ReportsTheLongerTime()
    {
        Assert.AreEqual(
            "This PC locks after 10 min without use.", Check.Run(Pc(Source(null, 10), Source(null, 3))).Summary);
    }

    [TestMethod]
    public void AScreenSaverThatAsksForSignIn_Counts()
    {
        CheckOutcome outcome = Check.Run(WithScreenSaver(Pc(Source(displayOff: null, sleep: null))));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("When idle: Locks after 10 min (screen saver) (expected 15 min or less) [ok]", outcome.Rows()[0]);
        Assert.IsTrue(outcome.Rows().Contains("Screen saver that asks for sign-in: After 10 min [note]"));
    }

    [TestMethod]
    [DataRow("0", "1", "600", true, DisplayName = "switched off")]
    [DataRow("1", "0", "600", true, DisplayName = "does not ask for sign-in")]
    [DataRow("1", "1", "0", true, DisplayName = "no waiting time")]
    [DataRow("1", "1", "soon", true, DisplayName = "waiting time is not a number")]
    [DataRow("1", "1", "600", false, DisplayName = "no screen saver program set")]
    public void AScreenSaverThatCannotLock_DoesNotCount(string active, string secure, string timeout, bool hasProgram)
    {
        FakeProbes probes = WithScreenSaver(
            Pc(Source(displayOff: null, sleep: null)), active, secure, timeout, hasProgram ? "scrnsave.scr" : null);

        Assert.AreEqual(CheckStatus.Fail, Check.Run(probes).Status);
    }

    [TestMethod]
    public void AScreenSaverPolicy_WinsOverTheUsersOwnSetting()
    {
        FakeProbes probes = WithScreenSaver(Pc(Source(displayOff: null, sleep: null)), secure: "0")
            .WithRegistryValue(RegistryRoot.CurrentUser, ScreenLockCheck.DesktopPolicyKey, "ScreenSaverIsSecure", RegistryValue.FromText("1"))
            .WithRegistryNumber(RegistryRoot.CurrentUser, ScreenLockCheck.DesktopPolicyKey, "ScreenSaveTimeOut", 300);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("This PC locks after 5 min without use.", outcome.Summary);
    }

    [TestMethod]
    public void TheInactivityLimit_LocksOnItsOwn()
    {
        CheckOutcome outcome = Check.Run(WithInactivityLimit(Pc(Source(displayOff: null, sleep: null)), 900));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("When idle: Locks after 15 min (inactivity limit) (expected 15 min or less) [ok]", outcome.Rows()[0]);
        Assert.IsTrue(outcome.Rows().Contains("Inactivity limit: 15 min [note]"));
    }

    [TestMethod]
    public void WithAnInactivityLimit_TheDisplayTurningOffLocksToo()
    {
        CheckOutcome outcome = Check.Run(WithInactivityLimit(Pc(Source(displayOff: 5, sleep: null)), 3600));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("This PC locks after 5 min without use.", outcome.Summary);
    }

    [TestMethod]
    public void AnInactivityLimitOfZero_MeansNone()
    {
        CheckOutcome outcome = Check.Run(WithInactivityLimit(Pc(Source(displayOff: 5, sleep: null)), 0));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.IsTrue(outcome.Rows().Contains("Inactivity limit: Not set [note]"));
    }

    [TestMethod]
    public void TheEarliestWayToLock_IsTheOneReported()
    {
        FakeProbes probes = WithInactivityLimit(WithScreenSaver(Pc(Source(displayOff: null, sleep: 12)), timeoutSeconds: "120"), 600);

        Assert.AreEqual("When idle: Locks after 2 min (screen saver) (expected 15 min or less) [ok]", Check.Run(probes).Rows()[0]);
    }

    [TestMethod]
    public void Unreadable_IsNeverAPass()
    {
        Assert.AreEqual(CheckStatus.Error, Check.Run(new FakeProbes()).Status, "power settings");

        FakeProbes registryFails = Pc(Source(displayOff: 5, sleep: 10));
        registryFails.RegistryFailure = ProbeFailure.Failed("Reading the registry failed.");
        Assert.AreEqual(CheckStatus.Error, Check.Run(registryFails).Status, "registry");
    }
}
