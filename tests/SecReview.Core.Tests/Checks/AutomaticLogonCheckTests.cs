using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class AutomaticLogonCheckTests
{
    private const string Key = AutomaticLogonCheck.WinlogonKey;
    private static readonly AutomaticLogonCheck Check = new();

    private static FakeProbes Winlogon(params (string Name, RegistryValue Value)[] values)
    {
        // A value that is always there on real Windows, so the key exists.
        var probes = new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, Key, "Shell", RegistryValue.FromText("explorer.exe"));
        foreach ((string name, RegistryValue value) in values)
        {
            probes.WithRegistryValue(RegistryRoot.LocalMachine, Key, name, value);
        }

        return probes;
    }

    [TestMethod]
    public void NothingConfigured_Passes()
    {
        CheckOutcome outcome = Check.Run(Winlogon());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Automatic sign-in is off.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "Automatic sign-in: Off (expected Off) [ok]",
                "Password kept in the registry: No (expected No) [ok]",
            },
            outcome.Rows());
    }

    [TestMethod]
    [DataRow("0")]
    [DataRow("")]
    [DataRow("no")]
    public void SwitchedOff_Passes(string value)
    {
        CheckOutcome outcome = Check.Run(Winlogon(("AutoAdminLogon", RegistryValue.FromText(value))));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
    }

    [TestMethod]
    public void SwitchedOn_Fails()
    {
        CheckOutcome outcome = Check.Run(Winlogon(("AutoAdminLogon", RegistryValue.FromText("1"))));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows signs in automatically at start-up.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "Automatic sign-in: On (expected Off) [problem]");
    }

    [TestMethod]
    public void SwitchedOnAsANumber_Fails()
    {
        CheckOutcome outcome = Check.Run(Winlogon(("AutoAdminLogon", RegistryValue.FromNumber(1))));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
    }

    [TestMethod]
    public void SwitchedOnWithAStoredPassword_ReportsBoth_WithoutThePassword()
    {
        CheckOutcome outcome = Check.Run(Winlogon(
            ("AutoAdminLogon", RegistryValue.FromText("1")),
            ("DefaultPassword", RegistryValue.FromText("hunter2-not-real"))));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.Contains(outcome.Rows(), "Password kept in the registry: Yes (expected No) [problem]");

        string everything = outcome.Summary + string.Join("|", outcome.Findings.Select(f => f.Found + f.Expected + f.Item + f.Source));
        Assert.IsFalse(everything.Contains("hunter2", StringComparison.Ordinal), "the password must never appear in a result");
    }

    [TestMethod]
    public void SwitchedOff_ButAPasswordIsStillStored_Fails()
    {
        CheckOutcome outcome = Check.Run(Winlogon(
            ("AutoAdminLogon", RegistryValue.FromText("0")),
            ("defaultpassword", RegistryValue.FromText("left-over-not-real"))));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(
            "Automatic sign-in is off, but a sign-in password is still stored in the registry.", outcome.Summary);
    }

    [TestMethod]
    public void FindingsNameWhereTheSettingLives()
    {
        CheckOutcome outcome = Check.Run(Winlogon());

        Assert.AreEqual(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon", outcome.Findings[0].Source);
    }

    [TestMethod]
    [DataRow(ProbeStatus.AccessDenied, CheckStatus.NeedsAdmin)]
    [DataRow(ProbeStatus.Failed, CheckStatus.Error)]
    public void RegistryCannotBeRead_IsNeverAPass(ProbeStatus probeStatus, CheckStatus expected)
    {
        var probes = new FakeProbes { RegistryFailure = FirewallCheckTests.FailureOf(probeStatus) };

        Assert.AreEqual(expected, Check.Run(probes).Status);
    }
}
