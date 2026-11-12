using SecReview.Diagnostics;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Diagnostics;

[TestClass]
public sealed class ProbeDiagnosticsTests
{
    private const string VersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    private static (bool AllFine, Dictionary<string, string> Lines) Run(FakeProbes probes)
    {
        using var output = new StringWriter();
        bool allFine = ProbeDiagnostics.Run(probes.Build(), output);

        // Each line starts with the probe's name in a 20-character column.
        var lines = output.ToString()
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
            .ToDictionary(line => line[..Math.Min(20, line.Length)].TrimEnd(), line => line);
        return (allFine, lines);
    }

    private static FakeProbes AllWorking() => new FakeProbes
    {
        Firewall = ProbeResult<FirewallState>.Ok(FakeProbes.FirewallAll(enabled: true)),
        AntivirusProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
            [new SecurityProduct("Example Antivirus", SecurityProductState.On, SignaturesUpToDate: true)]),
        FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok([]),
        AccountPolicy = ProbeResult<AccountPolicy>.Ok(FakeProbes.DefaultAccountPolicy()),
        Power = ProbeResult<PowerSettings>.Ok(FakeProbes.Laptop(displayOffMinutes: 5)),
    }
    .WithRegistryValue(RegistryRoot.LocalMachine, VersionKey, "CurrentBuild", RegistryValue.FromText("19045"))
    .WithService("EventLog", ServiceStartType.Automatic, isRunning: true);

    [TestMethod]
    public void EveryProbeWorking_ReportsOkAndSucceeds()
    {
        (bool allFine, var lines) = Run(AllWorking());

        Assert.IsTrue(allFine);
        Assert.AreEqual(7, lines.Count);
        Assert.IsTrue(lines.Values.All(line => line.Contains(" ok ", StringComparison.Ordinal)));
        StringAssert.Contains(lines["registry"], "Windows build 19045");
        StringAssert.Contains(lines["services"], "EventLog: Automatic, running");
        StringAssert.Contains(lines["power plan"], "display off 5 min, sleep 30 min, password on wake");
        StringAssert.Contains(lines["power plan"], "battery: yes");
        StringAssert.Contains(lines["firewall"], "Public: on, blocks inbound");
        StringAssert.Contains(lines["antivirus products"], "Example Antivirus (On, definitions current)");
        StringAssert.Contains(lines["firewall products"], "none registered");
        StringAssert.Contains(lines["account policy"], "minimum length 0");
    }

    [TestMethod]
    public void AccessDenied_IsReportedAsNeedingAdministrator_AndIsNotAFailure()
    {
        FakeProbes probes = AllWorking();
        probes.AccountPolicy = ProbeFailure.AccessDenied();

        (bool allFine, var lines) = Run(probes);

        Assert.IsTrue(allFine);
        StringAssert.Contains(lines["account policy"], "needs administrator");
    }

    [TestMethod]
    public void NotSupported_IsReportedWithItsReason_AndIsNotAFailure()
    {
        FakeProbes probes = AllWorking();
        probes.AntivirusProducts = ProbeFailure.NotSupported("Not on this edition of Windows.");

        (bool allFine, var lines) = Run(probes);

        Assert.IsTrue(allFine);
        StringAssert.Contains(lines["antivirus products"], "not supported");
        StringAssert.Contains(lines["antivirus products"], "Not on this edition of Windows.");
    }

    [TestMethod]
    public void AMissingRegistryValueOrService_IsReportedAsNotFound_AndIsNotAFailure()
    {
        var probes = new FakeProbes
        {
            Firewall = ProbeResult<FirewallState>.Ok(FakeProbes.FirewallAll(enabled: true)),
            AntivirusProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok([]),
            FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok([]),
            AccountPolicy = ProbeResult<AccountPolicy>.Ok(FakeProbes.DefaultAccountPolicy()),
            Power = ProbeResult<PowerSettings>.Ok(FakeProbes.Laptop(displayOffMinutes: 5)),
        };

        (bool allFine, var lines) = Run(probes);

        Assert.IsTrue(allFine);
        StringAssert.Contains(lines["registry"], "not found");
        StringAssert.Contains(lines["services"], "not found");
    }

    [TestMethod]
    public void AFailedProbe_IsReportedAndFailsTheRun_ButTheOthersStillRun()
    {
        FakeProbes probes = AllWorking();
        probes.Firewall = ProbeFailure.Failed("Reading the firewall failed (0x80004005).");

        (bool allFine, var lines) = Run(probes);

        Assert.IsFalse(allFine);
        Assert.AreEqual(7, lines.Count);
        StringAssert.Contains(lines["firewall"], "FAILED");
        StringAssert.Contains(lines["firewall"], "0x80004005");
        StringAssert.Contains(lines["account policy"], " ok ");
    }

    [TestMethod]
    public void OutOfDateDefinitionsAndInactiveProducts_AreSpelledOut()
    {
        FakeProbes probes = AllWorking();
        probes.AntivirusProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
        [
            new SecurityProduct("First", SecurityProductState.Snoozed, SignaturesUpToDate: false),
            new SecurityProduct("Second", SecurityProductState.Off, SignaturesUpToDate: true),
        ]);

        (_, var lines) = Run(probes);

        StringAssert.Contains(lines["antivirus products"], "First (Snoozed, definitions out of date)");
        StringAssert.Contains(lines["antivirus products"], "Second (Off, definitions current)");
    }

    [TestMethod]
    public void FirewallProduct_IsListedWithoutDefinitions()
    {
        FakeProbes probes = AllWorking();
        probes.FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
            [new SecurityProduct("Example Firewall", SecurityProductState.On, SignaturesUpToDate: null)]);

        (_, var lines) = Run(probes);

        StringAssert.Contains(lines["firewall products"], "Example Firewall (On)");
        Assert.IsFalse(lines["firewall products"].Contains("definitions", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AccountPolicy_WithALockoutThreshold_SaysWhenAndForHowLong()
    {
        (_, var lines) = Run(AllWorking());

        StringAssert.Contains(lines["account policy"], "lockout after 10 failed sign-ins for 10 min");
    }

    [TestMethod]
    public void AccountPolicy_WithNoLockoutThreshold_SaysNoLockout_NotTheUnusedDuration()
    {
        FakeProbes probes = AllWorking();
        probes.AccountPolicy = ProbeResult<AccountPolicy>.Ok(
            FakeProbes.DefaultAccountPolicy() with { LockoutThreshold = 0 });

        (_, var lines) = Run(probes);

        StringAssert.Contains(lines["account policy"], "no lockout");
        Assert.IsFalse(lines["account policy"].Contains("10 min", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AReadingTheTestDidNotSetUp_FailsTheRun()
    {
        FakeProbes probes = AllWorking();
        probes.Power = new FakeProbes().Power;

        (bool allFine, var lines) = Run(probes);

        Assert.IsFalse(allFine);
        StringAssert.Contains(lines["power plan"], "Not set up in this test.");
    }

    [TestMethod]
    public void PowerPlanThatNeverTurnsTheDisplayOff_SaysNever()
    {
        FakeProbes probes = AllWorking();
        var never = new PowerSourceSettings(DisplayOff: null, Sleep: null, RequirePasswordOnWake: false);
        probes.Power = ProbeResult<PowerSettings>.Ok(new PowerSettings(never, never, HasBattery: false));

        (_, var lines) = Run(probes);

        StringAssert.Contains(lines["power plan"], "display off never, sleep never, no password on wake");
        StringAssert.Contains(lines["power plan"], "battery: no");
    }
}
