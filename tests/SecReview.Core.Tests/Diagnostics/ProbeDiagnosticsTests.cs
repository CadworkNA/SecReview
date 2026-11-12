using SecReview.Diagnostics;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Diagnostics;

[TestClass]
public sealed class ProbeDiagnosticsTests
{
    private static (bool AllFine, string[] Lines) Run(FakeProbes probes)
    {
        using var output = new StringWriter();
        bool allFine = ProbeDiagnostics.Run(probes.Build(), output);
        return (allFine, output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
    }

    private static FakeProbes AllWorking() => new()
    {
        Firewall = ProbeResult<FirewallState>.Ok(FakeProbes.FirewallAll(enabled: true)),
        AntivirusProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
            [new SecurityProduct("Example Antivirus", SecurityProductState.On, SignaturesUpToDate: true)]),
        FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok([]),
        AccountPolicy = ProbeResult<AccountPolicy>.Ok(FakeProbes.DefaultAccountPolicy()),
    };

    [TestMethod]
    public void EveryProbeWorking_ReportsOkAndSucceeds()
    {
        (bool allFine, string[] lines) = Run(AllWorking());

        Assert.IsTrue(allFine);
        Assert.AreEqual(4, lines.Length);
        Assert.IsTrue(lines.All(line => line.Contains(" ok ", StringComparison.Ordinal)));
        StringAssert.Contains(lines[0], "Public: on, blocks inbound");
        StringAssert.Contains(lines[1], "Example Antivirus (On, definitions current)");
        StringAssert.Contains(lines[2], "none registered");
        StringAssert.Contains(lines[3], "minimum length 0");
    }

    [TestMethod]
    public void AccessDenied_IsReportedAsNeedingAdministrator_AndIsNotAFailure()
    {
        FakeProbes probes = AllWorking();
        probes.AccountPolicy = ProbeFailure.AccessDenied();

        (bool allFine, string[] lines) = Run(probes);

        Assert.IsTrue(allFine);
        StringAssert.Contains(lines[3], "needs administrator");
    }

    [TestMethod]
    public void NotSupported_IsReportedWithItsReason_AndIsNotAFailure()
    {
        FakeProbes probes = AllWorking();
        probes.AntivirusProducts = ProbeFailure.NotSupported("Not on this edition of Windows.");

        (bool allFine, string[] lines) = Run(probes);

        Assert.IsTrue(allFine);
        StringAssert.Contains(lines[1], "not supported");
        StringAssert.Contains(lines[1], "Not on this edition of Windows.");
    }

    [TestMethod]
    public void AFailedProbe_IsReportedAndFailsTheRun_ButTheOthersStillRun()
    {
        FakeProbes probes = AllWorking();
        probes.Firewall = ProbeFailure.Failed("Reading the firewall failed (0x80004005).");

        (bool allFine, string[] lines) = Run(probes);

        Assert.IsFalse(allFine);
        Assert.AreEqual(4, lines.Length);
        StringAssert.Contains(lines[0], "FAILED");
        StringAssert.Contains(lines[0], "0x80004005");
        StringAssert.Contains(lines[3], " ok ");
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

        (_, string[] lines) = Run(probes);

        StringAssert.Contains(lines[1], "First (Snoozed, definitions out of date)");
        StringAssert.Contains(lines[1], "Second (Off, definitions current)");
    }
}
