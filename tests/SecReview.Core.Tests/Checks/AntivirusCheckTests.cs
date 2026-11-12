using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class AntivirusCheckTests
{
    private static readonly AntivirusCheck Check = new();

    private static FakeProbes With(params SecurityProduct[] products) =>
        new() { AntivirusProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(products) };

    private static SecurityProduct Product(string name, SecurityProductState state, bool current) =>
        new(name, state, SignaturesUpToDate: current, IsBuiltIn: false);

    [TestMethod]
    public void OnAndCurrent_Passes_AndNamesTheProduct()
    {
        CheckOutcome outcome = Check.Run(With(Product("Example Antivirus", SecurityProductState.On, current: true)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Example Antivirus is on and up to date.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "Example Antivirus: On, definitions current (expected On, definitions current) [ok]" },
            outcome.Rows());
    }

    [TestMethod]
    public void OnButDefinitionsOutOfDate_Fails_AndSaysSo()
    {
        CheckOutcome outcome = Check.Run(With(Product("Example Antivirus", SecurityProductState.On, current: false)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Example Antivirus is on, but its definitions are out of date.", outcome.Summary);
        StringAssert.Contains(outcome.Rows()[0], "On, definitions out of date");
    }

    [TestMethod]
    [DataRow(SecurityProductState.Off, "Example Antivirus is off.")]
    [DataRow(SecurityProductState.Snoozed, "Example Antivirus is paused.")]
    [DataRow(SecurityProductState.Expired, "Example Antivirus is expired.")]
    public void NotOn_Fails_WithTheState(SecurityProductState state, string summary)
    {
        CheckOutcome outcome = Check.Run(With(Product("Example Antivirus", state, current: true)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void NothingRegistered_Fails()
    {
        CheckOutcome outcome = Check.Run(With());

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("No antivirus is registered with Windows.", outcome.Summary);
        Assert.AreEqual(1, outcome.Findings.Count);
    }

    [TestMethod]
    public void OneProductActive_AnIdleSecondOne_IsANoteNotAProblem()
    {
        CheckOutcome outcome = Check.Run(With(
            Product("Built-in Antivirus", SecurityProductState.Off, current: true),
            Product("Example Antivirus", SecurityProductState.On, current: true)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Example Antivirus is on and up to date.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "Built-in Antivirus: Off [note]");
    }

    [TestMethod]
    public void DefinitionsStateUnknown_IsNotTakenAsCurrent()
    {
        CheckOutcome outcome = Check.Run(With(
            new SecurityProduct("Example Antivirus", SecurityProductState.On, SignaturesUpToDate: null, IsBuiltIn: false)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
    }

    [TestMethod]
    public void WindowsServer_IsCouldNotCheck_NotDoesNotApply_BecauseAServerNeedsAntivirusToo()
    {
        var probes = new FakeProbes
        {
            AntivirusProducts = ProbeFailure.NotSupported("Windows Server has no Security Center."),
        };

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        Assert.AreEqual("Windows Server has no Security Center.", outcome.Summary);
    }

    [TestMethod]
    public void SecurityCenterCannotBeRead_IsCouldNotCheck_NeverAPass()
    {
        var probes = new FakeProbes { AntivirusProducts = ProbeFailure.Failed("Asking Windows Security Center failed.") };

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        Assert.AreEqual("Asking Windows Security Center failed.", outcome.Summary);
    }
}
