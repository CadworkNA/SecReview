using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain.Trust;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class DefenderExclusionsCheckTests
{
    private static readonly DefenderExclusionsCheck Check = new();

    private static FakeProbes With(string kind, string name, FakeProbes? probes = null, string key = DefenderExclusionsCheck.LocalKey) =>
        (probes ?? new FakeProbes()).WithRegistryNumber(RegistryRoot.LocalMachine, $@"{key}\{kind}", name, 0);

    [TestMethod]
    public void TheCheck_IsAnsweredOnlyByAnElevatedScan_OfThePc()
    {
        Assert.AreEqual(AdminNeed.Yes, Check.Definition.NeedsAdmin);
        Assert.AreEqual(CheckScope.Machine, Check.Definition.Scope);

        // Not elevated, the runner never asks: "needs administrator", not "none".
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(new FakeProbes(), elevated: false).Status);
    }

    [TestMethod]
    public void WhenWindowsRefusesTheList_TheAnswerIsNeedsAdministrator_NotNone()
    {
        var probes = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied() };

        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(probes, elevated: true).Status);
    }

    [TestMethod]
    public void NoExclusions_Pass()
    {
        CheckOutcome outcome = Check.Run(new FakeProbes(), elevated: true);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Microsoft Defender has no exclusions.", outcome.Summary);
    }

    [TestMethod]
    [DataRow(@"C:\", "A whole drive is not scanned")]
    [DataRow("D:", "A whole drive is not scanned")]
    [DataRow(@"C:\Users", "Folders a user's programs can write to are not scanned")]
    [DataRow(@"C:\Users\someone\source\repos", "Folders a user's programs can write to are not scanned")]
    [DataRow(@"C:\Users\someone\Downloads\*", "Folders a user's programs can write to are not scanned")]
    [DataRow(@"%USERPROFILE%\.nuget", "Folders a user's programs can write to are not scanned")]
    [DataRow(@"C:\Windows\Temp", "A temporary folder is not scanned")]
    [DataRow(@"D:\Temp\build", "A temporary folder is not scanned")]
    public void AnExclusionThatIsTooWide_Fails_AndSaysWhy(string path, string why)
    {
        CheckOutcome outcome = Check.Run(With("Paths", path), elevated: true);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Microsoft Defender skips a place where downloaded code lands.", outcome.Summary);
        Assert.AreEqual(why, outcome.Findings[0].Found);
        Assert.IsFalse(outcome.ManagedByPolicy);
    }

    [TestMethod]
    [DataRow(".exe")]
    [DataRow("ps1")]
    [DataRow("*.js")]
    [DataRow("DLL")]
    public void AnExcludedFileTypeThatRuns_Fails(string extension)
    {
        CheckOutcome outcome = Check.Run(With("Extensions", extension), elevated: true);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Files of this type can run", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void NarrowExclusions_AreListed_NotFailed()
    {
        FakeProbes probes = With("Paths", @"D:\VMs\disk.vhdx", With("Extensions", ".vhdx", With("Processes", @"C:\Program Files\Tool\tool.exe")));

        CheckOutcome outcome = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Microsoft Defender has 3 exclusions; none covers a drive, user folders or files that run.", outcome.Summary);
        Assert.AreEqual(3, outcome.Findings.Count(f => f.Status == FindingStatus.Note));
    }

    [TestMethod]
    public void ExclusionsSetByPolicy_Count_AndAreMarkedAsManaged()
    {
        CheckOutcome wide = Check.Run(With("Paths", @"C:\", key: DefenderExclusionsCheck.PolicyKey), elevated: true);
        Assert.AreEqual(CheckStatus.Fail, wide.Status);
        Assert.IsTrue(wide.ManagedByPolicy);

        CheckOutcome narrow = Check.Run(With("Paths", @"D:\Data\db", key: DefenderExclusionsCheck.PolicyKey), elevated: true);
        Assert.AreEqual("Not scanned (set by your organisation)", narrow.Findings[0].Found);
    }

    [TestMethod]
    public void SeveralProblems_AreCounted_AndManyNotesAreCutShort()
    {
        CheckOutcome two = Check.Run(With("Paths", @"C:\", With("Extensions", "exe")), elevated: true);
        Assert.AreEqual("Microsoft Defender skips 2 places or file types where downloaded code lands.", two.Summary);

        var many = new FakeProbes();
        for (int i = 0; i < 13; i++)
        {
            With("Paths", $@"D:\Data\set{i}", many);
        }

        CheckOutcome outcome = Check.Run(many, elevated: true);
        Assert.AreEqual(11, outcome.Findings.Count);
        Assert.AreEqual("More exclusions: 3 more [note]", outcome.Rows()[^1]);
    }
}
