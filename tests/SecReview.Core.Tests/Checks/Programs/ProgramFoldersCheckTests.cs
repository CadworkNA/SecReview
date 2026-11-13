using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class ProgramFoldersCheckTests
{
    private static readonly ProgramFoldersCheck Check = new();

    private static readonly FakeAccess Open = FakeAccess.Protected.Allow(FakeAccess.AuthenticatedUsers, FakeAccess.Level.Modify);

    /// <summary>Windows as it sets itself up, with one program installed the usual way.</summary>
    private static FakeProbes Tidy() => new FakeProbes().WithStandardWindows().WithFile(Installed, "made up");

    [TestMethod]
    public void ProgramsUnderProgramFiles_AndNothingElse_Pass()
    {
        CheckOutcome outcome = Check.Run(Tidy());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 3 program folders are protected from change by standard users.", outcome.Summary);
    }

    [TestMethod]
    public void AFolderUnderProgramFilesThatStandardUsersCanChange_Fails()
    {
        FakeProbes probes = Tidy().WithAccessBelow(@"C:\Program Files\Example", FakeAccess.UsersModify);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(@"1 program folder is not protected from change: Program folder: C:\Program Files\Example.", outcome.Summary);
        Assert.AreEqual(@"Users can add files to C:\Program Files\Example", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void AFolderAtTheTopOfTheDrive_WithPrograms_ThatStandardUsersCanChange_Fails()
    {
        FakeProbes probes = Tidy().WithFile(Loose, "made up").WithAccessBelow(@"C:\Tools", Open);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.Contains(
            outcome.Rows(),
            @"Folder with programs: C:\Tools: Authenticated Users can change C:\Tools (expected Only administrators can change it) [problem]");
    }

    [TestMethod]
    public void AnOpenFolderWithoutPrograms_AndAProtectedFolderWithPrograms_AreNotItsBusiness()
    {
        FakeProbes probes = Tidy()
            .WithFile(@"C:\Data\notes\list.txt", "made up")
            .WithAccessBelow(@"C:\Data", Open)
            .WithFile(@"C:\Apps\Example\agent.exe", "made up")
            .WithAccessBelow(@"C:\Apps", FakeAccess.Protected);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.IsFalse(outcome.Everything().Contains(@"C:\Data", StringComparison.Ordinal));
        Assert.IsFalse(outcome.Everything().Contains(@"C:\Apps", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AnOpenFolderTooDeepToLookThrough_IsSaidNotToHaveBeenLookedThroughInFull()
    {
        FakeProbes probes = Tidy()
            .WithFile(@"C:\Deep\one\two\three\four\agent.exe", "made up")
            .WithAccessBelow(@"C:\Deep", Open);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        CollectionAssert.Contains(
            outcome.Rows(),
            @"Folder: C:\Deep: Authenticated Users can change C:\Deep; it was not looked through in full for programs [note]");
    }

    [TestMethod]
    public void TheTopOfTheDrive_WhereStandardUsersCanAddFiles_Fails()
    {
        FakeProbes probes = Tidy().WithAccess(@"C:\", FakeAccess.UsersAdd);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Summary, "The top of drive C:");
    }

    [TestMethod]
    public void ALinkAtTheTop_IsNotFollowed()
    {
        FakeProbes probes = Tidy().WithFile(@"C:\Linked\agent.exe", "made up").WithAccessBelow(@"C:\Linked", Open).WithLink(@"C:\Linked");

        Assert.AreEqual(CheckStatus.Pass, Check.Run(probes).Status);
    }

    [TestMethod]
    public void AFolderOnlyAnAdministratorCanRead_IsNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = Tidy()
            .WithFolder(@"C:\Program Files\Closed")
            .WithAccessFailure(@"C:\Program Files\Closed", ProbeFailure.AccessDenied());

        CheckOutcome ordinary = Check.Run(probes);
        CheckOutcome elevated = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.NeedsAdmin, ordinary.Status);
        Assert.AreEqual("No problem in 3 program folders; 1 more needs administrator rights to read.", ordinary.Summary);
        Assert.AreEqual(CheckStatus.Error, elevated.Status);
    }

    [TestMethod]
    public void WhenTheFoldersCannotBeListed_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = Tidy();
        failed.FilesFailure = ProbeFailure.Failed("The disk reported an error.");
        FakeProbes denied = Tidy();
        denied.FilesFailure = ProbeFailure.AccessDenied();
        FakeProbes unlistable = Tidy()
            .WithFile(Loose, "made up")
            .WithAccessBelow(@"C:\Tools", Open)
            .WithFolderFailure(@"C:\Tools", ProbeFailure.Failed("The disk reported an error."));

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(unlistable).Status, "an open folder that could not be listed is not known to be harmless");
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(ProgramFoldersCheck.Id, Check.Definition.Id);
        Assert.AreEqual(Severity.Medium, Check.Definition.Severity);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }
}
