using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class SearchPathCheckTests
{
    private const string Usual = @"%SystemRoot%\system32;%SystemRoot%;C:\Program Files\Example";

    private static readonly SearchPathCheck Check = new();

    private static FakeProbes WithPath(string path) => Pc().WithText(PersistentEnvironment.MachineKey, "Path", path);

    [TestMethod]
    public void FoldersOnlyAdministratorsCanChange_Pass()
    {
        CheckOutcome outcome = Check.Run(WithPath(Usual + @";C:\PROGRAM FILES\EXAMPLE;"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 3 search path folders are protected from change by standard users.", outcome.Summary);
    }

    [TestMethod]
    public void NoSearchPathAtAll_PassesWithItsOwnWords()
    {
        Assert.AreEqual("The PC's search path is empty.", Check.Run(Pc()).Summary);
    }

    [TestMethod]
    [DataRow(@"C:\Tools\Example", @"C:\Tools\Example: Authenticated Users can change C:\Tools", DisplayName = "a folder users can change")]
    [DataRow(@"C:\Shared\bin", @"Users can add files to C:\Shared\bin", DisplayName = "a folder users can add files to")]
    [DataRow(@"C:\Gone\bin", @"C:\Gone\bin is missing and Authenticated Users can create it", DisplayName = "a missing folder users can create")]
    [DataRow(@"tools\bin", "Not a complete path: it is looked for from wherever a program is started", DisplayName = "a relative entry")]
    [DataRow(@"\\server\share\bin", "On a network location", DisplayName = "a network folder")]
    public void AFolderWhereAStandardUserCouldPutAProgram_Fails(string entry, string found)
    {
        FakeProbes probes = WithPath($"{Usual};{entry}")
            .WithAccess(@"C:\Shared", FakeAccess.Protected)
            .WithAccess(@"C:\Shared\bin", FakeAccess.UsersAdd);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status, outcome.Summary);
        Assert.AreEqual(found, outcome.Findings[0].Found);
        StringAssert.StartsWith(outcome.Summary, "1 search path folder is not protected from change: Search path: ");
        Assert.IsFalse(outcome.Everything().Contains("server", StringComparison.OrdinalIgnoreCase), "where on the network is not kept");
    }

    [TestMethod]
    public void TheVariablesThemselvesBeingWritable_Fails()
    {
        FakeProbes probes = WithPath(Usual).WithKeyAccess(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, FakeAccess.UsersAdd);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Summary, "The PC's environment variables");
    }

    [TestMethod]
    public void AMissingFolderNobodyCanCreate_AndAFolderThatIsEachUsersOwn_AreNotes()
    {
        CheckOutcome outcome = Check.Run(WithPath($@"{Usual};C:\Program Files\Gone;%USERPROFILE%\bin"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        string[] rows = outcome.Rows();
        CollectionAssert.Contains(rows, @"Search path: C:\Program Files\Gone: C:\Program Files\Gone is missing [note]");
        CollectionAssert.Contains(rows, @"Search path: %USERPROFILE%\bin: Each user's own folder; not judged [note]");
    }

    [TestMethod]
    public void AnEntryWithAVariableThatIsNotSet_IsCouldNotCheck()
    {
        CheckOutcome outcome = Check.Run(WithPath($@"{Usual};%NOT_SET_ANYWHERE%\bin"));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "1 could not be judged");
    }

    [TestMethod]
    public void WhenThePathCannotBeRead_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = WithPath(Usual);
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");
        FakeProbes denied = WithPath(Usual);
        denied.RegistryFailure = ProbeFailure.AccessDenied();

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
    }

    [TestMethod]
    public void PermissionsOnlyAnAdministratorCanRead_AreNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = WithPath(Usual).WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(probes, elevated: true).Status);
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(SearchPathCheck.Id, Check.Definition.Id);
        Assert.AreEqual(Severity.High, Check.Definition.Severity);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }
}
