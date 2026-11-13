using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class RegisteredComponentsCheckTests
{
    private const string First = "{11111111-1111-1111-1111-111111111111}";
    private const string Second = "{22222222-2222-2222-2222-222222222222}";
    private const string Third = "{33333333-3333-3333-3333-333333333333}";
    private const string Library = @"C:\Program Files\Example\lib.dll";
    private const string LooseLibrary = @"C:\Tools\Example\lib.dll";

    private static readonly RegisteredComponentsCheck Check = new();

    /// <summary>A PC with one product registered the usual way.</summary>
    private static FakeProbes Usual() => Pc()
        .WithFile(Library, "made up")
        .WithFile(LooseLibrary, "made up")
        .WithFile(@"C:\Windows\System32\example.dll", "made up")
        .AppPath("agent.exe", Installed)
        .InProcess(First, Library)
        .InProcess(Second, "example.dll")
        .OwnProcess(First, $@"""{Installed}"" -Embedding {Secret}");

    [TestMethod]
    public void ComponentsInstalledTheUsualWay_Pass()
    {
        CheckOutcome outcome = Check.Run(Usual());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 4 registered components are protected from change by standard users.", outcome.Summary);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    public void AComponentStandardUsersCanChange_Fails_AndIsReportedOnce_HoweverManyEntriesNameIt()
    {
        FakeProbes probes = Usual().InProcess(Second, LooseLibrary).InProcess(Third, LooseLibrary);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($"1 registered component is not protected from change: Component {Second}.", outcome.Summary);
        Assert.AreEqual(@"Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
        Assert.AreEqual($@"HKLM\{RegisteredComponentsCheck.ClassesKey}\{Second}\InprocServer32", outcome.Findings[0].Source);
    }

    [TestMethod]
    [DataRow(RegisteredComponentsCheck.AppPathsKey + @"\loose.exe", "", "App path: loose.exe")]
    [DataRow(RegisteredComponentsCheck.AppPaths32Key + @"\loose.exe", "", "App path: loose.exe")]
    [DataRow(RegisteredComponentsCheck.DebuggersKey + @"\example.exe", "Debugger", "Debugger for example.exe")]
    [DataRow(RegisteredComponentsCheck.Debuggers32Key + @"\example.exe", "Debugger", "Debugger for example.exe")]
    [DataRow(RegisteredComponentsCheck.PrintMonitorsKey + @"\Example Port", "Driver", "Print monitor: Example Port")]
    public void OtherThingsWindowsPicksUpByName_FailWhenStandardUsersCanChangeThem(string key, string value, string item)
    {
        FakeProbes probes = Usual()
            .WithText(RegisteredComponentsCheck.DebuggersKey + @"\fine.exe", "Debugger", $@"""{Installed}"" -p %ld")
            .WithText(RegisteredComponentsCheck.PrintMonitorsKey + @"\Local Port", "Driver", "example.dll")
            .WithText(key, value, Loose);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status, outcome.Summary);
        Assert.AreEqual($"1 registered component is not protected from change: {item}.", outcome.Summary);
        Assert.AreEqual(@"Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
        Assert.AreEqual($@"HKLM\{key}", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void LibrariesLoadedIntoEveryProgram_AreJudgedOneByOne()
    {
        FakeProbes fine = Usual().WithText(RegisteredComponentsCheck.WindowsKey, "AppInit_DLLs", @"C:\Windows\System32\example.dll, C:\Windows\explorer.exe");
        FakeProbes loose = Usual().WithText(RegisteredComponentsCheck.Windows32Key, "AppInit_DLLs", $@"example.dll {LooseLibrary}");
        FakeProbes none = Usual().WithText(RegisteredComponentsCheck.WindowsKey, "AppInit_DLLs", string.Empty);

        Assert.AreEqual(CheckStatus.Pass, Check.Run(fine).Status);
        Assert.AreEqual(CheckStatus.Pass, Check.Run(none).Status);
        CheckOutcome outcome = Check.Run(loose);
        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Summary, "Library loaded into every program");
    }

    [TestMethod]
    public void EntriesThatSufferFromTheSameFolder_AreOneRow_AndAllCounted()
    {
        FakeProbes probes = Usual()
            .WithFile(@"C:\Tools\Example\other.dll", "made up")
            .InProcess(Second, LooseLibrary)
            .InProcess(Third, @"C:\Tools\Example\other.dll")
            .AppPath("loose.exe", Loose);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("3 registered components are not protected from change.", outcome.Summary);
        Assert.AreEqual(1, outcome.Findings.Count(f => f.Status == FindingStatus.Problem), "one folder to fix");
        Assert.AreEqual("App path: loose.exe and 2 more", outcome.Findings[0].Item);
        Assert.AreEqual(@"Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void AComponentOnTheNetwork_Fails_WithoutNamingTheServer()
    {
        CheckOutcome outcome = Check.Run(Usual().OwnProcess(Third, @"\\server\share\agent.exe -Embedding"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("On a network location", outcome.Findings[0].Found);
        Assert.IsFalse(outcome.Everything().Contains(@"\\server", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(outcome.Everything().Contains("share", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void EntriesLeftBehind_AndEntriesInAUsersOwnFolders_AreCounted_NotListed()
    {
        FakeProbes probes = Usual()
            .InProcess(Third, @"C:\Program Files\Gone\lib.dll")
            .InProcess(Third, @"%ProgramFiles%\Example\gone32.dll", view32: true)
            .OwnProcess(Third, @"""%LOCALAPPDATA%\Example\agent.exe""");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        string[] rows = outcome.Rows();
        CollectionAssert.Contains(rows, "Left behind: 2 entries point to a file that is not there [note]");
        CollectionAssert.Contains(rows, "Each user's own: 1 entry points into the user's own folders; not judged [note]");
        Assert.IsFalse(outcome.Everything().Contains("Gone", StringComparison.Ordinal));
    }

    [TestMethod]
    public void A32BitComponent_IsLookedForWhere32BitProgramsAreInstalled()
    {
        FakeProbes probes = Usual()
            .WithFile(@"C:\Program Files (x86)\Example\lib.dll", "made up")
            .WithAccessBelow(@"C:\Program Files (x86)\Example", FakeAccess.UsersModify)
            .InProcess(Third, @"%ProgramFiles%\Example\lib.dll", view32: true);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(@"Users can change C:\Program Files (x86)\Example\lib.dll", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void AnEntryThatCannotBeUnderstood_IsCouldNotCheck_NotAPass()
    {
        CheckOutcome outcome = Check.Run(Usual().InProcess(Third, @"relative\lib.dll"));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "1 could not be judged");
    }

    [TestMethod]
    public void MoreComponentsThanItReads_IsCouldNotCheck_NotAPartialAnswer()
    {
        FakeProbes probes = Usual();
        for (int number = 0; number <= RegisteredComponentsCheck.MaximumClasses; number++)
        {
            probes.WithRegistryKey(RegistryRoot.LocalMachine, $@"{RegisteredComponentsCheck.Classes32Key}\{{{number:D8}-0000-0000-0000-000000000000}}");
        }

        // Run directly: the damaged copies of a PC this size are not worth their time.
        CheckOutcome outcome = Check.Run(new CheckContext(probes.Build(), TimeProvider.System, IsElevated: false, CancellationToken.None));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "More than 60000 components");
    }

    [TestMethod]
    public void NothingRegistered_PassesWithItsOwnWords()
    {
        FakeProbes probes = new FakeProbes().WithStandardWindows();

        Assert.AreEqual("No components are registered for the whole PC.", Check.Run(probes).Summary);
    }

    [TestMethod]
    public void WhenTheListsCannotBeRead_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = Usual();
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");
        FakeProbes denied = Usual();
        denied.RegistryFailure = ProbeFailure.AccessDenied();

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
    }

    [TestMethod]
    public void PermissionsOnlyAnAdministratorCanRead_AreNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = Usual().WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(probes, elevated: true).Status);
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(RegisteredComponentsCheck.Id, Check.Definition.Id);
        Assert.AreEqual(Severity.Medium, Check.Definition.Severity);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }
}
