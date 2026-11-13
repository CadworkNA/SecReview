using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class StartupProgramsCheckTests
{
    private const string Run = StartupProgramsCheck.RunKey;
    private const string Folder = @"C:\ProgramData\" + StartupProgramsCheck.StartupFolder;

    private static readonly StartupProgramsCheck Check = new();

    [TestMethod]
    public void ProgramsInstalledTheUsualWay_Pass()
    {
        FakeProbes probes = Pc()
            .WithText(Run, "Example Agent", $@"""{Installed}"" --tray {Secret}")
            .WithText(StartupProgramsCheck.Run32Key, "Example Helper", $@"""{Installed}""");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 4 start-up programs are protected from change by standard users.", outcome.Summary);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    public void WindowsAlone_WithNoStartUpListAtAll_Passes()
    {
        CheckOutcome outcome = Check.Run(Pc());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 2 start-up programs are protected from change by standard users.", outcome.Summary);
    }

    [TestMethod]
    public void NothingSetToStart_PassesWithItsOwnWords()
    {
        FakeProbes probes = new FakeProbes().WithStandardWindows();

        Assert.AreEqual("No program is set to start for every user.", Check.Run(probes).Summary);
    }

    [TestMethod]
    public void AProgramStandardUsersCanChange_Fails_AndSaysWhereThePermissionsAreWrong()
    {
        FakeProbes probes = Pc().WithText(Run, "Example Agent", $"{Loose} --tray {Secret}");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 start-up program is not protected from change: Start-up entry: Example Agent.", outcome.Summary);
        CollectionAssert.Contains(
            outcome.Rows(),
            $@"Start-up entry: Example Agent: {Loose}: Authenticated Users can change C:\Tools (expected Only administrators can change it) [problem]");
        Assert.AreEqual($@"HKLM\{Run}", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    [DataRow(@"C:\Shared\Example Agent\agent.exe --tray", @"Written without quotes; Users can create C:\Shared\Example.exe, which Windows would run first")]
    [DataRow(@"\\server\share\agent.exe", "On a network location")]
    [DataRow(@"""C:\Gone\agent.exe""", "C:\\Gone\\agent.exe is missing and Authenticated Users can create it")]
    [DataRow(@"rundll32.exe C:\Tools\Example\lib.dll,Start", "C:\\Tools\\Example\\lib.dll: Authenticated Users can change C:\\Tools")]
    public void OtherWaysAStandardUserCouldDecideWhatStarts_Fail(string command, string found)
    {
        FakeProbes probes = Pc()
            .WithFile(@"C:\Shared\Example Agent\agent.exe", "made up")
            .WithAccess(@"C:\Shared", FakeAccess.UsersAdd)
            .WithAccessBelow(@"C:\Shared\Example Agent", FakeAccess.Protected)
            .WithFile(@"C:\Tools\Example\lib.dll", "made up")
            .WithText(Run, "Example Agent", command);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status, outcome.Summary);
        Assert.AreEqual(found, outcome.Findings[0].Found);
    }

    [TestMethod]
    public void AListStandardUsersCanWriteTo_Fails_WhateverIsInIt()
    {
        FakeProbes probes = Pc()
            .WithText(Run, "Example Agent", $@"""{Installed}""")
            .WithKeyAccess(RegistryRoot.LocalMachine, Run, FakeAccess.UsersAdd);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.Contains(
            outcome.Rows(),
            $@"Start-up list: Users can change HKLM\{Run} (expected Only administrators can change it) [problem]");
    }

    [TestMethod]
    public void WhatWindowsStartsAtSignIn_IsJudgedToo()
    {
        FakeProbes probes = Pc().WithText(StartupProgramsCheck.WinlogonKey, "Userinit", $@"C:\Windows\system32\userinit.exe,{Loose},");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Summary, "Windows sign-in: Userinit");
    }

    [TestMethod]
    public void AnEntryThatIsEachUsersOwn_OrLeftBehind_OrACommandLine_IsANote_NotAProblem()
    {
        FakeProbes probes = Pc()
            .WithText(Run, "Own copy", @"""%LOCALAPPDATA%\Example\agent.exe"" --tray")
            .WithText(Run, "Left behind", @"""C:\Program Files\Gone\agent.exe""")
            .WithText(Run, "Script", "cmd /c echo made up > nul & echo more");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        string[] rows = outcome.Rows();
        CollectionAssert.Contains(rows, "Start-up entry: Own copy: Each user's own copy; not judged [note]");
        CollectionAssert.Contains(rows, @"Start-up entry: Left behind: C:\Program Files\Gone\agent.exe is missing [note]");
        CollectionAssert.Contains(rows, "Start-up entry: Script: Runs a command line; only its first program was judged [note]");
    }

    [TestMethod]
    public void AProblemFromTheOrganisationsPolicy_IsMarkedAsManaged()
    {
        FakeProbes local = Pc().WithText(Run, "Example Agent", Loose);
        FakeProbes policy = Pc().WithText(StartupProgramsCheck.PolicyRunKey, "Example Agent", Loose);

        Assert.IsFalse(Check.Run(local).ManagedByPolicy);
        Assert.IsTrue(Check.Run(policy).ManagedByPolicy);
    }

    [TestMethod]
    public void TheStartUpFolderForAllUsers_FailsWhenUsersCanAddToItOrChangeAShortcut()
    {
        FakeProbes protectedFolder = Pc()
            .WithFile(Folder + @"\Example.lnk", "made up")
            .WithFile(Folder + @"\desktop.ini", "made up")
            .WithAccessBelow(@"C:\ProgramData\Microsoft", FakeAccess.Protected);
        FakeProbes openFolder = Pc()
            .WithFile(Folder + @"\Example.lnk", "made up")
            .WithAccessBelow(@"C:\ProgramData\Microsoft", FakeAccess.Protected)
            .WithAccess(Folder, FakeAccess.UsersAdd)
            .WithAccess(Folder + @"\Example.lnk", FakeAccess.Protected);
        FakeProbes openShortcut = Pc()
            .WithFile(Folder + @"\Example.lnk", "made up")
            .WithAccessBelow(@"C:\ProgramData\Microsoft", FakeAccess.Protected)
            .WithAccess(Folder + @"\Example.lnk", FakeAccess.UsersModify);

        CheckOutcome fine = Check.Run(protectedFolder);
        CheckOutcome folder = Check.Run(openFolder);
        CheckOutcome shortcut = Check.Run(openShortcut);

        Assert.AreEqual(CheckStatus.Pass, fine.Status, fine.Summary);
        CollectionAssert.Contains(fine.Rows(), "Start-up folder for all users: Where its shortcuts point is not read [note]");
        Assert.AreEqual(CheckStatus.Fail, folder.Status);
        StringAssert.Contains(folder.Findings[0].Found, "Users can add files to");
        Assert.AreEqual(CheckStatus.Fail, shortcut.Status);
        StringAssert.Contains(shortcut.Summary, "Start-up shortcut: Example.lnk");
    }

    [TestMethod]
    public void WhenTheListsCannotBeRead_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = Pc();
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");
        FakeProbes denied = Pc();
        denied.RegistryFailure = ProbeFailure.AccessDenied();

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
    }

    [TestMethod]
    public void PermissionsOnlyAnAdministratorCanRead_AreNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = Pc()
            .WithText(Run, "Example Agent", $@"""{Installed}""")
            .WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied());

        CheckOutcome ordinary = Check.Run(probes);
        CheckOutcome elevated = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.NeedsAdmin, ordinary.Status);
        Assert.AreEqual("No problem in 2 start-up programs; 1 more needs administrator rights to read.", ordinary.Summary);
        Assert.AreEqual(CheckStatus.Error, elevated.Status);
    }

    [TestMethod]
    public void AnEntryThatCannotBeUnderstood_IsCouldNotCheck_NotAPass()
    {
        FakeProbes probes = Pc()
            .WithText(Run, "Odd", @"relative\agent.exe")
            .WithRegistryValue(RegistryRoot.LocalMachine, Run, "Number", RegistryValue.FromNumber(1));

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.StartsWith(outcome.Summary, "No problem in 2 start-up programs; 2 could not be judged.");
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(StartupProgramsCheck.Id, Check.Definition.Id);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.AreEqual(CheckScope.Machine, Check.Definition.Scope);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }
}
