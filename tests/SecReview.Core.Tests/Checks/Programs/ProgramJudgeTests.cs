using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class ProgramJudgeTests
{
    private const string Program = @"C:\Program Files\Example\agent.exe";
    private const string Tool = @"C:\Tools\Example\agent.exe";

    /// <summary>A PC as Windows sets it up, with one program installed the usual way.</summary>
    private static FakeProbes Pc() => new FakeProbes().WithStandardWindows().WithFile(Program, "made up");

    private static ProgramJudge Judge(FakeProbes probes) => new(probes.Build().Access);

    private static MachineContext Machine(FakeProbes probes)
    {
        Assert.IsNull(MachineContext.Load(probes.Build(), out MachineContext machine));
        return machine;
    }

    private static CommandVerdict Command(FakeProbes probes, string command, CommandForm form = CommandForm.CommandLine) =>
        Judge(probes).Command(ProgramReference.Parse(command, form, Machine(probes)));

    [TestMethod]
    public void AProgramInstalledTheUsualWay_IsProtected()
    {
        Verdict verdict = Judge(Pc()).File(Program);

        Assert.AreEqual(VerdictKind.Protected, verdict.Kind);
        Assert.IsFalse(verdict.IsProblem);
        Assert.AreEqual("Protected", verdict.Found);
    }

    [TestMethod]
    public void AFileUsersCanWrite_IsChangeable_AndSaysWhoAndWhere()
    {
        Verdict verdict = Judge(Pc().WithAccess(Program, FakeAccess.UsersModify)).File(Program);

        Assert.AreEqual(VerdictKind.Changeable, verdict.Kind);
        Assert.AreEqual("Users", verdict.Who);
        Assert.AreEqual(Program, verdict.Where);
        Assert.AreEqual($"Users can change {Program}", verdict.Found);
    }

    [TestMethod]
    public void AFolderMadeAtTheTopOfTheDrive_WithWhatItInherits_MakesEverythingInItChangeable()
    {
        FakeProbes probes = Pc()
            .WithFile(Tool, "made up")
            .WithAccessBelow(@"C:\Tools", FakeAccess.Protected.Allow(FakeAccess.AuthenticatedUsers, FakeAccess.Level.Modify));

        Verdict verdict = Judge(probes).File(Tool);

        Assert.AreEqual(VerdictKind.Changeable, verdict.Kind);
        Assert.AreEqual("Authenticated Users", verdict.Who);
        Assert.AreEqual(@"C:\Tools", verdict.Where, "the highest folder that lets them is the one to fix");
        Assert.AreEqual($@"{Tool}: Authenticated Users can change C:\Tools", verdict.Found);
    }

    [TestMethod]
    public void AFolderAboveWhosePermissionsUsersCanRewrite_MakesTheProgramChangeable_ThoughItsOwnAreFine()
    {
        FakeProbes probes = Pc()
            .WithFile(Tool, "made up")
            .WithAccess(@"C:\Tools", FakeAccess.EveryoneFull)
            .WithAccessBelow(@"C:\Tools\Example", FakeAccess.Protected);

        Verdict verdict = Judge(probes).File(Tool);

        Assert.AreEqual(VerdictKind.Changeable, verdict.Kind);
        Assert.AreEqual("Everyone", verdict.Who);
        Assert.AreEqual(@"C:\Tools", verdict.Where);
    }

    [TestMethod]
    public void AFolderWhereUsersCanOnlyAddFiles_IsAProblemOfItsOwn_BecauseAFileBesideAProgramIsLoaded()
    {
        FakeProbes probes = Pc()
            .WithFile(@"C:\ProgramData\Example\agent.exe", "made up")
            .WithAccess(@"C:\ProgramData\Example", FakeAccess.UsersAdd)
            .WithAccess(@"C:\ProgramData\Example\agent.exe", FakeAccess.Protected);

        Verdict verdict = Judge(probes).File(@"C:\ProgramData\Example\agent.exe");

        Assert.AreEqual(VerdictKind.AddBeside, verdict.Kind);
        Assert.IsTrue(verdict.IsProblem);
        Assert.AreEqual(@"C:\ProgramData\Example\agent.exe: Users can add files to C:\ProgramData\Example", verdict.Found);
    }

    [TestMethod]
    public void WhatWindowsAllowsAtTheTopOfTheDriveAndInTheSharedDataFolder_IsNotByItselfAProblemForWhatIsProtectedBelow()
    {
        FakeProbes probes = Pc()
            .WithFile(@"C:\ProgramData\Example\agent.exe", "made up")
            .WithAccessBelow(@"C:\ProgramData\Example", FakeAccess.Protected);

        Assert.AreEqual(VerdictKind.Protected, Judge(probes).File(@"C:\ProgramData\Example\agent.exe").Kind);
        Assert.AreEqual(VerdictKind.Protected, Judge(probes).File(Program).Kind);
    }

    [TestMethod]
    public void AMissingProgram_IsOnlyAProblem_WhereAStandardUserCouldPutOneThere()
    {
        FakeProbes probes = Pc();

        Verdict underProgramFiles = Judge(probes).File(@"C:\Program Files\Example\gone.exe");
        Verdict inMissingFolder = Judge(probes).File(@"C:\Program Files\Gone\agent.exe");
        Verdict atTheTop = Judge(probes).File(@"C:\Gone\agent.exe");
        Verdict inSharedData = Judge(probes).File(@"C:\ProgramData\gone.exe");

        Assert.AreEqual(VerdictKind.Missing, underProgramFiles.Kind);
        Assert.IsFalse(underProgramFiles.IsProblem);
        Assert.AreEqual(VerdictKind.Missing, inMissingFolder.Kind);
        Assert.AreEqual(VerdictKind.MissingCreatable, atTheTop.Kind, "users may create folders at the top of the drive");
        Assert.AreEqual("Authenticated Users", atTheTop.Who);
        Assert.AreEqual(@"C:\Gone\agent.exe is missing and Authenticated Users can create it", atTheTop.Found);
        Assert.AreEqual(VerdictKind.MissingCreatable, inSharedData.Kind);
        Assert.IsTrue(inSharedData.IsProblem);
    }

    [TestMethod]
    public void PermissionsThatCannotBeRead_AreUnknown_NeverProtected()
    {
        Verdict denied = Judge(Pc().WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied())).File(Program);
        Verdict failed = Judge(Pc().WithAccessFailure(Program, ProbeFailure.Failed("The disk reported an error."))).File(Program);
        Verdict notSetUp = Judge(new FakeProbes().WithDrive('C', DriveKind.Fixed).WithFile(Program, "made up")).File(Program);

        Assert.AreEqual(VerdictKind.Unknown, denied.Kind);
        Assert.IsTrue(denied.NeedsAdministrator);
        StringAssert.Contains(denied.Found, "needs administrator rights");
        Assert.AreEqual(VerdictKind.Unknown, failed.Kind);
        Assert.IsFalse(failed.NeedsAdministrator);
        StringAssert.Contains(failed.Found, "the disk reported an error");
        Assert.AreEqual(VerdictKind.Unknown, notSetUp.Kind);
    }

    [TestMethod]
    public void ALinkOnTheWay_IsNotFollowed_AndThePathIsUnknown()
    {
        FakeProbes probes = Pc().WithFile(Tool, "made up").WithAccessBelow(@"C:\Tools", FakeAccess.Protected).WithLink(@"C:\Tools");

        Verdict verdict = Judge(probes).File(Tool);

        Assert.AreEqual(VerdictKind.Unknown, verdict.Kind);
        StringAssert.Contains(verdict.Found, "link");
    }

    [TestMethod]
    [DataRow(DriveKind.Network, (int)VerdictKind.Network)]
    [DataRow(DriveKind.Removable, (int)VerdictKind.NotFixedDrive)]
    [DataRow(DriveKind.Other, (int)VerdictKind.NotFixedDrive)]
    [DataRow(DriveKind.Absent, (int)VerdictKind.Missing)]
    [DataRow(DriveKind.Unknown, (int)VerdictKind.Unknown)]
    public void OnlyAFixedDrive_IsRead(DriveKind drive, int kind)
    {
        // Nothing is set up for drive Z: a read of anything on it would fail the test's expectation.
        Verdict verdict = Judge(Pc().WithDrive('Z', drive)).File(@"Z:\Example\agent.exe");

        var expected = (VerdictKind)kind;
        Assert.AreEqual(expected, verdict.Kind);
        if (expected == VerdictKind.Network)
        {
            Assert.AreEqual(string.Empty, verdict.Path, "where on the network is not kept");
        }
    }

    [TestMethod]
    [DataRow(@"\\server\share\agent.exe", (int)VerdictKind.Network)]
    [DataRow(@"agent.exe", (int)VerdictKind.Unknown)]
    [DataRow(@"C:\Tools\..\Windows\agent.exe", (int)VerdictKind.Unknown)]
    [DataRow(@"C:\Tools\a<b.exe", (int)VerdictKind.Unknown)]
    [DataRow(@"C:\Tools\a.exe:stream", (int)VerdictKind.Unknown)]
    public void APathThatIsNotACompleteOneOnThisPc_IsNotRead(string path, int expected)
    {
        Assert.AreEqual((VerdictKind)expected, Judge(new FakeProbes()).File(path).Kind);
    }

    [TestMethod]
    public void AFolderProgramsAreLookedForIn_IsAProblem_AsSoonAsUsersCanAddFiles()
    {
        FakeProbes probes = Pc()
            .WithAccess(@"C:\Tools", FakeAccess.Protected)
            .WithAccess(@"C:\Tools\bin", FakeAccess.UsersAdd)
            .WithAccess(@"C:\Tools\safe", FakeAccess.Protected);
        ProgramJudge judge = Judge(probes);

        Assert.AreEqual(VerdictKind.AddBeside, judge.Folder(@"C:\Tools\bin").Kind);
        Assert.AreEqual(@"Users can add files to C:\Tools\bin", judge.Folder(@"C:\Tools\bin\").Found);
        Assert.AreEqual(VerdictKind.Protected, judge.Folder(@"C:\Tools\safe").Kind);
        Assert.AreEqual(VerdictKind.Protected, judge.Folder(@"C:\").Kind, "creating folders at the top is not adding programs to it");
        Assert.AreEqual(VerdictKind.MissingCreatable, judge.Folder(@"C:\Gone\bin").Kind);
        Assert.AreEqual(VerdictKind.Missing, judge.Folder(@"C:\Tools\gone").Kind);
    }

    [TestMethod]
    public void ARegistryKey_IsChangeable_WhenUsersCanSetValuesOrCreateKeysInIt()
    {
        const string Key = @"SOFTWARE\Example";
        FakeProbes probes = new FakeProbes()
            .WithKeyAccess(RegistryRoot.LocalMachine, Key, FakeAccess.UsersAdd)
            .WithKeyAccess(RegistryRoot.LocalMachine, Key + @"\Safe", FakeAccess.Protected)
            .WithKeyAccessFailure(RegistryRoot.LocalMachine, Key + @"\Closed", ProbeFailure.AccessDenied());
        ProgramJudge judge = Judge(probes);

        Assert.AreEqual(@"Users can change HKLM\SOFTWARE\Example", judge.Key(RegistryRoot.LocalMachine, Key).Found);
        Assert.AreEqual(VerdictKind.Protected, judge.Key(RegistryRoot.LocalMachine, Key + @"\Safe").Kind);
        Assert.IsTrue(judge.Key(RegistryRoot.LocalMachine, Key + @"\Closed").NeedsAdministrator);
        Assert.AreEqual(VerdictKind.Missing, judge.Key(RegistryRoot.LocalMachine, Key + @"\Gone").Kind);
    }

    [TestMethod]
    public void AQuotedCommandForAProtectedProgram_IsFine()
    {
        CommandVerdict verdict = Command(Pc(), $@"""{Program}"" --run");

        Assert.IsFalse(verdict.IsProblem);
        Assert.IsFalse(verdict.IsUnknown);
        Assert.AreEqual("Protected", verdict.Found);
    }

    [TestMethod]
    public void AnUnquotedPathWithSpaces_IsAProblemOnlyWhereTheEarlierFileCouldBeCreated()
    {
        FakeProbes usual = Pc();
        FakeProbes open = Pc()
            .WithFile(@"C:\Tools\Example Agent\agent.exe", "made up")
            .WithAccess(@"C:\Tools", FakeAccess.UsersAdd)
            .WithAccessBelow(@"C:\Tools\Example Agent", FakeAccess.Protected);

        CommandVerdict underProgramFiles = Command(usual, $"{Program} --run");
        CommandVerdict underTools = Command(open, @"C:\Tools\Example Agent\agent.exe --run");

        Assert.IsFalse(underProgramFiles.IsProblem, @"users cannot create C:\Program.exe");
        Assert.IsTrue(underProgramFiles.Reference.Ambiguous);
        Assert.IsTrue(underTools.IsProblem);
        Assert.AreEqual(
            @"Written without quotes; Users can create C:\Tools\Example.exe, which Windows would run first",
            underTools.Found);
    }

    [TestMethod]
    public void AProgramNamedWithoutAFolder_IsTheFirstOneFound_AndAnEarlierPlaceUsersCanWriteToIsAProblem()
    {
        FakeProbes probes = Pc()
            .WithRegistryValue(
                RegistryRoot.LocalMachine, SecReview.SupplyChain.PersistentEnvironment.MachineKey, "Path", RegistryValue.FromText(@"C:\Tools\bin;C:\Program Files\Example"))
            .WithAccess(@"C:\Tools", FakeAccess.Protected)
            .WithAccess(@"C:\Tools\bin", FakeAccess.UsersAdd)
            .WithFile(@"C:\Windows\System32\cmd.exe", "made up");

        CommandVerdict inWindows = Command(probes, "cmd.exe");
        CommandVerdict onThePath = Command(probes, "agent.exe --run");
        CommandVerdict nowhere = Command(probes, "gone.exe");

        Assert.IsFalse(inWindows.IsProblem);
        Assert.IsTrue(onThePath.IsProblem);
        Assert.AreEqual(
            @"Named without a folder; Users can create C:\Tools\bin\agent.exe, which Windows would run first",
            onThePath.Found);
        Assert.AreEqual(Program, onThePath.Program.Path);
        Assert.IsTrue(nowhere.IsProblem, "a name found nowhere runs whatever is put first on the path");
    }

    [TestMethod]
    public void WhatAWindowsProgramIsAskedToRun_IsJudgedToo()
    {
        FakeProbes probes = Pc()
            .WithFile(@"C:\Windows\System32\rundll32.exe", "made up")
            .WithFile(@"C:\Tools\Example\lib.dll", "made up")
            .WithAccessBelow(@"C:\Tools", FakeAccess.UsersModify);

        CommandVerdict verdict = Command(probes, @"rundll32.exe C:\Tools\Example\lib.dll,Start");

        Assert.AreEqual(VerdictKind.Protected, verdict.Program.Kind);
        Assert.IsTrue(verdict.IsProblem);
        Assert.AreEqual(@"C:\Tools\Example\lib.dll: Authenticated Users can change C:\Tools", verdict.Found);
    }

    [TestMethod]
    public void ANetworkProgram_AndACommandThatCannotBeRead_AreToldApart()
    {
        CommandVerdict network = Command(Pc(), @"\\server\share\agent.exe /x");
        CommandVerdict unreadable = Command(Pc(), @"relative\agent.exe");
        CommandVerdict missing = Command(Pc(), @"""C:\Program Files\Example\gone.exe""");

        Assert.IsTrue(network.IsProblem);
        Assert.AreEqual("On a network location", network.Found);
        Assert.IsTrue(unreadable.IsUnknown);
        Assert.IsFalse(unreadable.NeedsAdministrator);
        Assert.IsTrue(missing.IsMissing);
        Assert.IsFalse(missing.IsProblem);
    }

    [TestMethod]
    public void WhereTheProgramsNameEndsBeingAGuess_NoArgumentIsEverShown()
    {
        const string Secret = "made-up-secret-argument";
        FakeProbes probes = Pc().WithAccessBelow(@"C:\Tools", FakeAccess.UsersModify);

        CommandVerdict verdict = Command(probes, @"C:\Tools\agent data\" + Secret + @"\file.txt");

        Assert.IsFalse(verdict.Found.Contains(Secret, StringComparison.Ordinal), verdict.Found);
        Assert.IsTrue(verdict.IsProblem, "the program itself is missing where users can create it");
        Assert.IsNull(verdict.Planted);
    }
}
