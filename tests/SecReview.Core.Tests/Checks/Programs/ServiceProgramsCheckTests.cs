using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class ServiceProgramsCheckTests
{
    private const long OwnProcess = 0x10;
    private const long SharedProcess = 0x20;
    private const long KernelDriver = 0x1;
    private const long Disabled = 4;

    private static readonly ServiceProgramsCheck Check = new();

    private static string Key(string name) => $@"{ServiceProgramsCheck.ServicesKey}\{name}";

    /// <summary>A PC with one service installed the usual way, one hosted by Windows and one driver.</summary>
    private static FakeProbes Usual() => Pc()
        .WithFile(@"C:\Windows\System32\example.dll", "made up")
        .WithFile(@"C:\Windows\System32\drivers\example.sys", "made up")
        .Service("ExampleAgent", $@"""{Installed}"" --service {Secret}")
        .Service("ExampleHosted", @"%SystemRoot%\System32\svchost.exe -k netsvcs -p", SharedProcess, library: @"%SystemRoot%\System32\example.dll")
        .Service("ExampleDriver", @"\SystemRoot\System32\drivers\example.sys", KernelDriver);

    [TestMethod]
    public void ServicesInstalledTheUsualWay_Pass()
    {
        CheckOutcome outcome = Check.Run(Usual());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 3 service programs are protected from change by standard users.", outcome.Summary);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    public void AServiceProgramStandardUsersCanChange_Fails()
    {
        CheckOutcome outcome = Check.Run(Usual().Service("LooseAgent", $"{Loose} --service {Secret}"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 service program is not protected from change: Service: LooseAgent.", outcome.Summary);
        CollectionAssert.Contains(
            outcome.Rows(),
            $@"Service: LooseAgent: {Loose}: Authenticated Users can change C:\Tools (expected Only administrators can change it) [problem]");
        Assert.AreEqual($@"HKLM\{Key("LooseAgent")}", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    public void APathWithSpacesWrittenWithoutQuotes_FailsWhereTheEarlierFileCouldBeCreated_AndNotOtherwise()
    {
        FakeProbes plantable = Usual()
            .WithFile(@"C:\Shared\Example Agent\agent.exe", "made up")
            .WithAccess(@"C:\Shared", FakeAccess.UsersAdd)
            .WithAccessBelow(@"C:\Shared\Example Agent", FakeAccess.Protected)
            .Service("UnquotedAgent", @"C:\Shared\Example Agent\agent.exe --service");
        FakeProbes harmless = Usual().Service("UnquotedAgent", $"{Installed} --service");

        CheckOutcome fails = Check.Run(plantable);
        CheckOutcome passes = Check.Run(harmless);

        Assert.AreEqual(CheckStatus.Fail, fails.Status);
        Assert.AreEqual(
            @"Written without quotes; Users can create C:\Shared\Example.exe, which Windows would run first",
            fails.Findings[0].Found);
        Assert.AreEqual(CheckStatus.Pass, passes.Status, @"nobody but an administrator can create C:\Program.exe");
    }

    [TestMethod]
    public void TheLibraryOfAServiceHostedByWindows_IsJudged()
    {
        FakeProbes probes = Usual()
            .WithFile(@"C:\Tools\Example\service.dll", "made up")
            .Service("LooseHosted", @"C:\Windows\System32\svchost.exe -k example", SharedProcess, library: @"C:\Tools\Example\service.dll");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(@"C:\Tools\Example\service.dll: Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void AServiceWhoseSettingsStandardUsersCanChange_Fails_ThoughItsProgramIsProtected()
    {
        FakeProbes probes = Usual().WithKeyAccess(RegistryRoot.LocalMachine, Key("ExampleAgent"), FakeAccess.UsersModify);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($@"Users can change HKLM\{Key("ExampleAgent")}", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void AServiceOnTheNetwork_Fails_WithoutNamingTheServer()
    {
        CheckOutcome outcome = Check.Run(Usual().Service("NetworkAgent", @"\\server\share\agent.exe"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("On a network location", outcome.Findings[0].Found);
        Assert.IsFalse(outcome.Everything().Contains("server", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void ADisabledServiceWithAProblem_IsANote()
    {
        CheckOutcome outcome = Check.Run(Usual().Service("OldAgent", Loose, start: Disabled));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), $@"Service: OldAgent: Disabled. {Loose}: Authenticated Users can change C:\Tools [note]");
    }

    [TestMethod]
    public void ADriver_FailsWhenChangeable_AndIsNotMentionedWhenItsFileIsNotThere()
    {
        FakeProbes probes = Usual()
            .WithFile(@"C:\Tools\Example\driver.sys", "made up")
            .Service("LooseDriver", @"\??\C:\Tools\Example\driver.sys", KernelDriver)
            .Service("AbsentDriver", @"System32\drivers\absent.sys", KernelDriver);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 service program is not protected from change: Driver: LooseDriver.", outcome.Summary);
        Assert.IsFalse(outcome.Everything().Contains("AbsentDriver", StringComparison.Ordinal));
    }

    [TestMethod]
    public void WhatIsNotAService_OrIsACopyForOneUser_IsLeftOut()
    {
        FakeProbes probes = Usual()
            .WithText(Key("JustSettings"), "ImagePath", Loose)
            .Service("ExampleUserService_1a2b3", Loose, type: 0xE0)
            .WithRegistryNumber(RegistryRoot.LocalMachine, Key("NoProgram"), "Type", OwnProcess);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 3 service programs are protected from change by standard users.", outcome.Summary);
    }

    [TestMethod]
    public void AMissingProgram_IsANote_UnlessAStandardUserCouldPutOneThere()
    {
        CheckOutcome leftBehind = Check.Run(Usual().Service("GoneAgent", @"""C:\Program Files\Gone\agent.exe"""));
        CheckOutcome creatable = Check.Run(Usual().Service("GoneAgent", @"""C:\ProgramData\Gone\agent.exe"""));

        Assert.AreEqual(CheckStatus.Pass, leftBehind.Status, leftBehind.Summary);
        CollectionAssert.Contains(leftBehind.Rows(), @"Service: GoneAgent: C:\Program Files\Gone\agent.exe is missing [note]");
        Assert.AreEqual(CheckStatus.Fail, creatable.Status);
        Assert.AreEqual(@"C:\ProgramData\Gone\agent.exe is missing and Users can create it", creatable.Findings[0].Found);
    }

    [TestMethod]
    public void AProgramThatIsNotText_OrCannotBeUnderstood_IsCouldNotCheck()
    {
        FakeProbes probes = Usual()
            .WithRegistryNumber(RegistryRoot.LocalMachine, Key("OddAgent"), "Type", OwnProcess)
            .WithRegistryNumber(RegistryRoot.LocalMachine, Key("OddAgent"), "ImagePath", 7)
            .Service("RelativeAgent", @"bin\agent.exe");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.StartsWith(outcome.Summary, "No problem in 3 service programs; 2 could not be judged.");
    }

    [TestMethod]
    public void WhenTheListCannotBeRead_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = Usual();
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");
        FakeProbes denied = Usual();
        denied.RegistryFailure = ProbeFailure.AccessDenied();
        FakeProbes none = new FakeProbes().WithStandardWindows();

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(none).Status, "a PC without a list of services was not read right");
    }

    [TestMethod]
    public void PermissionsOnlyAnAdministratorCanRead_AreNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = Usual().WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied());

        CheckOutcome ordinary = Check.Run(probes);
        CheckOutcome elevated = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.NeedsAdmin, ordinary.Status);
        Assert.AreEqual("No problem in 2 service programs; 1 more needs administrator rights to read.", ordinary.Summary);
        Assert.AreEqual(CheckStatus.Error, elevated.Status);
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(ServiceProgramsCheck.Id, Check.Definition.Id);
        Assert.AreEqual(Severity.High, Check.Definition.Severity);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }
}
