using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class ScheduledTasksCheckTests
{
    private const string Tasks = @"C:\Windows\System32\Tasks";
    private const string AsSystem = "<UserId>S-1-5-18</UserId>";
    private const string AsUser = "<UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>";

    private static readonly ScheduledTasksCheck Check = new();

    /// <summary>A task file as Windows writes it, made up.</summary>
    private static string Task(string actions, string principal = AsSystem, bool enabled = true) => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Description>{Secret}</Description></RegistrationInfo>
          <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
          <Principals><Principal id="Author">{principal}</Principal></Principals>
          <Settings><Enabled>{(enabled ? "true" : "false")}</Enabled></Settings>
          <Actions Context="Author">{actions}</Actions>
        </Task>
        """;

    private static string Runs(string command, string arguments = "") =>
        $"<Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec>";

    private static CheckOutcome Run(FakeProbes probes) => Check.Run(probes, elevated: true);

    [TestMethod]
    public void WithoutAdministratorRights_TheAnswerIsNeedsAdministrator_NotNone()
    {
        FakeProbes probes = Pc().WithFile($@"{Tasks}\Example Task", Task(Runs(Loose)));

        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(probes).Status);
    }

    [TestMethod]
    public void SystemTasksThatRunProtectedPrograms_Pass_AndOrdinaryTasksAreCountedNotJudged()
    {
        FakeProbes probes = Pc()
            .WithFile($@"{Tasks}\Example Task", Task(Runs($@"""{Installed}""", $"--run {Secret}")))
            .WithFile($@"{Tasks}\Example\Nested\Check", Task(Runs(@"%windir%\system32\svchost.exe", "-k example")))
            .WithFile($@"{Tasks}\Example\Per user", Task(Runs(Loose), AsUser));

        CheckOutcome outcome = Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 2 task programs are protected from change by standard users.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "Ordinary tasks: 1 task runs with a user's ordinary rights; not judged [note]");
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    [DataRow(AsSystem, DisplayName = "as the system")]
    [DataRow("<UserId>NT AUTHORITY\\SYSTEM</UserId>", DisplayName = "as the system, by name")]
    [DataRow("<GroupId>S-1-5-32-544</GroupId>", DisplayName = "as the administrators group")]
    [DataRow(AsUser + "<RunLevel>HighestAvailable</RunLevel>", DisplayName = "with highest privileges")]
    public void ATaskWithHighRights_WhoseProgramStandardUsersCanChange_Fails(string principal)
    {
        FakeProbes probes = Pc().WithFile($@"{Tasks}\Example\Daily", Task(Runs(Loose, $"--run {Secret}"), principal));

        CheckOutcome outcome = Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(@"1 task program is not protected from change: Task: \Example\Daily.", outcome.Summary);
        Assert.AreEqual($@"{Loose}: Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
        Assert.AreEqual($@"{Tasks}\Example\Daily", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal));
    }

    [TestMethod]
    public void WhatAScriptHostIsToldToRun_AndARegisteredComponent_AreJudged()
    {
        const string Id = "{11111111-1111-1111-1111-111111111111}";
        FakeProbes probes = Pc()
            .WithFile(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "made up")
            .WithFile(@"C:\Tools\Example\run.ps1", "made up")
            .WithFile(@"C:\Tools\Example\lib.dll", "made up")
            .InProcess(Id, @"C:\Tools\Example\lib.dll")
            .WithFile($@"{Tasks}\Script", Task(Runs(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"-NoProfile -File ""C:\Tools\Example\run.ps1""")))
            .WithFile($@"{Tasks}\Component", Task($"<ComHandler><ClassId>{Id}</ClassId></ComHandler>"))
            .WithFile($@"{Tasks}\Unregistered", Task("<ComHandler><ClassId>{22222222-2222-2222-2222-222222222222}</ClassId></ComHandler>"));

        CheckOutcome outcome = Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("2 task programs are not protected from change.", outcome.Summary);
        string[] found = [.. outcome.Findings.Where(f => f.Status == FindingStatus.Problem).Select(f => f.Found)];
        CollectionAssert.Contains(found, @"C:\Tools\Example\lib.dll: Authenticated Users can change C:\Tools");
        CollectionAssert.Contains(found, @"C:\Tools\Example\run.ps1: Authenticated Users can change C:\Tools");
    }

    [TestMethod]
    public void ADisabledTaskWithAProblem_IsANote()
    {
        FakeProbes probes = Pc().WithFile($@"{Tasks}\Old", Task(Runs(Loose), enabled: false));

        CheckOutcome outcome = Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), $@"Task: \Old: Disabled. {Loose}: Authenticated Users can change C:\Tools [note]");
    }

    [TestMethod]
    public void ATaskFileThatCannotBeRead_OrIsNotATask_IsCouldNotCheck()
    {
        FakeProbes probes = Pc()
            .WithFile($@"{Tasks}\Fine", Task(Runs($@"""{Installed}""")))
            .WithFile($@"{Tasks}\Broken", "<Task><Actions>")
            .WithFile($@"{Tasks}\Other", "<Something />")
            .WithFileFailure($@"{Tasks}\Closed", ProbeFailure.Failed("The disk reported an error."));

        CheckOutcome outcome = Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.StartsWith(outcome.Summary, "No problem in 1 task program; 3 could not be judged.");
    }

    [TestMethod]
    public void ALinkAmongTheTasks_IsNotFollowed()
    {
        FakeProbes probes = Pc()
            .WithFile($@"{Tasks}\Fine", Task(Runs($@"""{Installed}""")))
            .WithFile($@"{Tasks}\Linked\Loose", Task(Runs(Loose)))
            .WithLink($@"{Tasks}\Linked");

        Assert.AreEqual(CheckStatus.Pass, Run(probes).Status);
    }

    [TestMethod]
    public void NoTaskWithHighRights_PassesWithItsOwnWords()
    {
        FakeProbes probes = Pc().WithFile($@"{Tasks}\Per user", Task(Runs(Loose), AsUser));

        Assert.AreEqual("No scheduled task runs with high rights.", Run(probes).Summary);
    }

    [TestMethod]
    public void MoreTasksThanItReads_IsCouldNotCheck_NotAPartialAnswer()
    {
        FakeProbes probes = Pc();
        for (int number = 0; number <= ScheduledTasksCheck.MaximumTasks; number++)
        {
            probes.WithFile($@"{Tasks}\Many\Task {number}", "made up");
        }

        // Run directly: the damaged copies of a PC this size are not worth their time.
        CheckOutcome outcome = Check.Run(new CheckContext(probes.Build(), TimeProvider.System, IsElevated: true, CancellationToken.None));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "More than 2000 scheduled tasks");
    }

    [TestMethod]
    public void WhenTheTasksCannotBeListed_TheAnswerIsCouldNotCheck()
    {
        FakeProbes failed = Pc().WithFile($@"{Tasks}\Fine", Task(Runs($@"""{Installed}""")));
        failed.FilesFailure = ProbeFailure.Failed("The disk reported an error.");
        FakeProbes noFolder = new FakeProbes().WithStandardWindows();

        Assert.AreEqual(CheckStatus.Error, Run(failed).Status);
        Assert.AreEqual(CheckStatus.Error, Run(noFolder).Status, "a PC without a tasks folder was not read right");
    }

    [TestMethod]
    public void OnlyAnAdministratorScanAnswersIt()
    {
        Assert.AreEqual(ScheduledTasksCheck.Id, Check.Definition.Id);
        Assert.AreEqual(Severity.High, Check.Definition.Severity);
        Assert.AreEqual(AdminNeed.Yes, Check.Definition.NeedsAdmin);
        Assert.AreEqual(CheckScope.Machine, Check.Definition.Scope);
    }
}
