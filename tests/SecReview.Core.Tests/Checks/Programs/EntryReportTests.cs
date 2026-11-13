using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class EntryReportTests
{
    private const string None = "No example programs are set up.";

    private static EntryReport Report(bool elevated = false) => new("example program", "example programs", elevated);

    private static Verdict Protected(string path = @"C:\Program Files\Example\agent.exe") => new(VerdictKind.Protected, path);

    private static Verdict Changeable(string path = @"C:\Tools\Example\agent.exe") => new(VerdictKind.Changeable, path, "Users", path);

    private static Verdict Denied(string path = @"C:\Program Files\Closed\agent.exe") =>
        new(VerdictKind.Unknown, path, Unread: ProbeStatus.AccessDenied);

    [TestMethod]
    public void EverythingProtected_Passes_AndSaysHowManyWereChecked()
    {
        EntryReport report = Report();
        report.Add("First", Protected());
        report.Add("Second", Protected());

        CheckOutcome outcome = report.Outcome(None);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("All 2 example programs are protected from change by standard users.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "Example programs: 2 checked, all protected (expected Only administrators can change it) [ok]" },
            outcome.Rows());
    }

    [TestMethod]
    public void AnEmptyList_Passes_WithTheChecksOwnWords()
    {
        CheckOutcome outcome = Report().Outcome(None);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(None, outcome.Summary);
    }

    [TestMethod]
    public void OneProblem_Fails_AndNamesIt_WhateverElseCouldNotBeRead()
    {
        EntryReport report = Report();
        report.Add("First", Protected());
        report.Add("Second", Changeable(), @"HKLM\SOFTWARE\Example");
        report.Add("Third", Denied());

        CheckOutcome outcome = report.Outcome(None);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status, "a problem is a fact; what could not be read does not hide it");
        Assert.AreEqual("1 example program is not protected from change: Second.", outcome.Summary);
        Assert.AreEqual(FindingStatus.Problem, outcome.Findings[0].Status);
        Assert.AreEqual(@"HKLM\SOFTWARE\Example", outcome.Findings[0].Source);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[1].Status);
        StringAssert.Contains(outcome.Findings[1].Found, "needs administrator rights");
    }

    [TestMethod]
    public void WithNoProblem_WhatOnlyAnAdministratorCanRead_IsNeedsAdministrator_NotAPass()
    {
        EntryReport report = Report();
        report.Add("First", Protected());
        report.Add("Second", Denied());

        CheckOutcome outcome = report.Outcome(None);

        Assert.AreEqual(CheckStatus.NeedsAdmin, outcome.Status);
        Assert.AreEqual("No problem in 1 example program; 1 more needs administrator rights to read.", outcome.Summary);
    }

    [TestMethod]
    public void TheSame_WhenAlreadyRunningAsAdministrator_IsCouldNotCheck()
    {
        EntryReport report = Report(elevated: true);
        report.Add("First", Protected());
        report.Add("Second", Denied());

        Assert.AreEqual(CheckStatus.Error, report.Outcome(None).Status, "asking for administrator rights again would change nothing");
    }

    [TestMethod]
    public void WithNoProblem_WhatCouldNotBeReadForAnotherReason_IsCouldNotCheck_WithTheFirstReason()
    {
        EntryReport report = Report();
        report.Add("First", Protected());
        report.Add("Second", Denied());
        report.Add("Third", new Verdict(VerdictKind.Unknown, @"C:\Tools\agent.exe", Reason: "The disk reported an error."));

        CheckOutcome outcome = report.Outcome(None);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.StartsWith(outcome.Summary, "No problem in 1 example program; 2 could not be judged.");
    }

    [TestMethod]
    public void AMissingProgram_IsANote_AndStillAPass()
    {
        EntryReport report = Report();
        report.Add("Left behind", new Verdict(VerdictKind.Missing, @"C:\Program Files\Gone\agent.exe"));

        CheckOutcome outcome = report.Outcome(None);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        CollectionAssert.Contains(outcome.Rows(), @"Left behind: C:\Program Files\Gone\agent.exe is missing [note]");
    }

    [TestMethod]
    public void MoreThanTenOfAKind_AreCounted_NotAllShown()
    {
        EntryReport report = Report();
        for (int i = 0; i < 14; i++)
        {
            report.Add($"Problem {i}", Changeable());
            report.Add($"Left behind {i}", new Verdict(VerdictKind.Missing, @"C:\Program Files\Gone\agent.exe"));
        }

        CheckOutcome outcome = report.Outcome(None);

        Assert.AreEqual("14 example programs are not protected from change.", outcome.Summary);
        Assert.AreEqual(10, outcome.Findings.Count(f => f.Status == FindingStatus.Problem));
        CollectionAssert.Contains(outcome.Rows(), "More problems: 4 more [note]");
        CollectionAssert.Contains(outcome.Rows(), "More notes: 4 more [note]");
        Assert.AreEqual(22, outcome.Findings.Count);
    }

    [TestMethod]
    public void AProblemFromPolicy_IsMarkedAsManaged()
    {
        EntryReport report = Report();
        report.Add("First", Changeable());
        report.ManagedByPolicy = true;

        Assert.IsTrue(report.Outcome(None).ManagedByPolicy);
    }
}
