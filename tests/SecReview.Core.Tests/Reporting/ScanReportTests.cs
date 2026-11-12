using System.Text.Json;
using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Reporting;
using SecReview.Scanning;

namespace SecReview.Tests.Reporting;

[TestClass]
public sealed class ScanReportTests
{
    private static readonly DateTimeOffset When = new(2026, 1, 15, 8, 30, 0, TimeSpan.Zero);
    private static readonly CheckTexts Texts = CheckTexts.Load();
    private static readonly Dictionary<string, CheckDefinition> Definitions =
        BuiltInChecks.All.ToDictionary(c => c.Definition.Id, c => c.Definition);

    private static ScanReport Build(bool elevated, params (string Id, CheckOutcome Outcome)[] results) =>
        ReportBuilder.Build(new ScanResult(
            [.. results.Select(r => new ScannedCheck(
                Definitions[r.Id], Texts[r.Id], new CheckResult(r.Id, r.Outcome, When, elevated, TimeSpan.FromMilliseconds(12))))],
            When,
            elevated));

    private static ScanReport Build(params (string Id, CheckOutcome Outcome)[] results) => Build(elevated: false, results);

    [TestMethod]
    public void Report_CarriesEachCheckWithTheTitleMatchingItsStatus()
    {
        ScanReport report = Build(
            (FirewallCheck.Id, CheckOutcome.Pass("Windows Firewall is on for all networks.")),
            (AntivirusCheck.Id, CheckOutcome.Fail(
                "Example Antivirus is off.", Finding.Problem("Example Antivirus", "Off", "On, definitions current"))));

        Assert.AreEqual(2, report.Checks.Count);

        ReportCheck firewall = report.Checks[0];
        Assert.AreEqual("firewall.enabled", firewall.Id);
        Assert.AreEqual("Pass", firewall.Status);
        Assert.AreEqual("Firewall is on", firewall.Title);
        Assert.AreEqual("FirewallAndSharing", firewall.Category);
        Assert.AreEqual("High", firewall.Severity);

        ReportCheck antivirus = report.Checks[1];
        Assert.AreEqual("Fail", antivirus.Status);
        Assert.AreEqual("Antivirus is off or out of date", antivirus.Title);
        Assert.AreEqual("Example Antivirus is off.", antivirus.Summary);
        Assert.AreEqual("Off", antivirus.Findings[0].Found);
        Assert.AreEqual("Problem", antivirus.Findings[0].Status);
    }

    [TestMethod]
    public void Counts_AddUpByStatus()
    {
        ScanReport report = Build(
            (FirewallCheck.Id, CheckOutcome.Pass("fine")),
            (AntivirusCheck.Id, CheckOutcome.Fail("broken")),
            (DriveEncryptionCheck.Id, CheckOutcome.NeedsAdmin("needs rights")),
            (AutomaticLogonCheck.Id, CheckOutcome.Error("could not read")));

        Assert.AreEqual(new ReportCounts(Pass: 1, Fail: 1, NeedsAdmin: 1, NotApplicable: 0, Error: 1), report.Counts);
    }

    [TestMethod]
    public void ACheckThatCouldNotBeAnswered_IsNamedNeutrally_NeverAsAFailureOrAPass()
    {
        foreach (CheckOutcome outcome in new[]
        {
            CheckOutcome.NeedsAdmin("x"), CheckOutcome.NotApplicable("x"), CheckOutcome.Error("x"),
        })
        {
            ScanReport report = Build((FirewallCheck.Id, outcome));

            Assert.AreEqual("Firewall", report.Checks[0].Title, outcome.Status.ToString());
        }
    }

    [TestMethod]
    public void Report_SaysWhetherTheScanWasElevated()
    {
        Assert.IsFalse(Build(elevated: false, (FirewallCheck.Id, CheckOutcome.Pass("fine"))).Elevated);
        Assert.IsTrue(Build(elevated: true, (FirewallCheck.Id, CheckOutcome.Pass("fine"))).Elevated);
    }

    [TestMethod]
    public void Json_HasTheDocumentedShape_AndNoComputerOrUserName()
    {
        ScanReport report = Build((
            FirewallCheck.Id,
            CheckOutcome.Fail("Windows Firewall is off for the Public network.", Finding.Problem("Public network", "Off", "On"))));

        string json = ReportFile.ToJson(report);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;

        Assert.AreEqual(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.AreEqual("SecReview", root.GetProperty("product").GetString());
        Assert.AreEqual(1, root.GetProperty("counts").GetProperty("fail").GetInt32());
        JsonElement check = root.GetProperty("checks")[0];
        Assert.AreEqual("firewall.enabled", check.GetProperty("id").GetString());
        Assert.AreEqual("Public network", check.GetProperty("findings")[0].GetProperty("item").GetString());

        // The report says what is wrong with a PC; it must not also say whose PC it is.
        Assert.IsFalse(json.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase));
        CollectionAssert.AreEquivalent(
            new[] { "schemaVersion", "product", "version", "generatedAt", "elevated", "counts", "checks" },
            root.EnumerateObject().Select(p => p.Name).ToArray());
    }

    [TestMethod]
    public void Write_ReplacesAnExistingFile_AndLeavesNoTemporaryFile()
    {
        string folder = Path.Combine(Path.GetTempPath(), "SecReviewTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            string path = Path.Combine(folder, "report.json");
            File.WriteAllText(path, "old content");

            ReportFile.Write(Build((FirewallCheck.Id, CheckOutcome.Pass("fine"))), path);

            using JsonDocument written = JsonDocument.Parse(File.ReadAllText(path));
            Assert.AreEqual(1, written.RootElement.GetProperty("counts").GetProperty("pass").GetInt32());
            CollectionAssert.AreEqual(new[] { "report.json" }, Directory.GetFiles(folder).Select(Path.GetFileName).ToArray());
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [TestMethod]
    public void Write_ToAFolderThatDoesNotExist_Throws_AndCreatesNothing()
    {
        string missing = Path.Combine(Path.GetTempPath(), "SecReviewTests-missing-" + Guid.NewGuid().ToString("N"));

        Assert.ThrowsExactly<DirectoryNotFoundException>(() =>
            ReportFile.Write(Build(), Path.Combine(missing, "report.json")));
        Assert.IsFalse(Directory.Exists(missing));
    }
}
