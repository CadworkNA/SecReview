using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Scanning;

namespace SecReview.Tests.Scanning;

[TestClass]
public sealed class ResultsStoreTests
{
    private static readonly DateTimeOffset When = new(2026, 11, 12, 8, 30, 0, TimeSpan.Zero);
    private static readonly CheckTexts Texts = CheckTexts.Load();

    /// <summary>Three real checks of the catalogue, so their wording is found.</summary>
    private static readonly ICheck[] Checks = [new FirewallCheck(), new AutomaticLogonCheck(), new AntivirusCheck()];

    private string _folder = string.Empty;

    private string File => Path.Combine(_folder, ResultsStore.FileName);

    [TestInitialize]
    public void CreateFolder() => _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));

    [TestCleanup]
    public void DeleteFolder()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private static ScanResult Scan() => new(
        [
            Scanned(Checks[0], new CheckOutcome(
                CheckStatus.Fail,
                "Windows Firewall is off for the Public network.",
                [Finding.Ok("Private network", "On", "On"), Finding.Problem("Public network", "Off", "On", @"HKLM\made\up"), Finding.Note("Rules", "12")],
                ManagedByPolicy: true)),
            Scanned(Checks[1], CheckOutcome.Pass("Automatic sign-in is off.")),
            Scanned(Checks[2], CheckOutcome.Error("Asking Windows Security Center failed.")),
        ],
        When.AddSeconds(4),
        Elevated: false);

    private static ScannedCheck Scanned(ICheck check, CheckOutcome outcome) => new(
        check.Definition, Texts[check.Definition.Id], new CheckResult(check.Definition.Id, outcome, When, Elevated: false, TimeSpan.FromMilliseconds(250)));

    [TestMethod]
    public void WithoutAFile_ThereIsNothingToShow()
    {
        Assert.IsNull(new ResultsStore(_folder).Load(Checks, Texts));
        Assert.IsFalse(Directory.Exists(_folder), "reading creates nothing");
    }

    [TestMethod]
    public void ASavedScan_ComesBackAsItWas()
    {
        var store = new ResultsStore(_folder);
        ScanResult scan = Scan();

        Assert.IsTrue(store.Save(scan));
        ScanResult read = store.Load(Checks, Texts)!;

        Assert.AreEqual(scan.FinishedAt, read.FinishedAt);
        Assert.AreEqual(scan.Elevated, read.Elevated);
        Assert.AreEqual(3, read.Checks.Count);
        for (int i = 0; i < 3; i++)
        {
            Assert.AreEqual(scan.Checks[i].Definition.Id, read.Checks[i].Definition.Id);
            Assert.AreEqual(scan.Checks[i].Result.Outcome.Status, read.Checks[i].Result.Outcome.Status);
            Assert.AreEqual(scan.Checks[i].Result.Outcome.Summary, read.Checks[i].Result.Outcome.Summary);
            Assert.AreEqual(scan.Checks[i].Result.Outcome.ManagedByPolicy, read.Checks[i].Result.Outcome.ManagedByPolicy);
            Assert.AreEqual(scan.Checks[i].Result.CheckedAt, read.Checks[i].Result.CheckedAt);
            Assert.AreEqual(scan.Checks[i].Result.Duration, read.Checks[i].Result.Duration);
            CollectionAssert.AreEqual(scan.Checks[i].Result.Outcome.Findings.ToArray(), read.Checks[i].Result.Outcome.Findings.ToArray());
            Assert.AreEqual(scan.Checks[i].Title, read.Checks[i].Title);
        }

        Assert.AreEqual(1, Directory.GetFiles(_folder).Length, "no temporary file is left behind");
    }

    [TestMethod]
    public void AResultForACheckThisVersionDoesNotHave_IsLeftOut()
    {
        var store = new ResultsStore(_folder);
        store.Save(Scan());

        ScanResult read = store.Load([Checks[1]], Texts)!;

        Assert.AreEqual(AutomaticLogonCheck.Id, read.Checks.Single().Definition.Id);
    }

    [TestMethod]
    [DataRow("\"schemaVersion\":1", "\"schemaVersion\":2", DisplayName = "another shape")]
    [DataRow("\"status\":\"Pass\"", "\"status\":\"Passed\"", DisplayName = "a status this version does not know")]
    [DataRow("\"status\":\"Pass\"", "\"status\":\"1\"", DisplayName = "a status as a number")]
    [DataRow("\"status\":\"Pass\"", "\"status\":\" 1\"", DisplayName = "a status as a padded number")]
    [DataRow("\"status\":\"Pass\"", "\"status\":\"+1\"", DisplayName = "a status as a signed number")]
    [DataRow("\"status\":\"Pass\"", "\"status\":\"pass\"", DisplayName = "a status in another case")]
    [DataRow("\"finishedAt\":\"2026-", "\"finishedAt\":\"2999-", DisplayName = "a scan from the future")]
    [DataRow("\"finishedAt\":\"2026-", "\"finishedAt\":\"1999-", DisplayName = "a scan from before SecReview")]
    [DataRow("\"status\":\"Problem\"", "\"status\":\"Bad\"", DisplayName = "a finding status this version does not know")]
    [DataRow("\"summary\":\"Automatic sign-in is off.\"", "\"summary\":\"\"", DisplayName = "an empty summary")]
    [DataRow("\"summary\":\"Automatic sign-in is off.\"", "\"summary\":null", DisplayName = "no summary")]
    [DataRow("\"id\":\"logon.automatic\"", "\"id\":\"firewall.enabled\"", DisplayName = "a check twice")]
    [DataRow("\"findings\":[]", "\"findings\":null", DisplayName = "no findings list")]
    public void AFileThisVersionCannotTrust_IsNotUsed(string find, string replace)
    {
        var store = new ResultsStore(_folder);
        store.Save(Scan());
        string saved = System.IO.File.ReadAllText(File);
        Assert.IsTrue(saved.Contains(find, StringComparison.Ordinal), $"the saved file has no {find}: {saved[..300]}");

        System.IO.File.WriteAllText(File, saved.Replace(find, replace, StringComparison.Ordinal));

        Assert.IsNull(store.Load(Checks, Texts));
    }

    [TestMethod]
    public void AVeryLongAnswer_IsCutToFit_AndTheFileStaysUsable()
    {
        var store = new ResultsStore(_folder);
        var scan = new ScanResult(
            [
                Scanned(Checks[0], new CheckOutcome(
                    CheckStatus.Fail,
                    new string('s', 9000),
                    [.. Enumerable.Range(0, 1500).Select(i => Finding.Problem($"item {i}", new string('f', 5000), "x", new string('p', 5000)))])),
            ],
            When,
            Elevated: false);

        Assert.IsTrue(store.Save(scan));
        ScanResult read = store.Load(Checks, Texts)!;

        Assert.AreEqual(4000, read.Checks[0].Result.Outcome.Summary.Length);
        Assert.AreEqual(1000, read.Checks[0].Result.Outcome.Findings.Count);
        Assert.AreEqual(4000, read.Checks[0].Result.Outcome.Findings[0].Found.Length);
        Assert.AreEqual(4000, read.Checks[0].Result.Outcome.Findings[0].Source!.Length);
    }

    [TestMethod]
    public void AFileFromAnotherVersionOfSecReview_IsNotUsed()
    {
        var store = new ResultsStore(_folder);
        store.Save(Scan());
        string saved = System.IO.File.ReadAllText(File);

        System.IO.File.WriteAllText(File, saved.Replace($"\"appVersion\":\"{ProductInfo.Version}\"", "\"appVersion\":\"0.0.1-other\"", StringComparison.Ordinal));

        Assert.IsNull(store.Load(Checks, Texts), "checks change between versions; an old answer may mean something else now");
    }

    [TestMethod]
    public void DamagedFiles_AreNotUsedOrAreStillResults_NeverAnError()
    {
        var store = new ResultsStore(_folder);
        store.Save(Scan());
        string good = System.IO.File.ReadAllText(File);
        var random = new Random(20261112);

        for (int round = 0; round < 500; round++)
        {
            System.IO.File.WriteAllText(File, Config.ConfigTesting.Damage(good, random));

            ScanResult? read = store.Load(Checks, Texts);

            if (read is not null)
            {
                Assert.IsTrue(read.Checks.All(c => !string.IsNullOrWhiteSpace(c.Result.Outcome.Summary) && Enum.IsDefined(c.Result.Outcome.Status)), $"round {round}");
            }
        }
    }
}
