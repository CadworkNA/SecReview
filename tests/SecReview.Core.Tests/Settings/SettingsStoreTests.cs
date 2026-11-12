using SecReview.Settings;

namespace SecReview.Tests.Settings;

[TestClass]
public sealed class SettingsStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 12, 9, 0, 0, TimeSpan.Zero);

    private string _folder = string.Empty;

    private string File => Path.Combine(_folder, SettingsStore.FileName);

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

    [TestMethod]
    public void WithoutAFile_TheDefaultsApply_AndNothingIsWrong()
    {
        AppSettings settings = new SettingsStore(_folder).Load(out string? problem);

        Assert.IsNull(problem);
        Assert.IsFalse(settings.FirstRunDone);
        Assert.IsTrue(settings.SendErrorReports);
        Assert.AreEqual(0, settings.Ignored.Count);
        Assert.IsFalse(Directory.Exists(_folder), "reading creates nothing");
    }

    [TestMethod]
    public void WhatIsSaved_IsReadBack()
    {
        var store = new SettingsStore(_folder);
        AppSettings settings = new AppSettings { FirstRunDone = true, SendErrorReports = false }
            .WithIgnored("firewall.enabled", "  Managed by\tthe lab network \n team ", Now)
            .WithIgnored("sc.npm.cooldown", string.Empty, Now.AddMinutes(1));

        Assert.IsTrue(store.Save(settings, out string? saveProblem));
        Assert.IsNull(saveProblem);
        AppSettings read = store.Load(out string? problem);

        Assert.IsNull(problem);
        Assert.IsTrue(read.FirstRunDone);
        Assert.IsFalse(read.SendErrorReports);
        Assert.AreEqual(new IgnoredCheck("firewall.enabled", "Managed by the lab network team", Now), read.Ignored[0]);
        Assert.AreEqual(new IgnoredCheck("sc.npm.cooldown", string.Empty, Now.AddMinutes(1)), read.Ignored[1]);
        Assert.AreEqual(1, Directory.GetFiles(_folder).Length, "no temporary file is left behind");
    }

    [TestMethod]
    public void IgnoringAgain_ReplacesTheReason_AndStoppingRemovesIt()
    {
        AppSettings settings = new AppSettings()
            .WithIgnored("a", "first", Now)
            .WithIgnored("b", "other", Now)
            .WithIgnored("a", "second", Now.AddDays(1));

        CollectionAssert.AreEqual(new[] { "b", "a" }, settings.Ignored.Select(i => i.CheckId).ToArray());
        Assert.AreEqual("second", settings.IgnoredOf("a")!.Reason);
        Assert.IsTrue(settings.IgnoredIds().SetEquals(["a", "b"]));

        AppSettings without = settings.WithoutIgnored("a");
        Assert.IsNull(without.IgnoredOf("a"));
        Assert.IsNotNull(without.IgnoredOf("b"));
        Assert.IsNull(settings.IgnoredOf("A"), "identifiers are matched exactly");
    }

    [TestMethod]
    public void AReason_IsKeptAsOneLine_WithinItsLimit()
    {
        Assert.AreEqual("a b c", AppSettings.Clean(" a\r\n b\t\tc "));
        Assert.AreEqual(AppSettings.MaximumReasonLength, AppSettings.Clean(new string('x', 500)).Length);
        Assert.AreEqual(string.Empty, AppSettings.Clean("   "));
        Assert.AreEqual("ab", AppSettings.Clean("a" + (char)7 + "b"));
    }

    [TestMethod]
    [DataRow("{ not json", "The settings file could not be understood.")]
    [DataRow("", "The settings file could not be understood.")]
    [DataRow("null", "The settings file is from another version of SecReview.")]
    [DataRow("{ \"version\": 2, \"firstRunDone\": true }", "The settings file is from another version of SecReview.")]
    [DataRow("{ \"version\": 1, \"ignored\": \"all\" }", "The settings file could not be understood.")]
    public void AFileThatCannotBeUsed_GivesTheDefaults_AndIsKeptAside(string contents, string expectedProblem)
    {
        Directory.CreateDirectory(_folder);
        System.IO.File.WriteAllText(File, contents);

        AppSettings settings = new SettingsStore(_folder).Load(out string? problem);

        Assert.AreEqual(expectedProblem, problem);
        Assert.IsFalse(settings.FirstRunDone);
        Assert.IsFalse(System.IO.File.Exists(File));
        string aside = Directory.GetFiles(_folder, SettingsStore.FileName + ".unreadable-*").Single();
        Assert.AreEqual(contents, System.IO.File.ReadAllText(aside), "what the user had is not thrown away");
    }

    [TestMethod]
    public void TwoDamagedFilesInARow_AreBothKept()
    {
        Directory.CreateDirectory(_folder);
        var store = new SettingsStore(_folder);

        System.IO.File.WriteAllText(File, "first damaged file");
        store.Load(out _);
        System.IO.File.WriteAllText(File, "second damaged file");
        store.Load(out _);

        CollectionAssert.AreEquivalent(
            new[] { "first damaged file", "second damaged file" },
            Directory.GetFiles(_folder, SettingsStore.FileName + ".unreadable-*").Select(System.IO.File.ReadAllText).ToArray());
    }

    [TestMethod]
    public void AFileThatCouldNotBeRead_IsNeverReplacedByDefaults()
    {
        // Another program holds the file for a moment (antivirus, backup, a second SecReview).
        var store = new SettingsStore(_folder);
        store.Save(new AppSettings { FirstRunDone = true }.WithIgnored("firewall.enabled", "lab PC", Now), out _);
        string good = System.IO.File.ReadAllText(File);

        using (new FileStream(File, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            AppSettings defaults = store.Load(out string? problem);
            Assert.IsFalse(defaults.FirstRunDone);
            StringAssert.StartsWith(problem, "The settings file could not be read");

            // The window now closes its first-run notice and tries to save that.
            Assert.IsFalse(store.Save(defaults with { FirstRunDone = true }, out string? saveProblem));
            Assert.AreEqual("The settings were not saved: the settings file on disk cannot be read, and saving would replace it.", saveProblem);
        }

        Assert.AreEqual(good, System.IO.File.ReadAllText(File), "the ignored checks and their reasons are still there");

        // Once the file can be read again, saving works: nothing is being replaced unseen.
        Assert.IsTrue(store.Save(store.Load(out _).WithIgnored("sc.uv.cooldown", "x", Now), out _));
        Assert.AreEqual(2, store.Load(out _).Ignored.Count);
    }

    [TestMethod]
    public void EntriesThatMakeNoSense_AreDropped_TheRestIsKept()
    {
        Directory.CreateDirectory(_folder);
        string longReason = new('r', 900);
        System.IO.File.WriteAllText(File, $$"""
            {
              "version": 1,
              "firstRunDone": true,
              "somethingFromALaterVersion": 5,
              "ignored": [
                { "checkId": "firewall.enabled", "reason": "{{longReason}}", "since": "2026-11-12T09:00:00+00:00" },
                { "checkId": "firewall.enabled", "reason": "twice", "since": "2026-11-12T09:00:00+00:00" },
                { "checkId": "", "reason": "no check", "since": "2026-11-12T09:00:00+00:00" },
                { "checkId": "has spaces; and more", "reason": "x", "since": "2026-11-12T09:00:00+00:00" },
                { "reason": "no id at all", "since": "2026-11-12T09:00:00+00:00" },
                null,
                { "checkId": "sc.uv.cooldown", "since": "2026-11-12T09:00:00+00:00" }
              ]
            }
            """);

        AppSettings settings = new SettingsStore(_folder).Load(out string? problem);

        Assert.IsNull(problem);
        Assert.IsTrue(settings.FirstRunDone);
        CollectionAssert.AreEqual(new[] { "firewall.enabled", "sc.uv.cooldown" }, settings.Ignored.Select(i => i.CheckId).ToArray());
        Assert.AreEqual(AppSettings.MaximumReasonLength, settings.Ignored[0].Reason.Length);
        Assert.AreEqual(string.Empty, settings.Ignored[1].Reason);
    }

    [TestMethod]
    public void DamagedFiles_AlwaysGiveUsableSettings()
    {
        var store = new SettingsStore(_folder);
        store.Save(new AppSettings { FirstRunDone = true }.WithIgnored("firewall.enabled", "because", Now), out _);
        string good = System.IO.File.ReadAllText(File);
        var random = new Random(20261112);

        for (int round = 0; round < 500; round++)
        {
            System.IO.File.WriteAllText(File, Config.ConfigTesting.Damage(good, random));

            AppSettings settings = store.Load(out _);

            Assert.IsNotNull(settings.Ignored);
            Assert.IsTrue(settings.Ignored.All(i => i.CheckId.Length > 0 && i.Reason.Length <= AppSettings.MaximumReasonLength), $"round {round}");
            Assert.AreEqual(AppSettings.CurrentVersion, settings.Version);
        }
    }
}
