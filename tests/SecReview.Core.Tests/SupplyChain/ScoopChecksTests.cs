using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Scoop;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class ScoopChecksTests
{
    private static readonly string Root = FakeProbes.UserProfile + @"\scoop";
    private static readonly string ConfigPath = FakeProbes.UserProfile + @"\.config\scoop\config.json";
    private const string GlobalRoot = @"C:\ProgramData\scoop";

    private static readonly ScoopBucketsCheck Buckets = new();
    private static readonly ScoopAppsCheck Apps = new();
    private static readonly ScoopUpdatesCheck Updates = new();
    private static readonly ScoopCredentialsCheck Tokens = new();

    /// <summary>A PC with Scoop and nothing in it yet.</summary>
    private static FakeProbes Scoop() => new FakeProbes().WithFile(Root + @"\apps\scoop\current\bin\scoop.ps1", "# scoop");

    private static FakeProbes WithBucket(FakeProbes probes, string name, string address) => probes.WithFile(
        $@"{Root}\buckets\{name}\.git\config",
        $"[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = {address}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\n\tremote = origin\n");

    private static FakeProbes WithApp(
        FakeProbes probes, string name, string manifest, string install = """{ "bucket": "main", "architecture": "64bit" }""", string? root = null) => probes
        .WithFile($@"{root ?? Root}\apps\{name}\current\scoop-manifest.json", manifest)
        .WithFile($@"{root ?? Root}\apps\{name}\current\scoop-install.json", install);

    private const string GoodManifest = """{ "version": "1.2.3", "url": "https://example.test/tool.zip", "hash": "aa11" }""";

    [TestMethod]
    public void WithoutScoop_NoneOfTheChecksApply()
    {
        foreach (ICheck check in new ICheck[] { Buckets, Apps, Updates, Tokens })
        {
            Assert.AreEqual(CheckStatus.NotApplicable, check.Run(new FakeProbes()).Status, check.Definition.Id);
            Assert.AreEqual(CheckScope.User, check.Definition.Scope);
        }
    }

    // Where Scoop is

    [TestMethod]
    public void TheRoot_FollowsTheScoopVariable_ThenTheSettingsFile()
    {
        FakeProbes byVariable = WithBucket(new FakeProbes(), "main", "https://github.com/ScoopInstaller/Main")
            .WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "SCOOP", RegistryValue.FromText(@"D:\tools\scoop"))
            .WithFile(@"D:\tools\scoop\apps\scoop\current\bin\scoop.ps1", "#")
            .WithFile(@"D:\tools\scoop\buckets\odd\.git\config", "[remote \"origin\"]\n\turl = https://example.test/odd\n");
        Assert.AreEqual(CheckStatus.Fail, Buckets.Run(byVariable).Status, "the buckets under the variable's folder are the ones read");

        FakeProbes bySetting = new FakeProbes()
            .WithFile(ConfigPath, """{ "root_path": "D:\\other" }""")
            .WithFile(@"D:\other\apps\scoop\current\bin\scoop.ps1", "#");
        Assert.AreEqual(CheckStatus.Pass, Buckets.Run(bySetting).Status);
    }

    [TestMethod]
    public void ASettingsFileThatIsNotJson_IsCouldNotCheck()
    {
        FakeProbes probes = Scoop().WithFile(ConfigPath, "{ not json");

        Assert.AreEqual(CheckStatus.Error, Buckets.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Error, Tokens.Run(probes).Status);
    }

    // Buckets

    [TestMethod]
    public void Buckets_ScoopsOwn_Pass_HoweverTheAddressIsWritten()
    {
        FakeProbes probes = WithBucket(WithBucket(WithBucket(Scoop(),
            "main", "https://github.com/ScoopInstaller/Main"),
            "extras", "https://github.com/ScoopInstaller/Extras.git"),
            "versions", "https://github.com/scoopinstaller/versions/");

        CheckOutcome outcome = Buckets.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(3, outcome.Findings.Count);
    }

    [TestMethod]
    public void Buckets_AThirdPartyBucket_Fails_AndSaysWhereItComesFrom()
    {
        FakeProbes probes = WithBucket(WithBucket(Scoop(), "main", "https://github.com/ScoopInstaller/Main"), "vendor", "https://github.com/example/scoop-bucket.git");

        CheckOutcome outcome = Buckets.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 Scoop source is not one of Scoop's own.", outcome.Summary);
        Assert.AreEqual(
            "Bucket \"vendor\": From https://github.com/example/scoop-bucket.git (expected One of Scoop's known buckets) [problem]", outcome.Rows()[1]);
    }

    [TestMethod]
    public void Buckets_AKnownNameFromAnotherAddress_Fails()
    {
        CheckOutcome outcome = Buckets.Run(WithBucket(Scoop(), "main", "https://github.com/someone-else/Main"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Found, "not Scoop's own address for it");
    }

    [TestMethod]
    public void Buckets_ATokenInTheAddress_IsNeverShown()
    {
        CheckOutcome outcome = Buckets.Run(WithBucket(Scoop(), "private", "https://made-up-token@github.com/example/private-bucket"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("From https://github.com/example/private-bucket", outcome.Findings[0].Found);
    }

    [TestMethod]
    [DataRow("https://someone:made-up@pass@github.com/example/private-bucket", DisplayName = "an @ inside the password")]
    [DataRow("https://someone:made-up-password@github.com/example/private-bucket", DisplayName = "a user name and password")]
    [DataRow("https://github.com/example/private-bucket?token=made-up-token", DisplayName = "a token after ?")]
    [DataRow("https://github.com/example/private-bucket#made-up-token", DisplayName = "a token after #")]
    public void Buckets_ASecretAnywhereInTheAddress_IsNeverShown(string address)
    {
        CheckOutcome outcome = Buckets.Run(WithBucket(Scoop(), "private", address));

        Assert.AreEqual("From https://github.com/example/private-bucket", outcome.Findings[0].Found);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Item + f.Found + f.Expected + f.Source).Contains("made-up", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Buckets_AnAddressWithASignInPart_IsStillComparedByWhereItPoints()
    {
        Assert.AreEqual(CheckStatus.Pass, Buckets.Run(WithBucket(Scoop(), "main", "https://someone:made-up@github.com/ScoopInstaller/Main")).Status);
        Assert.AreEqual(CheckStatus.Fail, Buckets.Run(WithBucket(Scoop(), "main", "https://github.com@example.test/ScoopInstaller/Main")).Status);
    }

    [TestMethod]
    public void Buckets_ScoopItselfFromAnotherRepository_Fails()
    {
        FakeProbes probes = Scoop().WithFile(ConfigPath, """{ "scoop_repo": "https://github.com/example/Scoop" }""");
        Assert.AreEqual(CheckStatus.Fail, Buckets.Run(probes).Status);

        FakeProbes own = Scoop().WithFile(ConfigPath, """{ "scoop_repo": "https://github.com/ScoopInstaller/Scoop.git", "scoop_branch": "master" }""");
        Assert.AreEqual(CheckStatus.Pass, Buckets.Run(own).Status);
    }

    [TestMethod]
    public void Buckets_OneWhoseOriginCannotBeRead_IsCouldNotCheck()
    {
        FakeProbes noOrigin = Scoop().WithFile(Root + @"\buckets\odd\.git\config", "[core]\n\tbare = false\n");
        Assert.AreEqual(CheckStatus.Error, Buckets.Run(noOrigin).Status);

        FakeProbes denied = Scoop().WithFileFailure(Root + @"\buckets\odd\.git\config", ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Error, Buckets.Run(denied).Status);
    }

    // Apps

    [TestMethod]
    public void Apps_VerifiedAndFromABucket_Pass()
    {
        CheckOutcome outcome = Apps.Run(WithApp(WithApp(Scoop(), "tool", GoodManifest), "other", GoodManifest));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("All 2 apps installed with Scoop were verified and come from a bucket.", outcome.Summary);
    }

    [TestMethod]
    public void Apps_NoneInstalled_Pass()
    {
        Assert.AreEqual(CheckStatus.Pass, Apps.Run(Scoop()).Status);
    }

    [TestMethod]
    [DataRow("""{ "version": "1.0", "url": "https://example.test/a.zip" }""", "no hash, so the download was not verified")]
    [DataRow("""{ "version": "nightly", "url": "https://example.test/a.zip" }""", "a nightly build, which Scoop does not verify")]
    [DataRow("""{ "version": "1.0", "url": "http://example.test/a.zip", "hash": "aa" }""", "downloaded over plain HTTP")]
    [DataRow("""{ "version": "1.0", "url": ["https://example.test/a.zip", "http://example.test/b.zip"], "hash": ["aa", "bb"] }""", "downloaded over plain HTTP")]
    [DataRow("""{ "version": "1.0", "architecture": { "64bit": { "url": "http://example.test/a.zip", "hash": "aa" }, "32bit": { "url": "https://example.test/b.zip", "hash": "bb" } } }""", "downloaded over plain HTTP")]
    [DataRow("""{ "version": "1.0", "architecture": { "64bit": { "url": "https://example.test/a.zip" } } }""", "no hash, so the download was not verified")]
    [DataRow("""{ "version": "1.0", "url": ["https://example.test/a.zip", "https://example.test/b.zip"], "hash": ["aa"] }""", "no hash for some of its downloads")]
    [DataRow("""{ "version": "1.0", "url": ["https://example.test/a.zip", "https://example.test/b.zip"], "hash": "aa" }""", "no hash for some of its downloads")]
    [DataRow("""{ "version": "1.0", "url": "https://example.test/a.zip", "hash": [""] }""", "no hash, so the download was not verified")]
    public void Apps_EachWeakness_Fails_AndIsNamed(string manifest, string found)
    {
        CheckOutcome outcome = Apps.Run(WithApp(WithApp(Scoop(), "good", GoodManifest), "weak", manifest));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 Scoop app has a weakness in how it was downloaded or where it comes from.", outcome.Summary);
        Assert.AreEqual($"weak: {found} (expected Verified download from a bucket) [problem]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void Apps_TheOtherProcessorsDownload_DoesNotCount()
    {
        const string Manifest = """{ "version": "1.0", "architecture": { "64bit": { "url": "https://example.test/a.zip", "hash": "aa" }, "32bit": { "url": "http://example.test/b.zip", "hash": "bb" } } }""";

        Assert.AreEqual(CheckStatus.Pass, Apps.Run(WithApp(Scoop(), "tool", Manifest)).Status);
    }

    [TestMethod]
    public void Apps_NotFromABucket_OrDeprecated_Fails()
    {
        CheckOutcome noBucket = Apps.Run(WithApp(Scoop(), "tool", GoodManifest, """{ "architecture": "64bit", "url": "https://example.test/tool.json" }"""));
        Assert.AreEqual("tool: not from a bucket (expected Verified download from a bucket) [problem]", noBucket.Rows()[0]);

        FakeProbes deprecated = WithApp(Scoop(), "tool", GoodManifest).WithFile(Root + @"\buckets\main\deprecated\tool.json", GoodManifest);
        Assert.AreEqual("tool: marked as deprecated in its bucket (expected Verified download from a bucket) [problem]", Apps.Run(deprecated).Rows()[0]);
    }

    [TestMethod]
    public void Apps_SeveralWeaknessesOfOneApp_AreOneRow()
    {
        CheckOutcome outcome = Apps.Run(WithApp(Scoop(), "tool", """{ "version": "1.0", "url": "http://example.test/a.zip" }""", """{ "architecture": "64bit" }"""));

        Assert.AreEqual(
            "tool: no hash, so the download was not verified, downloaded over plain HTTP and not from a bucket (expected Verified download from a bucket) [problem]",
            outcome.Rows()[0]);
    }

    [TestMethod]
    public void Apps_InstalledForAllUsers_AreIncluded_AndOldFileNamesAreRead()
    {
        FakeProbes probes = Scoop()
            .WithFile(GlobalRoot + @"\apps\shared\current\manifest.json", """{ "version": "1.0", "url": "https://example.test/a.zip" }""")
            .WithFile(GlobalRoot + @"\apps\shared\current\install.json", """{ "bucket": "main", "architecture": "64bit" }""");

        CheckOutcome outcome = Apps.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.StartsWith(outcome.Rows()[0], "shared: no hash");
    }

    [TestMethod]
    public void Apps_ScriptsAtInstallTime_AreCounted_NotFailed()
    {
        const string WithScript = """{ "version": "1.0", "url": "https://example.test/a.zip", "hash": "aa", "post_install": ["echo done"] }""";
        const string WithInstaller = """{ "version": "1.0", "url": "https://example.test/a.zip", "hash": "aa", "installer": { "script": "run" } }""";

        CheckOutcome outcome = Apps.Run(WithApp(WithApp(WithApp(Scoop(), "a", WithScript), "b", WithInstaller), "c", GoodManifest));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Apps whose manifest runs scripts at install time: 2 of 3 [note]", outcome.Rows()[^1]);
    }

    [TestMethod]
    public void Apps_AnInstallRecordThatCannotBeRead_IsCouldNotCheck()
    {
        FakeProbes broken = WithApp(Scoop(), "tool", "{ not json");
        Assert.AreEqual(CheckStatus.Error, Apps.Run(broken).Status);

        FakeProbes missing = Scoop().WithFile(Root + @"\apps\tool\current\scoop-manifest.json", GoodManifest);
        Assert.AreEqual(CheckStatus.Error, Apps.Run(missing).Status, "no install record");

        FakeProbes closed = WithApp(Scoop(), "tool", GoodManifest).WithFolderFailure(Root + @"\apps\tool", ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Error, Apps.Run(closed).Status, "a folder that cannot be opened is an app, not no app");
    }

    // Updates

    private static FakeProbes WithBucketManifest(FakeProbes probes, string app, string version, bool inBucketFolder = true) =>
        probes.WithFile(inBucketFolder ? $@"{Root}\buckets\main\bucket\{app}.json" : $@"{Root}\buckets\main\{app}.json", $$"""{ "version": "{{version}}" }""");

    private static FakeProbes Fetched(FakeProbes probes, int daysAgo)
    {
        probes.FileTime = CheckTesting.Now.AddDays(-daysAgo);
        return probes.WithFile(Root + @"\buckets\main\.git\FETCH_HEAD", "abc\t\tbranch 'master'");
    }

    [TestMethod]
    public void Updates_AllAtTheBucketsVersion_Pass()
    {
        FakeProbes probes = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.2.3"), daysAgo: 2);

        CheckOutcome outcome = Updates.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Scoop last looked for updates: 2 days ago (expected Within 14 days) [ok]", outcome.Rows()[^1]);
    }

    [TestMethod]
    public void Updates_AnAppBehindItsBucket_Fails_AndIsNamed()
    {
        FakeProbes probes = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.3.0", inBucketFolder: false), daysAgo: 0);

        CheckOutcome outcome = Updates.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("tool has an update waiting in Scoop.", outcome.Summary);
        Assert.AreEqual("tool: 1.2.3 (expected 1.3.0) [problem]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void Updates_AnAppHeldBackOnPurpose_IsListed_NotFailed()
    {
        FakeProbes probes = Fetched(
            WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest, """{ "bucket": "main", "architecture": "64bit", "hold": true }"""), "tool", "1.3.0"),
            daysAgo: 1);

        CheckOutcome outcome = Updates.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.IsTrue(outcome.Rows().Any(r => r.StartsWith("tool: 1.2.3, held back on purpose; the bucket has 1.3.0", StringComparison.Ordinal)));
        Assert.AreEqual("Scoop last looked for updates: 1 day ago (expected Within 14 days) [ok]", outcome.Rows()[^1]);
    }

    [TestMethod]
    public void Updates_AnAppThatCannotBeCompared_IsCouldNotCheck_NotAPass()
    {
        FakeProbes good = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.2.3"), daysAgo: 1);

        CheckOutcome brokenRecord = Updates.Run(WithApp(good, "other", GoodManifest, "{ not json"));
        Assert.AreEqual(CheckStatus.Error, brokenRecord.Status);
        Assert.AreEqual("1 Scoop app could not be compared with its bucket.", brokenRecord.Summary);
        Assert.AreEqual("other: Its install record could not be read (expected The version in its bucket) [problem]", brokenRecord.Rows()[0]);

        FakeProbes again = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.2.3"), daysAgo: 1);
        CheckOutcome brokenBucket = Updates.Run(WithApp(again, "other", GoodManifest).WithFile(Root + @"\buckets\main\bucket\other.json", "{ not json"));
        Assert.AreEqual(CheckStatus.Error, brokenBucket.Status);
        StringAssert.Contains(brokenBucket.Rows()[0], "Its bucket's manifest could not be read");

        FakeProbes closed = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.2.3"), daysAgo: 1)
            .WithFolderFailure(Root + @"\apps\tool", ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Error, Updates.Run(closed).Status);
    }

    [TestMethod]
    public void Updates_AnAppBehind_StillFails_WhenAnotherCannotBeCompared()
    {
        FakeProbes probes = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.3.0"), daysAgo: 1);

        Assert.AreEqual(CheckStatus.Fail, Updates.Run(WithApp(probes, "other", GoodManifest, "{ not json")).Status);
    }

    [TestMethod]
    public void Updates_AnAppItsBucketNoLongerOffers_IsSaid_NotFailed()
    {
        CheckOutcome outcome = Updates.Run(Fetched(WithApp(Scoop(), "tool", GoodManifest), daysAgo: 1));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Scoop has no updates waiting; 1 app is no longer offered by its bucket.", outcome.Summary);
        Assert.AreEqual("tool: 1.2.3; its bucket no longer offers it [note]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void Updates_StaleBuckets_Fail_BecauseLatestIsNotKnown()
    {
        FakeProbes probes = Fetched(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.2.3"), daysAgo: 20);

        CheckOutcome outcome = Updates.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Scoop has not looked for updates for 20 days, so it cannot know what is outdated.", outcome.Summary);
    }

    [TestMethod]
    public void Updates_WhenTheLastRefreshIsNotRecorded_SaysSo()
    {
        CheckOutcome outcome = Updates.Run(WithBucketManifest(WithApp(Scoop(), "tool", GoodManifest), "tool", "1.2.3"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        StringAssert.Contains(outcome.Summary, "not recorded");
    }

    [TestMethod]
    public void Updates_ABucketNameThatIsNotAName_IsNeverUsedAsAPath()
    {
        FakeProbes probes = WithApp(Scoop(), "tool", GoodManifest, """{ "bucket": "..\\..\\elsewhere", "architecture": "64bit" }""")
            .WithFile(Root + @"\buckets\..\..\elsewhere\bucket\tool.json", """{ "version": "9.9.9" }""");

        Assert.AreEqual(CheckStatus.Pass, Updates.Run(probes).Status, "the app is skipped, not looked up outside Scoop's folder");
    }

    // Tokens

    [TestMethod]
    public void Tokens_NoneStored_Pass()
    {
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(Scoop()).Status);
        Assert.AreEqual(
            CheckStatus.Pass, Tokens.Run(Scoop().WithFile(ConfigPath, """{ "last_update": "2026-11-11T08:00:00", "proxy": "proxy.example:8080", "gh_token": "" }""")).Status);
    }

    [TestMethod]
    [DataRow("""{ "gh_token": "made-up-token" }""", "GitHub token")]
    [DataRow("""{ "virustotal_api_key": "made-up-key" }""", "VirusTotal key")]
    [DataRow("""{ "proxy": "someone:made-up-password@proxy.example:8080" }""", "Proxy password")]
    [DataRow("""{ "private_hosts": [ { "match": "example\\.test", "headers": "Authorization: made-up" } ] }""", "Sign-in headers for private hosts")]
    [DataRow("""{ "GH_Token": "made-up-token" }""", "GitHub token")]
    [DataRow("""{ "Private_Hosts": [ { "Match": "example\\.test", "Headers": "Authorization: made-up" } ] }""", "Sign-in headers for private hosts")]
    [DataRow("""{ "proxy": "someone:made-up@word@proxy.example:8080" }""", "Proxy password")]
    public void Tokens_EachStoredSecret_Fails_NamingTheSettingOnly(string config, string item)
    {
        CheckOutcome outcome = Tokens.Run(Scoop().WithFile(ConfigPath, config));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(item, outcome.Findings[0].Item);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Item + f.Found + f.Source).Contains("made-up", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Tokens_InAPermanentVariable_Fail()
    {
        FakeProbes probes = Scoop().WithRegistryValue(
            RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "SCOOP_GH_TOKEN", RegistryValue.FromText("made-up-token"));

        CheckOutcome outcome = Tokens.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Scoop keeps a token as plain text.", outcome.Summary);
    }

    [TestMethod]
    public void APortableSettingsFile_BesideScoop_WinsOverTheUsualOne()
    {
        FakeProbes probes = Scoop()
            .WithFile(ConfigPath, """{ "gh_token": "" }""")
            .WithFile(Root + @"\config.json", """{ "gh_token": "made-up-token" }""");

        Assert.AreEqual(CheckStatus.Fail, Tokens.Run(probes).Status);
    }
}
