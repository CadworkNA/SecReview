using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Credentials;
using SecReview.Tests.Checks;
using SecReview.Tests.Config;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

/// <summary>Stored sign-ins of Docker, the GitHub CLI, cloud tools and build tools, and Docker's settings.</summary>
[TestClass]
public sealed class StoredCredentialChecksTests
{
    private static readonly string Profile = FakeProbes.UserProfile;
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);

    private static readonly string DockerConfig = Profile + @"\.docker\config.json";
    private static readonly string DockerDaemon = Profile + @"\.docker\daemon.json";
    private static readonly string DockerDesktop = Roaming + @"\Docker\settings-store.json";
    private static readonly string GhHosts = Roaming + @"\GitHub CLI\hosts.yml";
    private static readonly string AwsCredentials = Profile + @"\.aws\credentials";
    private static readonly string KubeConfig = Profile + @"\.kube\config";
    private static readonly string Terraform = Roaming + @"\terraform.d\credentials.tfrc.json";
    private static readonly string AzureTokens = Profile + @"\.azure\accessTokens.json";
    private static readonly string MavenSettings = Profile + @"\.m2\settings.xml";
    private static readonly string GradleProperties = Profile + @"\.gradle\gradle.properties";
    private static readonly string GemCredentials = Profile + @"\.gem\credentials";
    private static readonly string ComposerAuth = Roaming + @"\Composer\auth.json";

    private static FakeProbes File(string path, string text) => new FakeProbes().WithFile(path, text);

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    private static IEnumerable<object[]> Checks =>
    [
        [new DockerCredentialsCheck()], [new DockerSettingsCheck()], [new GitHubCliCredentialsCheck()],
        [new CloudCredentialsCheck()], [new BuildCredentialsCheck()],
    ];

    [TestMethod]
    [DynamicData(nameof(Checks))]
    public void WithoutTheFiles_TheCheckDoesNotApply_AndItNeverRunsElevated(ICheck check)
    {
        Assert.AreEqual(CheckStatus.NotApplicable, check.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, check.Definition.Scope);
    }

    // Docker sign-ins

    [TestMethod]
    public void Docker_WithACredentialStore_TheFileHoldsOnlyNames_AndPasses()
    {
        const string Config = """{ "auths": { "https://index.docker.io/v1/": {}, "registry.example.test": {} }, "credsStore": "desktop" }""";

        Assert.AreEqual(CheckStatus.Pass, new DockerCredentialsCheck().Run(File(DockerConfig, Config)).Status);
    }

    [TestMethod]
    public void Docker_PasswordsInTheFile_Fail_NamingTheRegistryOnly()
    {
        const string Config = """
            { "auths": {
                "https://index.docker.io/v1/": { "auth": "bWFkZS11cDptYWRlLXVw" },
                "registry.example.test:5000": { "identitytoken": "made-up-token" },
                "other.example.test": {} } }
            """;

        CheckOutcome outcome = new DockerCredentialsCheck().Run(File(DockerConfig, Config));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Docker: 2 secrets are stored as plain text.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "Sign-in for index.docker.io", "Sign-in for registry.example.test:5000" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("bWFkZS", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Docker_TheFolderCanBeMoved_AndABrokenFileIsCouldNotCheck()
    {
        FakeProbes moved = WithVariable(new FakeProbes(), "DOCKER_CONFIG", @"D:\docker")
            .WithFile(@"D:\docker\config.json", """{ "auths": { "registry.example.test": { "auth": "bWFkZS11cA==" } } }""");
        Assert.AreEqual(CheckStatus.Fail, new DockerCredentialsCheck().Run(moved).Status);

        Assert.AreEqual(CheckStatus.Error, new DockerCredentialsCheck().Run(File(DockerConfig, "{ not json")).Status);
    }

    // Docker settings

    [TestMethod]
    public void DockerSettings_Defaults_Pass()
    {
        FakeProbes probes = File(DockerDaemon, """{ "builder": { "gc": { "enabled": true } }, "experimental": false }""")
            .WithFile(DockerDesktop, """{ "AutoStart": false, "ExposeDockerAPIOnTCP2375": false }""");

        Assert.AreEqual(CheckStatus.Pass, new DockerSettingsCheck().Run(probes).Status);
    }

    [TestMethod]
    [DataRow("""{ "insecure-registries": ["registry.example.test:5000"] }""", "Docker: registries exempt from TLS checks: 1.")]
    [DataRow("""{ "hosts": ["npipe://", "tcp://0.0.0.0:2375"] }""", "Docker: control port: open over TCP without client certificates.")]
    public void DockerSettings_AWeakEngineSetting_Fails(string daemon, string summary)
    {
        CheckOutcome outcome = new DockerSettingsCheck().Run(File(DockerDaemon, daemon));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void DockerSettings_ATcpPortWithClientCertificates_OrNoRegistries_Passes()
    {
        Assert.AreEqual(
            CheckStatus.Pass,
            new DockerSettingsCheck().Run(File(DockerDaemon, """{ "hosts": ["tcp://0.0.0.0:2376"], "tlsverify": true, "insecure-registries": [] }""")).Status);
    }

    [TestMethod]
    public void DockerSettings_DockerDesktopsOpenPort_Fails_AndThePcsEngineFileCounts()
    {
        CheckOutcome desktop = new DockerSettingsCheck().Run(File(DockerDesktop, """{ "exposeDockerAPIOnTCP2375": true }"""));
        Assert.AreEqual("Docker: control port: open on TCP 2375 without sign-in.", desktop.Summary);

        CheckOutcome machine = new DockerSettingsCheck().Run(File(@"C:\ProgramData\docker\config\daemon.json", """{ "insecure-registries": ["a", "b"] }"""));
        Assert.AreEqual(CheckStatus.Fail, machine.Status);
    }

    // GitHub CLI

    [TestMethod]
    public void GitHubCli_WithTheTokenInWindowsStore_TheFileHasNone_AndPasses()
    {
        const string Hosts = "github.com:\n    git_protocol: https\n    users:\n        someone:\n    user: someone\n";

        Assert.AreEqual(CheckStatus.Pass, new GitHubCliCredentialsCheck().Run(File(GhHosts, Hosts)).Status);
    }

    [TestMethod]
    public void GitHubCli_ATokenInTheFile_Fails_OncePerHost_WithoutShowingIt()
    {
        const string Hosts = "github.com:\n    oauth_token: made-up-token\n    user: someone\n    users:\n        someone:\n            oauth_token: made-up-token\nghe.example.test:\n    users:\n        other:\n            oauth_token: made-up-other\n";

        CheckOutcome outcome = new GitHubCliCredentialsCheck().Run(File(GhHosts, Hosts));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.AreEqual(new[] { "Token for github.com", "Token for ghe.example.test" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.AreEqual($"{GhHosts}, line 2", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("someone", StringComparison.Ordinal));
    }

    // Cloud

    [TestMethod]
    public void Cloud_AnAwsKeyWithoutASessionToken_Fails_AndATemporaryOneDoesNot()
    {
        const string Credentials = "[default]\naws_access_key_id = AKIAMADEUPMADEUPMADE\naws_secret_access_key = made-up-secret\n\n[temporary]\naws_access_key_id = ASIAMADEUP\naws_secret_access_key = made-up-other\naws_session_token = made-up-session\n";

        CheckOutcome outcome = new CloudCredentialsCheck().Run(File(AwsCredentials, Credentials));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Cloud tools: 1 secret is stored as plain text.", outcome.Summary);
        Assert.AreEqual("AWS access key (profile \"default\")", outcome.Findings[0].Item);
        Assert.AreEqual($"{AwsCredentials}, line 3", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("AKIA", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Cloud_AFixedKubernetesTokenOrPassword_Fails_ByEntryNumber()
    {
        const string Kube = """
            apiVersion: v1
            kind: Config
            users:
            - name: someone@example.test
              user:
                exec:
                  command: kubelogin
            - name: other
              user:
                token: made-up-token
            - name: third
              user:
                username: admin
                password: made-up-password
            """;

        CheckOutcome outcome = new CloudCredentialsCheck().Run(File(KubeConfig, Kube));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.AreEqual(
            new[] { "Kubernetes sign-in (user entry 2)", "Kubernetes sign-in (user entry 3)" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("someone", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Cloud_TerraformTokens_AndTheOldAzureCache_Fail()
    {
        CheckOutcome terraform = new CloudCredentialsCheck().Run(
            File(Terraform, """{ "credentials": { "app.terraform.io": { "token": "made-up-token" } } }"""));
        Assert.AreEqual("Terraform token for app.terraform.io", terraform.Findings[0].Item);

        CheckOutcome azure = new CloudCredentialsCheck().Run(File(AzureTokens, """[ { "accessToken": "made-up", "userId": "someone" } ]"""));
        Assert.AreEqual(CheckStatus.Fail, azure.Status);
        Assert.IsFalse(Everything(azure).Contains("made-up", StringComparison.Ordinal));

        Assert.AreEqual(CheckStatus.Pass, new CloudCredentialsCheck().Run(File(AzureTokens, "[]")).Status, "an emptied cache is fine");
    }

    [TestMethod]
    public void Cloud_SettingsWithoutSecrets_Pass_AndBrokenFilesAreCouldNotCheck()
    {
        FakeProbes clean = File(AwsCredentials, "[default]\nsso_session = work\n").WithFile(KubeConfig, "apiVersion: v1\nusers: []\n");
        Assert.AreEqual(CheckStatus.Pass, new CloudCredentialsCheck().Run(clean).Status);

        Assert.AreEqual(CheckStatus.Error, new CloudCredentialsCheck().Run(File(KubeConfig, "users: &anchor []\n")).Status);
        Assert.AreEqual(CheckStatus.Error, new CloudCredentialsCheck().Run(File(AzureTokens, "[ not json")).Status);
        Assert.AreEqual(
            CheckStatus.Error, new CloudCredentialsCheck().Run(new FakeProbes().WithFileFailure(AwsCredentials, ProbeFailure.AccessDenied())).Status);
    }

    // What the reviews found

    [TestMethod]
    public void Cloud_AListOfKubernetesFiles_IsReadFileByFile()
    {
        FakeProbes probes = WithVariable(new FakeProbes(), "KUBECONFIG", @"D:\kube\one;D:\kube\two")
            .WithFile(@"D:\kube\one", "apiVersion: v1\nusers: []\n")
            .WithFile(@"D:\kube\two", "users:\n- name: x\n  user:\n    token: made-up-token\n");

        CheckOutcome outcome = new CloudCredentialsCheck().Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(@"D:\kube\two, line 4", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void GitHubCli_ItsFolderUnderTheConfigHomeVariable_IsRead()
    {
        FakeProbes probes = WithVariable(new FakeProbes(), "XDG_CONFIG_HOME", @"D:\config")
            .WithFile(@"D:\config\gh\hosts.yml", "github.com:\n    oauth_token: made-up-token\n");

        Assert.AreEqual(CheckStatus.Fail, new GitHubCliCredentialsCheck().Run(probes).Status);
    }

    [TestMethod]
    [DataRow("$ummer2026", true)]
    [DataRow("%percent%", true)]
    [DataRow("${REPO_PASSWORD}", false)]
    [DataRow("${a}and${b}", true)]
    public void OnlyABracedReference_IsNotALiteralSecret(string value, bool literal)
    {
        Assert.AreEqual(literal, SecretFindings.IsLiteral(value));
    }

    // Build tools

    [TestMethod]
    public void Build_MavenPasswords_Fail_UnlessEncryptedOrAReference()
    {
        const string Settings = """
            <settings>
              <servers>
                <server><id>releases</id><username>someone</username><password>made-up-password</password></server>
                <server><id>encrypted</id><password>{COQLCE6DU6GtcS5P=}</password></server>
                <server><id>fromVariable</id><password>${env.REPO_PASSWORD}</password></server>
              </servers>
              <proxies>
                <proxy><id>corp</id><password>made-up-proxy</password></proxy>
              </proxies>
            </settings>
            """;

        CheckOutcome outcome = new BuildCredentialsCheck().Run(File(MavenSettings, Settings));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.AreEqual(
            new[] { "Maven password for server \"releases\"", "Maven password for proxy \"corp\"" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.AreEqual($"{MavenSettings}, line 3", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("someone", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Build_GradleProperties_NamedLikeASecret_Fail()
    {
        const string Properties = "# publishing\norg.gradle.jvmargs=-Xmx2g\nossrhUsername=someone\nossrhPassword=made-up-password\nsigning.secretKeyRingFile=C:/keys/ring.gpg\nsigning.keyId=ABCD1234\ngithubToken = made-up-token\nfromVariable.token=${TOKEN}\n";

        CheckOutcome outcome = new BuildCredentialsCheck().Run(File(GradleProperties, Properties));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.AreEqual(new[] { "Gradle property ossrhPassword", "Gradle property githubToken" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.AreEqual($"{GradleProperties}, line 4", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Build_RubyGemsKeys_AndComposerSignIns_Fail()
    {
        CheckOutcome gems = new BuildCredentialsCheck().Run(File(GemCredentials, "---\n:rubygems_api_key: made-up-key\n"));
        Assert.AreEqual("RubyGems key \"rubygems_api_key\"", gems.Findings[0].Item);

        const string Auth = """
            { "http-basic": { "repo.example.test": { "username": "someone", "password": "made-up-password" } },
              "github-oauth": { "github.com": "made-up-token" },
              "bearer": {} }
            """;
        CheckOutcome composer = new BuildCredentialsCheck().Run(File(ComposerAuth, Auth));
        CollectionAssert.AreEqual(
            new[] { "Composer sign-in for repo.example.test", "Composer sign-in for github.com" }, composer.Findings.Select(f => f.Item).ToArray());
        Assert.IsFalse(Everything(composer).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(composer).Contains("someone", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Build_SettingsWithoutSecrets_Pass_AndBrokenFilesAreCouldNotCheck()
    {
        FakeProbes clean = File(MavenSettings, "<settings><localRepository>D:/m2</localRepository></settings>")
            .WithFile(GradleProperties, "org.gradle.parallel=true\n");
        Assert.AreEqual(CheckStatus.Pass, new BuildCredentialsCheck().Run(clean).Status);

        Assert.AreEqual(CheckStatus.Error, new BuildCredentialsCheck().Run(File(MavenSettings, "<settings><servers>")).Status);
        Assert.AreEqual(
            CheckStatus.Error, new BuildCredentialsCheck().Run(new FakeProbes().WithFileFailure(GradleProperties, ProbeFailure.AccessDenied())).Status);

        FakeProbes both = File(MavenSettings, "<settings><servers>").WithFile(GradleProperties, "repoPassword=made-up\n");
        Assert.AreEqual(CheckStatus.Fail, new BuildCredentialsCheck().Run(both).Status, "a found secret still fails");
    }

    // The properties reader

    [TestMethod]
    public void Properties_AreReadInAllTheirForms()
    {
        const char Backslash = (char)92;
        string text = $"# comment\n! another\na=1\nb : two words\nc three\n  d = spaced  \nlong = one {Backslash}\n   two\nempty=\nwith{Backslash}=sign = x\n";

        IReadOnlyList<PropertyEntry> entries = PropertiesReader.Read(text);

        CollectionAssert.AreEqual(
            new[] { "a=1@3", "b=two words@4", "c=three@5", "d=spaced  @6", "long=one two@7", "empty=@9", "with=sign=x@10" },
            entries.Select(e => $"{e.Key}={e.Value}@{e.Line}").ToArray());
    }

    [TestMethod]
    public void Properties_AVeryLongRunOfContinuedLines_IsReadInOnePass()
    {
        const char Backslash = (char)92;
        string text = "key=" + string.Concat(Enumerable.Repeat($"{Backslash}{Backslash}{Backslash}\n", 200_000)) + "end\n";

        var watch = System.Diagnostics.Stopwatch.StartNew();
        IReadOnlyList<PropertyEntry> entries = PropertiesReader.Read(text);

        Assert.AreEqual(1, entries.Count);
        Assert.IsTrue(watch.Elapsed < TimeSpan.FromSeconds(5), $"took {watch.Elapsed}");
    }

    [TestMethod]
    public void Properties_DamagedFiles_AlwaysEndWithAnAnswer()
    {
        const string Text = "# c\na=1\nb : two\nlong = one \\\n  two\nrepoPassword=x\n";
        var random = new Random(20261112);

        for (int round = 0; round < 2000; round++)
        {
            Assert.IsNotNull(PropertiesReader.Read(ConfigTesting.Damage(Text, random)));
        }
    }
}
