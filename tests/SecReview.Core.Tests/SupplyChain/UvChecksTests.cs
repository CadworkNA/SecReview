using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Uv;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class UvChecksTests
{
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);
    private static readonly string Local = FakeProbes.FolderPath(KnownFolder.LocalAppData);

    private static readonly string UserConfig = Roaming + @"\uv\uv.toml";
    private const string SystemConfig = @"C:\ProgramData\uv\uv.toml";
    private static readonly string Receipt = Local + @"\uv\uv-receipt.json";
    private static readonly string Credentials = Roaming + @"\uv\credentials\credentials.toml";

    private static readonly UvCooldownCheck Cooldown = new();
    private static readonly UvSourcesCheck Sources = new();
    private static readonly UvCredentialsCheck Secrets = new();

    /// <summary>A PC with uv: a user settings file with the given text and, unless told otherwise, a receipt saying 0.12.19.</summary>
    private static FakeProbes Uv(string settings, string? version = "0.12.19")
    {
        FakeProbes probes = new FakeProbes().WithFile(UserConfig, settings);
        return version is null ? probes : probes.WithFile(Receipt, $$"""{ "version": "{{version}}" }""");
    }

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    // Not installed, and scope

    [TestMethod]
    public void WithoutUv_NoneOfTheChecksApply()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Cooldown.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Sources.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Secrets.Run(new FakeProbes()).Status);
    }

    [TestMethod]
    public void TheChecks_ReadTheUsersOwnFiles_SoNeverRunElevated()
    {
        Assert.AreEqual(CheckScope.User, Cooldown.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Sources.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Secrets.Definition.Scope);
        Assert.AreEqual(CheckCategory.SupplyChain, Cooldown.Definition.Category);
    }

    // Cooldown

    [TestMethod]
    public void Cooldown_AWeek_WithAUvThatUnderstandsIt_Passes()
    {
        CheckOutcome outcome = Cooldown.Run(Uv("# my settings\nexclude-newer = \"7 days\"\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("uv waits 7 days before installing a new release.", outcome.Summary);
        Assert.AreEqual($"{UserConfig}, line 2", outcome.Findings[0].Source);
        Assert.AreEqual("uv version: 0.12.19 (expected 0.9.17 or later) [ok]", outcome.Rows()[1]);
    }

    [TestMethod]
    [DataRow("exclude-newer = \"1 week\"")]
    [DataRow("exclude-newer = \"P7D\"")]
    [DataRow("exclude-newer = \"30 days\"")]
    public void Cooldown_OtherWaysToWriteAWeekOrMore_Pass(string settings)
    {
        Assert.AreEqual(CheckStatus.Pass, Cooldown.Run(Uv(settings)).Status);
    }

    [TestMethod]
    public void Cooldown_NotSet_Fails_BecauseUvHasNoDefault()
    {
        CheckOutcome outcome = Cooldown.Run(Uv("link-mode = \"copy\"\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("uv installs new package versions the moment they are published.", outcome.Summary);
    }

    [TestMethod]
    public void Cooldown_UvPresentButNoSettingsFileAtAll_Fails()
    {
        FakeProbes probes = new FakeProbes().WithFile(Receipt, """{ "version": "0.12.19" }""");

        Assert.AreEqual(CheckStatus.Fail, Cooldown.Run(probes).Status);
    }

    [TestMethod]
    [DataRow("exclude-newer = \"3 days\"", "uv waits only 3 days before installing a new release.")]
    [DataRow("exclude-newer = \"2026-11-01T00:00:00Z\"", "uv's release cut-off is a fixed date, which stops protecting as time passes.")]
    [DataRow("exclude-newer = 2026-11-01", "uv's release cut-off is a fixed date, which stops protecting as time passes.")]
    [DataRow("exclude-newer = false", "uv's wait for new releases is switched off.")]
    public void Cooldown_TooShort_AFixedDate_OrSwitchedOff_Fails(string settings, string summary)
    {
        CheckOutcome outcome = Cooldown.Run(Uv(settings));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    [DataRow("exclude-newer = \"soon\"")]
    [DataRow("exclude-newer = 7")]
    [DataRow("exclude-newer = [\"7 days\"]")]
    [DataRow("exclude-newer = \"7 days\"\nthis line is not TOML\n")]
    public void Cooldown_AValueOrFileThatCannotBeUnderstood_IsCouldNotCheck(string settings)
    {
        Assert.AreEqual(CheckStatus.Error, Cooldown.Run(Uv(settings)).Status);
    }

    [TestMethod]
    public void Cooldown_AnUnreadableSettingsFile_IsCouldNotCheck_NotAFailure()
    {
        FakeProbes probes = new FakeProbes()
            .WithFile(Receipt, """{ "version": "0.12.19" }""")
            .WithFileFailure(UserConfig, ProbeFailure.AccessDenied());

        CheckOutcome outcome = Cooldown.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "uv.toml could not be read");
    }

    [TestMethod]
    public void Cooldown_AnOldUv_Fails_BecauseItDoesNotUnderstandALength()
    {
        CheckOutcome outcome = Cooldown.Run(Uv("exclude-newer = \"7 days\"", version: "0.9.16"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("uv 0.9.16 is too old for a wait written as a length of time; update uv.", outcome.Summary);
    }

    [TestMethod]
    public void Cooldown_VersionNotReadable_Passes_AndSaysWhatThatRestsOn()
    {
        CheckOutcome outcome = Cooldown.Run(Uv("exclude-newer = \"7 days\"", version: null));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(
            "uv is set to wait 7 days; this holds from uv 0.9.17, and the installed version could not be read.", outcome.Summary);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[1].Status);
        StringAssert.Contains(outcome.Findings[1].Found, "required-version");
    }

    [TestMethod]
    public void Cooldown_VersionNotReadable_ButARequiredVersion_SettlesIt()
    {
        CheckOutcome outcome = Cooldown.Run(Uv("exclude-newer = \"7 days\"\nrequired-version = \">=0.9.17\"", version: null));

        Assert.AreEqual("uv waits 7 days before installing a new release.", outcome.Summary);
        Assert.AreEqual(FindingStatus.Ok, outcome.Findings[1].Status);

        CheckOutcome tooLow = Cooldown.Run(Uv("exclude-newer = \"7 days\"\nrequired-version = \">=0.5.0\"", version: null));
        Assert.AreEqual(FindingStatus.Note, tooLow.Findings[1].Status);
    }

    [TestMethod]
    public void Cooldown_TheVersionMayComeFromScoop()
    {
        string scoop = FakeProbes.UserProfile + @"\scoop\apps\uv\current";
        FakeProbes probes = new FakeProbes()
            .WithFile(UserConfig, "exclude-newer = \"7 days\"")
            .WithFile(scoop + @"\scoop-manifest.json", """{ "version": "0.9.10" }""")
            .WithFile(scoop + @"\scoop-install.json", """{ "bucket": "main" }""");

        CheckOutcome outcome = Cooldown.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Summary, "uv 0.9.10 is too old");
    }

    [TestMethod]
    public void Cooldown_TheEnvironmentVariable_WinsOverTheFile()
    {
        FakeProbes off = WithVariable(Uv("exclude-newer = \"7 days\""), UvCooldownCheck.Variable, "false");
        CheckOutcome outcome = Cooldown.Run(off);
        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Source, "UV_EXCLUDE_NEWER");

        FakeProbes on = WithVariable(Uv("link-mode = \"copy\""), UvCooldownCheck.Variable, "10 days");
        Assert.AreEqual(CheckStatus.Pass, Cooldown.Run(on).Status);
    }

    [TestMethod]
    public void Cooldown_TheUsersFile_WinsOverThePcs_AndThePcsCountsWhenTheUsersIsSilent()
    {
        FakeProbes both = Uv("exclude-newer = \"7 days\"").WithFile(SystemConfig, "exclude-newer = false");
        Assert.AreEqual(CheckStatus.Pass, Cooldown.Run(both).Status);

        FakeProbes systemOnly = Uv("link-mode = \"copy\"").WithFile(SystemConfig, "exclude-newer = \"8 days\"");
        CheckOutcome outcome = Cooldown.Run(systemOnly);
        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual($"{SystemConfig}, line 1", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Cooldown_UvConfigFile_ReplacesBothFiles()
    {
        const string Other = @"D:\settings\uv.toml";
        FakeProbes probes = WithVariable(Uv("exclude-newer = \"7 days\""), "UV_CONFIG_FILE", Other).WithFile(Other, "link-mode = \"copy\"");
        Assert.AreEqual(CheckStatus.Fail, Cooldown.Run(probes).Status, "the usual file is not read any more");

        FakeProbes missing = WithVariable(Uv("exclude-newer = \"7 days\""), "UV_CONFIG_FILE", @"D:\gone\uv.toml");
        Assert.AreEqual(CheckStatus.Error, Cooldown.Run(missing).Status);
    }

    [TestMethod]
    public void Cooldown_PackagesExemptFromTheWait_AreListed()
    {
        CheckOutcome outcome = Cooldown.Run(Uv(
            "exclude-newer = \"7 days\"\nexclude-newer-package = { numpy = false, torch = \"1 day\", pandas = \"14 days\" }"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        CollectionAssert.IsSubsetOf(
            new[] { "Exception for numpy: No wait [note]", "Exception for torch: 1 day [note]" }, outcome.Rows());
        Assert.IsFalse(outcome.Rows().Any(r => r.Contains("pandas", StringComparison.Ordinal)), "a longer wait is not an exception");
    }

    // Sources

    [TestMethod]
    public void Sources_Defaults_Pass()
    {
        CheckOutcome outcome = Sources.Run(Uv("exclude-newer = \"7 days\""));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(3, outcome.Findings.Count);
    }

    [TestMethod]
    [DataRow("index-strategy = \"unsafe-best-match\"", "uv: index strategy: unsafe-best-match.")]
    [DataRow("index-strategy = \"unsafe-first-match\"", "uv: index strategy: unsafe-first-match.")]
    [DataRow("allow-insecure-host = [\"packages.example\"]", "uv: hosts exempt from TLS checks: 1.")]
    [DataRow("index-url = \"http://packages.example/simple\"", "uv: index-url: plain HTTP.")]
    [DataRow("extra-index-url = [\"https://ok.example/simple\", \"http://bad.example/simple\"]", "uv: extra-index-url: plain HTTP.")]
    [DataRow("[[index]]\nname = \"internal\"\nurl = \"http://packages.example/simple\"", "uv: index \"internal\": plain HTTP.")]
    [DataRow("[[index]]\nname = \"internal\"\nurl = \"https://packages.example/simple\"\nignore-error-codes = [401, 403]", "uv: index \"internal\": ignores \"access denied\".")]
    [DataRow("[[index]]\nurl = \"https://packages.example/simple\"\nexclude-newer = false", "uv: an index: exempt from the release wait.")]
    [DataRow("python-install-mirror = \"https://mirror.example/python\"", "uv: python download source: replaced.")]
    public void Sources_EachWeakSetting_Fails_AndIsNamed(string settings, string summary)
    {
        CheckOutcome outcome = Sources.Run(Uv(settings));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Sources_SafeSettings_Pass()
    {
        const string Settings = """
            index-strategy = "first-index"
            allow-insecure-host = []

            [[index]]
            name = "internal"
            url = "https://packages.example/simple"
            explicit = true
            ignore-error-codes = [404]
            """;

        Assert.AreEqual(CheckStatus.Pass, Sources.Run(Uv(Settings)).Status);
    }

    [TestMethod]
    public void Sources_APasswordInAnAddress_IsReported_ButNeverShown()
    {
        CheckOutcome outcome = Sources.Run(Uv("[[index]]\nname = \"internal\"\nurl = \"https://someone:made-up-secret@packages.example/simple\""));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Index \"internal\": A password in the address (expected No password in files) [problem]", outcome.Rows()[0]);
        string everything = outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));
        Assert.IsFalse(everything.Contains("made-up-secret", StringComparison.Ordinal));
        Assert.IsFalse(everything.Contains("someone", StringComparison.Ordinal));
    }

    [TestMethod]
    [DataRow("UV_INDEX_STRATEGY", "unsafe-best-match")]
    [DataRow("UV_INSECURE_HOST", "packages.example")]
    [DataRow("UV_NO_VERIFY_HASHES", "1")]
    [DataRow("UV_INSECURE_NO_ZIP_VALIDATION", "1")]
    [DataRow("UV_PYTHON_INSTALL_MIRROR", "https://mirror.example")]
    [DataRow("UV_INSTALLER_GITHUB_BASE_URL", "https://mirror.example")]
    public void Sources_PermanentEnvironmentVariables_CountToo(string name, string value)
    {
        CheckOutcome outcome = Sources.Run(WithVariable(Uv("exclude-newer = \"7 days\""), name, value));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Source, name);
    }

    [TestMethod]
    public void Sources_SeveralProblems_AreCounted_AndThePcsFileCountsToo()
    {
        FakeProbes probes = Uv("index-strategy = \"unsafe-best-match\"").WithFile(SystemConfig, "allow-insecure-host = [\"a.example\", \"b.example\"]");

        CheckOutcome outcome = Sources.Run(probes);

        Assert.AreEqual("uv has 2 settings that weaken where it gets packages from.", outcome.Summary);
    }

    [TestMethod]
    public void Sources_AnUnreadableFile_IsCouldNotCheck_ButADefiniteProblemStillFails()
    {
        FakeProbes unreadable = new FakeProbes()
            .WithFile(Receipt, """{ "version": "0.12.19" }""")
            .WithFile(UserConfig, "not toml at all");
        Assert.AreEqual(CheckStatus.Error, Sources.Run(unreadable).Status);

        Assert.AreEqual(CheckStatus.Fail, Sources.Run(WithVariable(unreadable, "UV_INSECURE_HOST", "x")).Status);
    }

    // Credentials

    [TestMethod]
    public void Credentials_NoneStored_Passes()
    {
        Assert.AreEqual(CheckStatus.Pass, Secrets.Run(Uv("exclude-newer = \"7 days\"")).Status);

        FakeProbes empty = Uv("exclude-newer = \"7 days\"").WithFile(Credentials, "# nothing yet\n");
        Assert.AreEqual(CheckStatus.Pass, Secrets.Run(empty).Status);
    }

    [TestMethod]
    public void Credentials_AStoredPasswordOrToken_Fails_NamingTheHostOnly()
    {
        const string Stored = """
            [[credential]]
            service = "https://packages.example/simple"
            username = "someone"
            scheme = "basic"
            password = "made-up-secret"

            [[credential]]
            service = "https://other.example"
            scheme = "bearer"
            token = "made-up-token"
            """;

        CheckOutcome outcome = Secrets.Run(Uv("exclude-newer = \"7 days\"").WithFile(Credentials, Stored));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("uv keeps 2 sign-in secrets as plain text.", outcome.Summary);
        Assert.AreEqual("Sign-in for packages.example: Stored as plain text (expected Not stored as plain text) [problem]", outcome.Rows()[0]);
        Assert.AreEqual($"{Credentials}, line 5", outcome.Findings[0].Source);

        string everything = outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));
        Assert.IsFalse(everything.Contains("made-up", StringComparison.Ordinal), "the secret itself never appears");
        Assert.IsFalse(everything.Contains("someone", StringComparison.Ordinal), "nor the user name");
    }

    [TestMethod]
    public void Credentials_AnEntryWithoutASecret_IsFine()
    {
        const string Stored = "[[credential]]\nservice = \"https://packages.example\"\nusername = \"someone\"\npassword = \"\"\n";

        Assert.AreEqual(CheckStatus.Pass, Secrets.Run(Uv("x = 1").WithFile(Credentials, Stored)).Status);
    }

    [TestMethod]
    [DataRow("UV_PUBLISH_TOKEN")]
    [DataRow("UV_GITHUB_TOKEN")]
    [DataRow("UV_INDEX_INTERNAL_PASSWORD")]
    public void Credentials_ASecretInAPermanentVariable_Fails_NamingTheVariableOnly(string variable)
    {
        CheckOutcome outcome = Secrets.Run(WithVariable(Uv("x = 1"), variable, "made-up-secret"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($"Variable {variable}", outcome.Findings[0].Item);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Found + f.Source).Contains("made-up", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Credentials_OtherUvVariables_AreNotSecrets()
    {
        FakeProbes probes = WithVariable(WithVariable(Uv("x = 1"), "UV_INDEX_INTERNAL_USERNAME", "someone"), "UV_CACHE_DIR", @"D:\cache");

        Assert.AreEqual(CheckStatus.Pass, Secrets.Run(probes).Status);
    }

    [TestMethod]
    public void Credentials_AFileThatCannotBeReadOrUnderstood_IsCouldNotCheck()
    {
        Assert.AreEqual(
            CheckStatus.Error, Secrets.Run(Uv("x = 1").WithFileFailure(Credentials, ProbeFailure.AccessDenied())).Status);
        Assert.AreEqual(CheckStatus.Error, Secrets.Run(Uv("x = 1").WithFile(Credentials, "[[credential\n")).Status);
    }

    [TestMethod]
    public void Credentials_TheFolderCanBeMoved_ByAVariable()
    {
        const string Moved = @"D:\secrets";
        FakeProbes probes = WithVariable(Uv("x = 1"), "UV_CREDENTIALS_DIR", Moved)
            .WithFile(Moved + @"\credentials.toml", "[[credential]]\nservice = \"https://a.example\"\ntoken = \"made-up\"\n");

        Assert.AreEqual(CheckStatus.Fail, Secrets.Run(probes).Status);
    }
}
