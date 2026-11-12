using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Pnpm;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class PnpmChecksTests
{
    private static readonly string ConfigFolder = FakeProbes.FolderPath(KnownFolder.LocalAppData) + @"\pnpm\config";
    private static readonly string Yaml = ConfigFolder + @"\config.yaml";
    private static readonly string Rc = ConfigFolder + @"\rc";
    private static readonly string AuthIni = ConfigFolder + @"\auth.ini";
    private static readonly string ScoopApp = FakeProbes.UserProfile + @"\scoop\apps\pnpm\current";

    private static readonly PnpmCooldownCheck Cooldown = new();
    private static readonly PnpmSettingsCheck Settings = new();
    private static readonly PnpmCredentialsCheck Tokens = new();

    /// <summary>A PC with pnpm from Scoop at the given version (null: no file records a version) and the given settings files.</summary>
    private static FakeProbes Pnpm(string? version = "12.19.0", string? yaml = null, string? rc = null, string? authIni = null)
    {
        var probes = new FakeProbes();
        if (version is not null)
        {
            probes.WithFile(ScoopApp + @"\scoop-manifest.json", $$"""{ "version": "{{version}}" }""")
                .WithFile(ScoopApp + @"\scoop-install.json", """{ "bucket": "main" }""");
        }

        if (yaml is not null)
        {
            probes.WithFile(Yaml, yaml);
        }

        if (rc is not null)
        {
            probes.WithFile(Rc, rc);
        }

        if (authIni is not null)
        {
            probes.WithFile(AuthIni, authIni);
        }

        return probes;
    }

    [TestMethod]
    public void WithoutPnpm_NoneOfTheChecksApply()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Cooldown.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Settings.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Tokens.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, Cooldown.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Settings.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Tokens.Definition.Scope);
    }

    // Cooldown

    [TestMethod]
    public void Cooldown_AWeekInTheFileThisPnpmReads_Passes()
    {
        CheckOutcome outcome = Cooldown.Run(Pnpm(yaml: "storeDir: D:\\store\nminimumReleaseAge: 10080\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("pnpm waits 7 days before installing a new release.", outcome.Summary);
        Assert.AreEqual($"{Yaml}, line 2", outcome.Findings[0].Source);
        Assert.AreEqual("pnpm version: 12.19.0 (expected 10.16.0 or later) [ok]", outcome.Rows()[1]);
    }

    [TestMethod]
    public void Cooldown_NotSet_Fails_WithWhatThatVersionDoesByDefault()
    {
        CheckOutcome current = Cooldown.Run(Pnpm(yaml: "storeDir: D:\\store\n"));
        Assert.AreEqual(CheckStatus.Fail, current.Status);
        Assert.AreEqual("pnpm waits only its default of 1 day before installing a new release.", current.Summary);

        CheckOutcome ten = Cooldown.Run(Pnpm(version: "10.34.9"));
        Assert.AreEqual(CheckStatus.Fail, ten.Status);
        Assert.AreEqual("pnpm installs new package versions the moment they are published.", ten.Summary);
    }

    [TestMethod]
    [DataRow("minimumReleaseAge: 1440", "pnpm waits only 1 day before installing a new release.")]
    [DataRow("minimumReleaseAge: 0", "pnpm's wait for new releases is switched off.")]
    public void Cooldown_TooShortOrOff_Fails(string yaml, string summary)
    {
        CheckOutcome outcome = Cooldown.Run(Pnpm(yaml: yaml));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Cooldown_SetInTheFileOfTheOtherMajorVersion_DoesNotCount_AndSaysSo()
    {
        // pnpm 12 ignores the dashed name in rc.
        CheckOutcome twelve = Cooldown.Run(Pnpm(rc: "minimum-release-age=10080\n"));
        Assert.AreEqual(CheckStatus.Fail, twelve.Status);
        Assert.IsTrue(twelve.Rows().Contains("Set in a file this pnpm ignores: rc is only read for this by pnpm 10 [note]"));

        // pnpm 10 ignores config.yaml.
        CheckOutcome ten = Cooldown.Run(Pnpm(version: "10.34.9", yaml: "minimumReleaseAge: 10080\n"));
        Assert.AreEqual(CheckStatus.Fail, ten.Status);
        Assert.IsTrue(ten.Rows().Contains("Set in a file this pnpm ignores: config.yaml is only read by pnpm 11 and later [note]"));
    }

    [TestMethod]
    public void Cooldown_Pnpm10_ReadsTheDashedNameFromRc()
    {
        CheckOutcome outcome = Cooldown.Run(Pnpm(version: "10.34.9", rc: "minimum-release-age=10080\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual($"{Rc}, line 1", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Cooldown_APnpmTooOldForTheSetting_Fails()
    {
        CheckOutcome outcome = Cooldown.Run(Pnpm(version: "10.15.0", rc: "minimum-release-age=10080\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("pnpm 10.15.0 cannot wait before installing new releases; update pnpm.", outcome.Summary);
    }

    [TestMethod]
    public void Cooldown_VersionNotReadable_UsesTheCurrentFile_AndSaysWhatThatRestsOn()
    {
        CheckOutcome outcome = Cooldown.Run(Pnpm(version: null, yaml: "minimumReleaseAge: 10080\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        StringAssert.Contains(outcome.Summary, "the installed version could not be read");
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[^1].Status);
    }

    [TestMethod]
    public void Cooldown_NotStrict_Fails_AndExemptionsAreCounted()
    {
        CheckOutcome loose = Cooldown.Run(Pnpm(yaml: "minimumReleaseAge: 10080\nminimumReleaseAgeStrict: false\n"));
        Assert.AreEqual(CheckStatus.Fail, loose.Status);
        StringAssert.Contains(loose.Summary, "not strictly");

        CheckOutcome exempt = Cooldown.Run(Pnpm(yaml: "minimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - '@types/*'\n  - left-pad\n"));
        Assert.AreEqual(CheckStatus.Pass, exempt.Status);
        Assert.IsTrue(exempt.Rows().Contains("Packages exempt from the wait: 2 [note]"));
    }

    [TestMethod]
    [DataRow("minimumReleaseAge: seven days")]
    [DataRow("minimumReleaseAge: \"10080\"")]
    [DataRow("minimumReleaseAge: [10080]")]
    [DataRow("minimumReleaseAge: 10080\n\tbroken: yaml")]
    public void Cooldown_AValueOrFileThatCannotBeUnderstood_IsCouldNotCheck(string yaml)
    {
        Assert.AreEqual(CheckStatus.Error, Cooldown.Run(Pnpm(yaml: yaml)).Status);
    }

    [TestMethod]
    public void Cooldown_AnUnreadableFile_IsCouldNotCheck_NotAFailure()
    {
        FakeProbes probes = Pnpm().WithFileFailure(Yaml, ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.Error, Cooldown.Run(probes).Status);
    }

    [TestMethod]
    public void TheVersion_CanAlsoComeFromTheNpmCopy_OrCorepack()
    {
        string npmCopy = FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\npm\node_modules\pnpm\package.json";
        FakeProbes viaNpm = new FakeProbes().WithFile(npmCopy, """{ "name": "pnpm", "version": "10.20.1" }""");
        Assert.AreEqual("pnpm version: 10.20.1 (expected 10.16.0 or later) [ok]", Cooldown.Run(viaNpm).Rows()[^1]);

        string corepack = FakeProbes.FolderPath(KnownFolder.LocalAppData) + @"\node\corepack\v1\pnpm";
        FakeProbes viaCorepack = new FakeProbes()
            .WithFile(corepack + @"\9.15.0\package.json", "{}")
            .WithFile(corepack + @"\11.28.11\package.json", "{}")
            .WithFile(Yaml, "minimumReleaseAge: 10080\n");
        CheckOutcome outcome = Cooldown.Run(viaCorepack);
        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("pnpm version: 11.28.11 (expected 10.16.0 or later) [ok]", outcome.Rows()[^1]);
    }

    // Settings

    [TestMethod]
    public void Settings_Defaults_Pass_AndSuggestTheTrustPolicy()
    {
        CheckOutcome outcome = Settings.Run(Pnpm(yaml: "minimumReleaseAge: 10080\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[1].Status);
        StringAssert.Contains(outcome.Findings[1].Found, "no-downgrade");
    }

    [TestMethod]
    public void Settings_TheRecommendedTrustPolicy_IsRecognised()
    {
        CheckOutcome outcome = Settings.Run(Pnpm(yaml: "trustPolicy: no-downgrade\n"));

        Assert.AreEqual("Trust policy: no-downgrade (expected no-downgrade) [ok]", outcome.Rows()[1]);
    }

    [TestMethod]
    [DataRow("trustLockfile: true", "pnpm: lockfile verification: skipped.")]
    [DataRow("dangerouslyAllowAllBuilds: true", "pnpm: build scripts: every package may run them.")]
    [DataRow("strictDepBuilds: false", "pnpm: unapproved build scripts: ignored silently.")]
    [DataRow("blockExoticSubdeps: false", "pnpm: dependencies from arbitrary addresses: allowed.")]
    [DataRow("verifyStoreIntegrity: false", "pnpm: package store integrity check: off.")]
    [DataRow("strictSsl: false", "pnpm: TLS certificate checks: off.")]
    [DataRow("registries:\n  default: http://registry.example/\n", "pnpm: registry \"default\": plain HTTP.")]
    public void Settings_EachProtectionSwitchedOff_Fails_AndIsNamed(string yaml, string summary)
    {
        CheckOutcome outcome = Settings.Run(Pnpm(yaml: yaml));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Settings_TheSafeValues_Pass()
    {
        const string Safe = "trustLockfile: false\ndangerouslyAllowAllBuilds: false\nstrictDepBuilds: true\nblockExoticSubdeps: true\nstrictSsl: true\nregistries:\n  default: https://registry.npmjs.org/\n";

        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Pnpm(yaml: Safe)).Status);
    }

    [TestMethod]
    public void Settings_NetworkSettingsInRc_CountForEveryVersion()
    {
        CheckOutcome tls = Settings.Run(Pnpm(rc: "strict-ssl=false\n"));
        Assert.AreEqual(CheckStatus.Fail, tls.Status);

        CheckOutcome registry = Settings.Run(Pnpm(rc: "registry=http://registry.example/\n@company:registry=http://npm.example/\n"));
        Assert.AreEqual("pnpm has 2 protections switched off.", registry.Summary);
        Assert.AreEqual("Registry for @company: Plain HTTP (expected HTTPS) [problem]", registry.Rows()[1]);
    }

    [TestMethod]
    public void Settings_Pnpm10_ReadsItsOwnSettingsFromRc_NotFromYaml()
    {
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(Pnpm(version: "10.34.9", rc: "dangerously-allow-all-builds=true\n")).Status);
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Pnpm(version: "10.34.9", yaml: "dangerouslyAllowAllBuilds: true\n")).Status);
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Pnpm(rc: "dangerously-allow-all-builds=true\n")).Status, "pnpm 12 ignores it in rc");
    }

    [TestMethod]
    public void Settings_AnUnreadableFile_IsCouldNotCheck_ButADefiniteProblemStillFails()
    {
        Assert.AreEqual(CheckStatus.Error, Settings.Run(Pnpm(yaml: "a: &anchor 1\n")).Status);
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(Pnpm(yaml: "a: &anchor 1\n", rc: "strict-ssl=false\n")).Status);
    }

    // Tokens

    [TestMethod]
    public void Tokens_NoneStored_Passes()
    {
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(Pnpm(yaml: "minimumReleaseAge: 10080\n")).Status);
        Assert.AreEqual(
            CheckStatus.Pass,
            Tokens.Run(Pnpm(authIni: "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n")).Status,
            "a reference to a variable is not a stored token");
    }

    [TestMethod]
    public void Tokens_InAuthIni_OrRc_Fail_NamingTheRegistryOnly()
    {
        CheckOutcome outcome = Tokens.Run(Pnpm(
            authIni: "; tokens\n//registry.npmjs.org/:_authToken=made-up-token\n",
            rc: "//npm.example/company/:_password=made-up-password\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("pnpm keeps 2 registry tokens as plain text.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "Token for registry.npmjs.org: Stored as plain text (expected Not stored as plain text) [problem]",
                "Password for npm.example: Stored as plain text (expected Not stored as plain text) [problem]",
            },
            outcome.Rows());
        Assert.AreEqual($"{AuthIni}, line 2", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Item + f.Found + f.Source).Contains("made-up", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Tokens_LeftBehindInConfigYaml_ByPnpm12_AreFound()
    {
        const string Left = """
            minimumReleaseAge: 10080
            _auth:
              https://registry.npmjs.org:
                "@":
                  authToken: made-up-token
                "@org":
                  authToken: ${ORG_TOKEN}
            """;

        CheckOutcome outcome = Tokens.Run(Pnpm(yaml: Left));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("pnpm keeps a registry token as plain text.", outcome.Summary);
        Assert.AreEqual("Token for registry.npmjs.org", outcome.Findings[0].Item);
        Assert.AreEqual($"{Yaml}, line 5", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Tokens_InAPermanentVariable_Fail_WithoutShowingIt()
    {
        FakeProbes probes = Pnpm().WithRegistryValue(
            RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "npm_config_//registry.npmjs.org/:_authToken", RegistryValue.FromText("made-up-token"));

        CheckOutcome outcome = Tokens.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Item + f.Found + f.Source).Contains("made-up", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Tokens_AFileThatCannotBeUnderstood_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, Tokens.Run(Pnpm(authIni: "this is not a settings line\n")).Status);
        Assert.AreEqual(CheckStatus.Error, Tokens.Run(Pnpm().WithFileFailure(AuthIni, ProbeFailure.AccessDenied())).Status);
    }
}
