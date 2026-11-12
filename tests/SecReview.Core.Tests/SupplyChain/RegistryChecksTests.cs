using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Npm;
using SecReview.SupplyChain.Python;
using SecReview.SupplyChain.Yarn;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

/// <summary>Settings and stored tokens of npm, Yarn and the Python packaging tools.</summary>
[TestClass]
public sealed class RegistryChecksTests
{
    private static readonly string Profile = FakeProbes.UserProfile;
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);

    private static readonly string Npmrc = Profile + @"\.npmrc";
    private static readonly string Yarnrc = Profile + @"\.yarnrc.yml";
    private static readonly string PipIni = Roaming + @"\pip\pip.ini";
    private static readonly string Pypirc = Profile + @"\.pypirc";
    private static readonly string PoetryAuth = Roaming + @"\pypoetry\auth.toml";

    private static FakeProbes File(string path, string text) => new FakeProbes().WithFile(path, text);

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    private static IEnumerable<object[]> Checks =>
    [
        [new NpmSettingsCheck()], [new NpmCredentialsCheck()], [new YarnSettingsCheck()],
        [new YarnCredentialsCheck()], [new PipSettingsCheck()], [new PythonCredentialsCheck()],
    ];

    [TestMethod]
    [DynamicData(nameof(Checks))]
    public void WithoutTheFiles_TheCheckDoesNotApply_AndItNeverRunsElevated(ICheck check)
    {
        Assert.AreEqual(CheckStatus.NotApplicable, check.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, check.Definition.Scope);
    }

    // npm

    [TestMethod]
    public void NpmSettings_AnOrdinaryFile_Passes()
    {
        Assert.AreEqual(
            CheckStatus.Pass,
            new NpmSettingsCheck().Run(File(Npmrc, "registry=https://registry.npmjs.org/\nstrict-ssl=true\nmin-release-age=7\n")).Status);
    }

    [TestMethod]
    [DataRow("strict-ssl=false", "npm: TLS certificate checks: off.")]
    [DataRow("registry=http://registry.example/", "npm: default registry: plain HTTP.")]
    [DataRow("@company:registry=http://npm.example/", "npm: registry for @company: plain HTTP.")]
    [DataRow("dangerously-allow-all-scripts=true", "npm: install scripts: every package may run them.")]
    public void NpmSettings_EachProtectionSwitchedOff_Fails_AndIsNamed(string line, string summary)
    {
        CheckOutcome outcome = new NpmSettingsCheck().Run(File(Npmrc, line + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual($"{Npmrc}, line 1", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void NpmSettings_TheGlobalFile_CountsToo_AndSeveralProblemsAreCounted()
    {
        FakeProbes probes = File(Npmrc, "strict-ssl=false\n").WithFile(Roaming + @"\npm\etc\npmrc", "registry=http://registry.example/\n");

        Assert.AreEqual("npm has 2 protections switched off.", new NpmSettingsCheck().Run(probes).Summary);
    }

    [TestMethod]
    public void NpmSettings_AFileThatCannotBeUnderstood_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new NpmSettingsCheck().Run(File(Npmrc, "not a settings line\n")).Status);
        Assert.AreEqual(CheckStatus.Error, new NpmCredentialsCheck().Run(new FakeProbes().WithFileFailure(Npmrc, ProbeFailure.AccessDenied())).Status);
    }

    [TestMethod]
    public void NpmCredentials_NoTokens_OrOnlyReferences_Pass()
    {
        const string Text = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n//npm.example/:_authToken=\n";

        Assert.AreEqual(CheckStatus.Pass, new NpmCredentialsCheck().Run(File(Npmrc, Text)).Status);
    }

    [TestMethod]
    public void NpmCredentials_StoredTokens_Fail_NamingTheRegistryOnly()
    {
        const string Text = "//registry.npmjs.org/:_authToken=made-up-token\n//npm.example/:_auth=made-up-basic\n_password=made-up-password\n";

        CheckOutcome outcome = new NpmCredentialsCheck().Run(File(Npmrc, Text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("3 registry tokens for npm are stored as plain text.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "Token for registry.npmjs.org", "Token for npm.example", "Password (_password)" },
            outcome.Findings.Select(f => f.Item).ToArray());
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal), "the secret itself never appears");
    }

    [TestMethod]
    public void Npm_TheUsersFileCanBeMoved_ByAVariable()
    {
        const string Moved = @"D:\settings\npmrc";
        FakeProbes probes = WithVariable(File(Npmrc, "registry=https://registry.npmjs.org/\n"), "NPM_CONFIG_USERCONFIG", Moved)
            .WithFile(Moved, "//registry.npmjs.org/:_authToken=made-up-token\n");

        Assert.AreEqual(CheckStatus.Fail, new NpmCredentialsCheck().Run(probes).Status);
    }

    [TestMethod]
    public void NpmCredentials_ATokenOnALineThatALaterLineReplaces_IsStillFound()
    {
        const string Text = "//registry.npmjs.org/:_authToken=made-up-token\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n";

        CheckOutcome outcome = new NpmCredentialsCheck().Run(File(Npmrc, Text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("A registry token for npm is stored as plain text.", outcome.Summary);
        Assert.AreEqual($"{Npmrc}, line 1", outcome.Findings[0].Source);
    }

    [TestMethod]
    [DataRow("NPM_TOKEN")]
    [DataRow("NODE_AUTH_TOKEN")]
    [DataRow("npm_config_//registry.npmjs.org/:_authToken")]
    public void NpmCredentials_ATokenInAPermanentVariable_Fails_EvenWithoutAFile(string variable)
    {
        CheckOutcome outcome = new NpmCredentialsCheck().Run(WithVariable(new FakeProbes(), variable, "made-up-token"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($"Variable {variable}", outcome.Findings[0].Item);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void NpmSettings_TheLastLineOfASetting_IsTheOneInForce()
    {
        Assert.AreEqual(CheckStatus.Pass, new NpmSettingsCheck().Run(File(Npmrc, "strict-ssl=false\nstrict-ssl=true\n")).Status);

        CheckOutcome off = new NpmSettingsCheck().Run(File(Npmrc, "strict-ssl=true\nstrict-ssl=false\n"));
        Assert.AreEqual(CheckStatus.Fail, off.Status);
        Assert.AreEqual($"{Npmrc}, line 2", off.Findings[0].Source);
    }

    [TestMethod]
    [DataRow("strict-ssl=false ; the proxy needs this")]
    [DataRow("strict-ssl = FALSE")]
    [DataRow("strict-ssl=0")]
    [DataRow("strict-ssl=\"false\"")]
    public void NpmSettings_ASwitch_IsReadAsNpmReadsIt(string line)
    {
        Assert.AreEqual(CheckStatus.Fail, new NpmSettingsCheck().Run(File(Npmrc, line + "\n")).Status);
    }

    [TestMethod]
    public void NpmSettings_TheVariable_WinsOverTheFile_AndCountsWithoutOne()
    {
        CheckOutcome alone = new NpmSettingsCheck().Run(WithVariable(new FakeProbes(), "npm_config_strict_ssl", "false"));
        Assert.AreEqual(CheckStatus.Fail, alone.Status);
        StringAssert.Contains(alone.Findings[0].Source, "npm_config_strict_ssl");

        FakeProbes overridden = WithVariable(File(Npmrc, "strict-ssl=false\n"), "npm_config_strict_ssl", "true");
        Assert.AreEqual(CheckStatus.Pass, new NpmSettingsCheck().Run(overridden).Status);

        FakeProbes registry = WithVariable(File(Npmrc, "registry=https://registry.npmjs.org/\n"), "npm_config_registry", "http://registry.example/");
        Assert.AreEqual("npm: default registry: plain HTTP.", new NpmSettingsCheck().Run(registry).Summary);
    }

    // Yarn

    [TestMethod]
    public void YarnSettings_AnOrdinaryFile_Passes()
    {
        const string Text = "npmMinimalAgeGate: \"7d\"\nenableScripts: false\nenableStrictSsl: true\nnpmRegistryServer: \"https://registry.yarnpkg.com\"\nunsafeHttpWhitelist: []\n";

        Assert.AreEqual(CheckStatus.Pass, new YarnSettingsCheck().Run(File(Yarnrc, Text)).Status);
    }

    [TestMethod]
    [DataRow("enableStrictSsl: false", "Yarn: TLS certificate checks: off.")]
    [DataRow("checksumBehavior: ignore", "Yarn: checksum verification: ignored.")]
    [DataRow("enableScripts: true", "Yarn: install scripts: every package may run them.")]
    [DataRow("unsafeHttpWhitelist: [\"*.internal.example\"]", "Yarn: hosts allowed over plain HTTP: 1.")]
    [DataRow("npmRegistryServer: \"http://registry.example\"", "Yarn: default registry: plain HTTP.")]
    [DataRow("npmScopes:\n  company:\n    npmRegistryServer: http://npm.example", "Yarn: registry for @company: plain HTTP.")]
    public void YarnSettings_EachProtectionSwitchedOff_Fails_AndIsNamed(string text, string summary)
    {
        CheckOutcome outcome = new YarnSettingsCheck().Run(File(Yarnrc, text + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    [DataRow("enableStrictSsl: \"false\"", CheckStatus.Fail)]
    [DataRow("enableStrictSsl: 0", CheckStatus.Fail)]
    [DataRow("enableStrictSsl: \"0\"", CheckStatus.Fail)]
    [DataRow("enableScripts: \"true\"", CheckStatus.Fail)]
    [DataRow("enableScripts: 1", CheckStatus.Fail)]
    [DataRow("enableStrictSsl: \"true\"", CheckStatus.Pass)]
    [DataRow("enableScripts: 0", CheckStatus.Pass)]
    [DataRow("enableStrictSsl: maybe", CheckStatus.Error)]
    [DataRow("enableStrictSsl: [false]", CheckStatus.Error)]
    [DataRow("unsafeHttpWhitelist: \"*.internal.example\"", CheckStatus.Fail)]
    [DataRow("unsafeHttpWhitelist:", CheckStatus.Pass)]
    public void YarnSettings_ASwitch_IsReadAsYarnReadsIt_QuotedOrAsANumber(string text, CheckStatus expected)
    {
        Assert.AreEqual(expected, new YarnSettingsCheck().Run(File(Yarnrc, text + "\n")).Status);
    }

    [TestMethod]
    public void YarnSettings_TheVariable_WinsOverTheFile_AndCountsWithoutOne()
    {
        CheckOutcome alone = new YarnSettingsCheck().Run(WithVariable(new FakeProbes(), "YARN_ENABLE_STRICT_SSL", "false"));
        Assert.AreEqual(CheckStatus.Fail, alone.Status);
        StringAssert.Contains(alone.Findings[0].Source, "YARN_ENABLE_STRICT_SSL");

        FakeProbes overridden = WithVariable(File(Yarnrc, "enableScripts: true\n"), "YARN_ENABLE_SCRIPTS", "false");
        Assert.AreEqual(CheckStatus.Pass, new YarnSettingsCheck().Run(overridden).Status);

        FakeProbes server = WithVariable(File(Yarnrc, "enableScripts: false\n"), "YARN_NPM_REGISTRY_SERVER", "http://registry.example");
        Assert.AreEqual("Yarn: default registry: plain HTTP.", new YarnSettingsCheck().Run(server).Summary);
    }

    [TestMethod]
    [DataRow("YARN_NPM_AUTH_TOKEN")]
    [DataRow("YARN_NPM_AUTH_IDENT")]
    public void YarnCredentials_ATokenInAPermanentVariable_Fails_EvenWithoutAFile(string variable)
    {
        CheckOutcome outcome = new YarnCredentialsCheck().Run(WithVariable(new FakeProbes(), variable, "made-up-token"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("A registry token for Yarn is stored as plain text.", outcome.Summary);
        Assert.AreEqual($"Variable {variable}", outcome.Findings[0].Item);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void YarnCredentials_NoTokens_OrOnlyReferences_Pass()
    {
        const string Text = "npmAuthToken: ${NPM_TOKEN}\nnpmScopes:\n  company:\n    npmRegistryServer: https://npm.example\n";

        Assert.AreEqual(CheckStatus.Pass, new YarnCredentialsCheck().Run(File(Yarnrc, Text)).Status);
    }

    [TestMethod]
    public void YarnCredentials_StoredTokens_Fail_WhereverTheyAre()
    {
        const string Text = """
            npmAuthToken: made-up-token
            npmScopes:
              company:
                npmAuthIdent: "someone:made-up-password"
            npmRegistries:
              "//npm.example/private":
                npmAuthToken: made-up-other
            """;

        CheckOutcome outcome = new YarnCredentialsCheck().Run(File(Yarnrc, Text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.AreEqual(
            new[] { "Token for the default registry", "Token for @company", "Token for npm.example" },
            outcome.Findings.Select(f => f.Item).ToArray());
        Assert.AreEqual($"{Yarnrc}, line 4", outcome.Findings[1].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Yarn_AFileThatCannotBeUnderstood_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new YarnSettingsCheck().Run(File(Yarnrc, "a: &anchor 1\n")).Status);
        Assert.AreEqual(CheckStatus.Error, new YarnCredentialsCheck().Run(File(Yarnrc, "a: &anchor 1\n")).Status);
    }

    // pip

    [TestMethod]
    public void PipSettings_OneIndexOverHttps_Passes()
    {
        Assert.AreEqual(
            CheckStatus.Pass,
            new PipSettingsCheck().Run(File(PipIni, "[global]\nindex-url = https://pypi.org/simple\nuploaded-prior-to = P7D\n")).Status);
    }

    [TestMethod]
    [DataRow("[global]\ntrusted-host = packages.example", "pip: hosts exempt from TLS checks: some.")]
    [DataRow("[global]\nextra-index-url = https://packages.example/simple", "pip: extra package indexes: some.")]
    [DataRow("[global]\nindex-url = http://packages.example/simple", "pip: package index (index-url): plain HTTP.")]
    [DataRow("[install]\ntrusted-host =\n    a.example\n    b.example", "pip: hosts exempt from TLS checks: some.")]
    [DataRow("[global]\nTrusted_Host = packages.example", "pip: hosts exempt from TLS checks: some.")]
    [DataRow("[global]\n--extra-index-url = https://packages.example/simple", "pip: extra package indexes: some.")]
    [DataRow("[global]\n  index-url = http://packages.example/simple", "pip: package index (index-url): plain HTTP.")]
    public void PipSettings_EachWeakSetting_Fails_AndIsNamed(string ini, string summary)
    {
        CheckOutcome outcome = new PipSettingsCheck().Run(File(PipIni, ini + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void PipSettings_PermanentVariables_CountEvenWithoutAFile()
    {
        CheckOutcome outcome = new PipSettingsCheck().Run(WithVariable(new FakeProbes(), "PIP_TRUSTED_HOST", "packages.example"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Source, "PIP_TRUSTED_HOST");
    }

    [TestMethod]
    public void PipSettings_AFileThatCannotBeUnderstood_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new PipSettingsCheck().Run(File(PipIni, "[global\nindex-url = x\n")).Status);
    }

    // Python index passwords

    [TestMethod]
    public void PythonCredentials_NoPasswords_Pass()
    {
        FakeProbes probes = File(Pypirc, "[distutils]\nindex-servers =\n    pypi\n\n[pypi]\nusername = __token__\n")
            .WithFile(PipIni, "[global]\nindex-url = https://pypi.org/simple\n");

        Assert.AreEqual(CheckStatus.Pass, new PythonCredentialsCheck().Run(probes).Status);
    }

    [TestMethod]
    public void PythonCredentials_APasswordInPypirc_Fails_NamingTheIndexOnly()
    {
        CheckOutcome outcome = new PythonCredentialsCheck().Run(
            File(Pypirc, "[pypi]\nusername = __token__\npassword = made-up-token\n\n[testpypi]\nusername = someone\npassword = made-up-other\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("2 Python package index passwords are stored as plain text.", outcome.Summary);
        Assert.AreEqual("Password for pypi", outcome.Findings[0].Item);
        Assert.AreEqual($"{Pypirc}, line 3", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("someone", StringComparison.Ordinal));
    }

    [TestMethod]
    [DataRow("[pypi]\n  username = __token__\n  password = made-up-token\n", 3, DisplayName = "keys indented alike")]
    [DataRow("[pypi]\nusername = __token__\npassword =\n    made-up-token\n", 4, DisplayName = "the password on the line below its key")]
    [DataRow("[pypi]\nusername = __token__\nPassword: made-up-token\n", 3, DisplayName = "another spelling of the key")]
    public void PythonCredentials_APasswordInPypirc_IsFound_HoweverTheFileIsLaidOut(string text, int line)
    {
        CheckOutcome outcome = new PythonCredentialsCheck().Run(File(Pypirc, text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($"{Pypirc}, line {line}", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void PythonCredentials_APasswordInAnIndexAddress_Fails_WithoutShowingTheAddress()
    {
        CheckOutcome outcome = new PythonCredentialsCheck().Run(
            File(PipIni, "[global]\nindex-url = https://someone:made-up-password@packages.example/simple\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Password in an index address (index-url)", outcome.Findings[0].Item);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("packages.example", StringComparison.Ordinal));
    }

    [TestMethod]
    public void PythonCredentials_AUserNameAlone_InAnAddress_IsNotAPassword()
    {
        Assert.AreEqual(
            CheckStatus.Pass,
            new PythonCredentialsCheck().Run(File(PipIni, "[global]\nindex-url = https://someone@packages.example/simple\n")).Status);
    }

    [TestMethod]
    public void PythonCredentials_PoetrysAuthFile_IsRead()
    {
        const string Text = """
            [http-basic.internal]
            username = "someone"
            password = "made-up-password"

            [pypi-token]
            pypi = "made-up-token"
            """;

        CheckOutcome outcome = new PythonCredentialsCheck().Run(File(PoetryAuth, Text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        CollectionAssert.AreEqual(new[] { "Password for internal", "Token for pypi" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void PythonCredentials_AFileThatCannotBeUnderstood_IsCouldNotCheck_ButAFoundPasswordStillFails()
    {
        Assert.AreEqual(CheckStatus.Error, new PythonCredentialsCheck().Run(File(PoetryAuth, "[http-basic\n")).Status);

        FakeProbes both = File(PoetryAuth, "[http-basic\n").WithFile(Pypirc, "[pypi]\npassword = made-up\n");
        Assert.AreEqual(CheckStatus.Fail, new PythonCredentialsCheck().Run(both).Status);
    }
}
