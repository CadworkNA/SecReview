using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Cooldowns;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

/// <summary>The release-wait checks of npm, Yarn, Bun, pip, Poetry and PDM, which share one implementation.</summary>
[TestClass]
public sealed class CooldownChecksTests
{
    private static readonly string Profile = FakeProbes.UserProfile;
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);
    private static readonly string Local = FakeProbes.FolderPath(KnownFolder.LocalAppData);

    private static readonly string Npmrc = Profile + @"\.npmrc";
    private static readonly string NpmPackage = Roaming + @"\npm\node_modules\npm\package.json";
    private static readonly string Yarnrc = Profile + @"\.yarnrc.yml";
    private static readonly string Bunfig = Profile + @"\.bunfig.toml";
    private static readonly string PipIni = Roaming + @"\pip\pip.ini";
    private static readonly string PoetryConfig = Roaming + @"\pypoetry\config.toml";
    private static readonly string PdmConfig = Local + @"\pdm\pdm\config.toml";

    private static FakeProbes Npm(string npmrc, string version = "11.17.0") =>
        new FakeProbes().WithFile(Npmrc, npmrc).WithFile(NpmPackage, $$"""{ "name": "npm", "version": "{{version}}" }""");

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    private static IEnumerable<object[]> Checks =>
    [
        [new NpmCooldownCheck()], [new YarnCooldownCheck()], [new BunCooldownCheck()],
        [new PipCooldownCheck()], [new PoetryCooldownCheck()], [new PdmCooldownCheck()],
    ];

    [TestMethod]
    [DynamicData(nameof(Checks))]
    public void WithoutTheTool_TheCheckDoesNotApply_AndItNeverRunsElevated(ICheck check)
    {
        Assert.AreEqual(CheckStatus.NotApplicable, check.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, check.Definition.Scope);
        Assert.AreEqual(CheckCategory.SupplyChain, check.Definition.Category);
    }

    // npm, which also exercises everything the tools share

    [TestMethod]
    public void Npm_AWeek_WithAnNpmThatHasTheSetting_Passes()
    {
        CheckOutcome outcome = new NpmCooldownCheck().Run(Npm("registry=https://registry.npmjs.org/\nmin-release-age=7\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("npm waits 7 days before installing a new release.", outcome.Summary);
        Assert.AreEqual($"{Npmrc}, line 2", outcome.Findings[0].Source);
        Assert.AreEqual("npm version: 11.17.0 (expected 11.10.0 or later) [ok]", outcome.Rows()[1]);
    }

    [TestMethod]
    public void Npm_NotSet_Fails_BecauseNpmDoesNotWaitByDefault()
    {
        CheckOutcome outcome = new NpmCooldownCheck().Run(Npm("registry=https://registry.npmjs.org/\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("npm installs new package versions the moment they are published.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("min-release-age=3", CheckStatus.Fail, "npm waits only 3 days before installing a new release.")]
    [DataRow("min-release-age=0", CheckStatus.Fail, "npm's wait for new releases is switched off.")]
    [DataRow("min-release-age=14", CheckStatus.Pass, "npm waits 14 days before installing a new release.")]
    public void Npm_TheNumberIsDays(string npmrc, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = new NpmCooldownCheck().Run(Npm(npmrc));

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    [DataRow("min-release-age=a week")]
    [DataRow("min-release-age=7d")]
    [DataRow("min-release-age=7\nnot a settings line\n")]
    public void Npm_AValueOrFileThatCannotBeUnderstood_IsCouldNotCheck(string npmrc)
    {
        Assert.AreEqual(CheckStatus.Error, new NpmCooldownCheck().Run(Npm(npmrc)).Status);
    }

    [TestMethod]
    public void Npm_TooOldForTheSetting_Fails_WhateverTheFileSays()
    {
        CheckOutcome outcome = new NpmCooldownCheck().Run(Npm("min-release-age=7\n", version: "11.9.0"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("npm 11.9.0 cannot wait before installing new releases; update npm.", outcome.Summary);
    }

    [TestMethod]
    public void Npm_VersionNotReadable_Passes_AndSaysWhatThatRestsOn()
    {
        CheckOutcome outcome = new NpmCooldownCheck().Run(new FakeProbes().WithFile(Npmrc, "min-release-age=7\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(
            "npm is set to wait 7 days; this holds from npm 11.10.0, and the installed version could not be read.", outcome.Summary);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[1].Status);
    }

    [TestMethod]
    public void Npm_TheVariable_WinsOverTheFile_AndTheGlobalFileCountsWhenTheUsersIsSilent()
    {
        CheckOutcome byVariable = new NpmCooldownCheck().Run(WithVariable(Npm("min-release-age=7\n"), "NPM_CONFIG_MIN_RELEASE_AGE", "1"));
        Assert.AreEqual(CheckStatus.Fail, byVariable.Status);
        StringAssert.Contains(byVariable.Findings[0].Source, "NPM_CONFIG_MIN_RELEASE_AGE");

        string global = Roaming + @"\npm\etc\npmrc";
        CheckOutcome byGlobal = new NpmCooldownCheck().Run(Npm("registry=https://registry.npmjs.org/\n").WithFile(global, "min-release-age=10\n"));
        Assert.AreEqual(CheckStatus.Pass, byGlobal.Status);
        Assert.AreEqual($"{global}, line 1", byGlobal.Findings[0].Source);
    }

    [TestMethod]
    public void Npm_TheUsersFileCanBeMoved_ByAVariable()
    {
        const string Moved = @"D:\settings\npmrc";
        FakeProbes probes = WithVariable(Npm("min-release-age=7\n"), "NPM_CONFIG_USERCONFIG", Moved).WithFile(Moved, "registry=https://registry.npmjs.org/\n");

        Assert.AreEqual(CheckStatus.Fail, new NpmCooldownCheck().Run(probes).Status, "the usual file is not read any more");
    }

    [TestMethod]
    public void Npm_AnUnreadableFile_IsCouldNotCheck_NotAFailure()
    {
        FakeProbes probes = new FakeProbes().WithFile(NpmPackage, """{ "version": "11.17.0" }""").WithFileFailure(Npmrc, ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.Error, new NpmCooldownCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Npm_TheVersion_ComesFromNodeJs_OrFromScoop()
    {
        FakeProbes withNode = new FakeProbes()
            .WithFile(@"C:\Program Files\nodejs\node_modules\npm\package.json", """{ "version": "10.9.2" }""")
            .WithFile(Npmrc, "min-release-age=7\n");
        StringAssert.Contains(new NpmCooldownCheck().Run(withNode).Summary, "npm 10.9.2 cannot wait");

        string scoopNode = Profile + @"\scoop\apps\nodejs-lts\current";
        FakeProbes withScoop = new FakeProbes()
            .WithFile(scoopNode + @"\scoop-manifest.json", """{ "version": "24.11.0" }""")
            .WithFile(scoopNode + @"\scoop-install.json", """{ "bucket": "main" }""")
            .WithFile(scoopNode + @"\node_modules\npm\package.json", """{ "version": "11.12.0" }""")
            .WithFile(Npmrc, "min-release-age=7\n");
        Assert.AreEqual("npm version: 11.12.0 (expected 11.10.0 or later) [ok]", new NpmCooldownCheck().Run(withScoop).Rows()[1]);
    }

    // Yarn

    [TestMethod]
    [DataRow("npmMinimalAgeGate: \"7d\"", CheckStatus.Pass)]
    [DataRow("npmMinimalAgeGate: 7d", CheckStatus.Pass)]
    [DataRow("npmMinimalAgeGate: 168h", CheckStatus.Pass)]
    [DataRow("npmMinimalAgeGate: 10080", CheckStatus.Pass)]
    [DataRow("npmMinimalAgeGate: \"1d\"", CheckStatus.Fail)]
    [DataRow("npmMinimalAgeGate: 7", CheckStatus.Fail)]
    [DataRow("npmMinimalAgeGate: 0", CheckStatus.Fail)]
    [DataRow("npmMinimalAgeGate: soon", CheckStatus.Error)]
    [DataRow("enableScripts: false", CheckStatus.Fail)]
    public void Yarn_ReadsLettersAsUnits_AndABareNumberAsMinutes(string yarnrc, CheckStatus expected)
    {
        Assert.AreEqual(expected, new YarnCooldownCheck().Run(new FakeProbes().WithFile(Yarnrc, yarnrc + "\n")).Status);
    }

    [TestMethod]
    public void Yarn_NeverKnowsItsVersion_AndSaysSo()
    {
        CheckOutcome pass = new YarnCooldownCheck().Run(new FakeProbes().WithFile(Yarnrc, "npmMinimalAgeGate: \"7d\"\n"));
        Assert.AreEqual("Yarn is set to wait 7 days; this holds from Yarn 4.10.0, and the installed version could not be read.", pass.Summary);

        CheckOutcome notSet = new YarnCooldownCheck().Run(new FakeProbes().WithFile(Yarnrc, "enableScripts: false\n"));
        StringAssert.Contains(notSet.Findings[0].Found, "Yarn 4.15 and later wait 1 day");
    }

    [TestMethod]
    public void Yarn_TheVariableCounts()
    {
        FakeProbes probes = WithVariable(new FakeProbes().WithFile(Yarnrc, "enableScripts: false\n"), "YARN_NPM_MINIMAL_AGE_GATE", "14d");

        Assert.AreEqual(CheckStatus.Pass, new YarnCooldownCheck().Run(probes).Status);
    }

    // Bun

    [TestMethod]
    [DataRow("[install]\nminimumReleaseAge = 604800", CheckStatus.Pass)]
    [DataRow("[install]\nminimumReleaseAge = 86400", CheckStatus.Fail)]
    [DataRow("[install]\nminimumReleaseAge = \"7 days\"", CheckStatus.Error)]
    [DataRow("[install]\nexact = true", CheckStatus.Fail)]
    [DataRow("minimumReleaseAge = 604800", CheckStatus.Fail)]
    public void Bun_TheNumberIsSeconds_UnderInstall(string bunfig, CheckStatus expected)
    {
        Assert.AreEqual(expected, new BunCooldownCheck().Run(new FakeProbes().WithFile(Bunfig, bunfig + "\n")).Status);
    }

    [TestMethod]
    public void Bun_InstalledButWithoutASettingsFile_Fails()
    {
        FakeProbes probes = new FakeProbes().WithFile(Profile + @"\.bun\bin\bun.exe", "binary");

        Assert.AreEqual("Bun installs new package versions the moment they are published.", new BunCooldownCheck().Run(probes).Summary);
    }

    // pip

    [TestMethod]
    [DataRow("[global]\nuploaded-prior-to = P7D", CheckStatus.Pass)]
    [DataRow("[global]\nuploaded-prior-to = P3D", CheckStatus.Fail)]
    [DataRow("[global]\nuploaded-prior-to = 2026-11-01", CheckStatus.Fail)]
    [DataRow("[global]\nuploaded-prior-to = 7 days", CheckStatus.Error)]
    [DataRow("[global]\nindex-url = https://pypi.org/simple", CheckStatus.Fail)]
    [DataRow("[install]\nuploaded-prior-to = P7D", CheckStatus.Pass)]
    [DataRow("[global]\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P1D", CheckStatus.Fail)]
    [DataRow("[global]\nuploaded-prior-to = P1D\n[install]\nuploaded-prior-to = P7D", CheckStatus.Pass)]
    [DataRow("[global]\nUploaded_Prior_To = P7D", CheckStatus.Pass)]
    [DataRow("[global]\nuploaded-prior-to = P7D\nuploaded-prior-to = P1D", CheckStatus.Error)]
    [DataRow("[download]\nuploaded-prior-to = P7D", CheckStatus.Fail)]
    public void Pip_TakesALengthUnderGlobal_AndInstallWinsOverIt(string ini, CheckStatus expected)
    {
        Assert.AreEqual(expected, new PipCooldownCheck().Run(new FakeProbes().WithFile(PipIni, ini + "\n")).Status);
    }

    [TestMethod]
    public void Pip_InstallInAnyFile_WinsOverGlobalInAnyFile()
    {
        FakeProbes probes = new FakeProbes()
            .WithFile(PipIni, "[global]\nuploaded-prior-to = P7D\n")
            .WithFile(@"C:\ProgramData\pip\pip.ini", "[install]\nuploaded-prior-to = P1D\n");

        CheckOutcome outcome = new PipCooldownCheck().Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(@"C:\ProgramData\pip\pip.ini, line 2", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void AFileThatCannotBeRead_BeforeTheOneThatSetsTheWait_IsCouldNotCheck()
    {
        // The user's file would win over the PC's, and nobody knows what it says.
        FakeProbes probes = new FakeProbes()
            .WithFileFailure(PipIni, ProbeFailure.AccessDenied())
            .WithFile(@"C:\ProgramData\pip\pip.ini", "[global]\nuploaded-prior-to = P7D\n");
        Assert.AreEqual(CheckStatus.Error, new PipCooldownCheck().Run(probes).Status);

        string global = Roaming + @"\npm\etc\npmrc";
        FakeProbes npm = new FakeProbes().WithFile(Npmrc, "not a settings line\n").WithFile(global, "min-release-age=7\n");
        Assert.AreEqual(CheckStatus.Error, new NpmCooldownCheck().Run(npm).Status);

        // The other way round the answer is known: the user's file sets it and wins.
        FakeProbes known = new FakeProbes().WithFile(Npmrc, "min-release-age=7\n").WithFile(global, "not a settings line\n");
        Assert.AreEqual(CheckStatus.Pass, new NpmCooldownCheck().Run(known).Status);
    }

    [TestMethod]
    public void Npm_TheLastLineOfTheSetting_IsTheOneInForce()
    {
        CheckOutcome outcome = new NpmCooldownCheck().Run(Npm("min-release-age=7\nmin-release-age=1\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($"{Npmrc}, line 2", outcome.Findings[0].Source);
        Assert.AreEqual(CheckStatus.Pass, new NpmCooldownCheck().Run(Npm("min-release-age=7 ; a week\n")).Status);
    }

    [TestMethod]
    public void AVariableWrittenWithAReference_IsExpanded_AsWindowsDoes()
    {
        // "%USERPROFILE%\settings\npmrc" names a file in the user folder.
        FakeProbes probes = WithVariable(Npm("min-release-age=7\n"), "NPM_CONFIG_USERCONFIG", @"%USERPROFILE%\settings\npmrc")
            .WithFile(Profile + @"\settings\npmrc", "min-release-age=1\n");

        CheckOutcome outcome = new NpmCooldownCheck().Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($@"{Profile}\settings\npmrc, line 1", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Pip_AFixedDate_IsCalledWhatItIs()
    {
        CheckOutcome outcome = new PipCooldownCheck().Run(new FakeProbes().WithFile(PipIni, "[global]\nuploaded-prior-to = 2026-11-01\n"));

        Assert.AreEqual("pip's release cut-off is a fixed date, which stops protecting as time passes.", outcome.Summary);
    }

    [TestMethod]
    public void Pip_IsInUse_OnceItsOwnFoldersExist_NotMerelyBecausePythonIsInstalled()
    {
        FakeProbes used = new FakeProbes().WithFile(Local + @"\pip\cache\selfcheck\abc", "x");
        Assert.AreEqual(CheckStatus.Fail, new PipCooldownCheck().Run(used).Status);

        FakeProbes pythonOnly = new FakeProbes().WithRegistryValue(
            RegistryRoot.CurrentUser, @"SOFTWARE\Python\PythonCore\3.14\InstallPath", "ExecutablePath", RegistryValue.FromText(@"C:\python\python.exe"));
        Assert.AreEqual(CheckStatus.NotApplicable, new PipCooldownCheck().Run(pythonOnly).Status);
    }

    [TestMethod]
    public void Pip_TheOldLocation_ThePcsFile_AndTheVariables_AllCount()
    {
        Assert.AreEqual(
            CheckStatus.Pass, new PipCooldownCheck().Run(new FakeProbes().WithFile(Profile + @"\pip\pip.ini", "[global]\nuploaded-prior-to = P7D\n")).Status);
        Assert.AreEqual(
            CheckStatus.Pass, new PipCooldownCheck().Run(new FakeProbes().WithFile(@"C:\ProgramData\pip\pip.ini", "[global]\nuploaded-prior-to = P10D\n")).Status);

        FakeProbes byVariable = WithVariable(new FakeProbes().WithFile(PipIni, "[global]\n"), "PIP_UPLOADED_PRIOR_TO", "P7D");
        Assert.AreEqual(CheckStatus.Pass, new PipCooldownCheck().Run(byVariable).Status);

        const string Moved = @"D:\settings\pip.ini";
        FakeProbes byConfigFile = WithVariable(new FakeProbes().WithFile(PipIni, "[global]\n"), "PIP_CONFIG_FILE", Moved)
            .WithFile(Moved, "[global]\nuploaded-prior-to = P7D\n");
        Assert.AreEqual(CheckStatus.Pass, new PipCooldownCheck().Run(byConfigFile).Status);
    }

    // Poetry and PDM

    [TestMethod]
    [DataRow("[solver]\nmin-release-age = 7", CheckStatus.Pass)]
    [DataRow("[solver]\nmin-release-age = 2", CheckStatus.Fail)]
    [DataRow("[solver]\nmin-release-age = \"7\"", CheckStatus.Error)]
    [DataRow("[virtualenvs]\nin-project = true", CheckStatus.Fail)]
    public void Poetry_TheNumberIsDays_UnderSolver(string toml, CheckStatus expected)
    {
        Assert.AreEqual(expected, new PoetryCooldownCheck().Run(new FakeProbes().WithFile(PoetryConfig, toml + "\n")).Status);
    }

    [TestMethod]
    [DataRow("[strategy]\nexclude-newer = \"7d\"", CheckStatus.Pass)]
    [DataRow("strategy.exclude-newer = \"2w\"", CheckStatus.Pass)]
    [DataRow("[strategy]\nexclude-newer = \"3d\"", CheckStatus.Fail)]
    [DataRow("[strategy]\nexclude-newer = \"2026-11-01\"", CheckStatus.Fail)]
    [DataRow("[strategy]\nexclude-newer = \"7\"", CheckStatus.Error)]
    [DataRow("[pypi]\nurl = \"https://pypi.org/simple\"", CheckStatus.Fail)]
    public void Pdm_TakesANumberWithAUnit_UnderStrategy(string toml, CheckStatus expected)
    {
        Assert.AreEqual(expected, new PdmCooldownCheck().Run(new FakeProbes().WithFile(PdmConfig, toml + "\n")).Status);
    }
}
