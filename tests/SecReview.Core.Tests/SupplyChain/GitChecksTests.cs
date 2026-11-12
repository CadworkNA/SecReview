using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Git;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class GitChecksTests
{
    private static readonly string Profile = FakeProbes.UserProfile;
    private static readonly string UserConfig = Profile + @"\.gitconfig";
    private const string InstallFolder = @"C:\Program Files\Git";
    private const string SystemConfig = InstallFolder + @"\etc\gitconfig";

    private static readonly GitSettingsCheck Settings = new();
    private static readonly GitCredentialsCheck Passwords = new();

    /// <summary>A PC with Git and the given user settings.</summary>
    private static FakeProbes Git(string userConfig = "[user]\n\tname = Someone\n") => new FakeProbes()
        .WithRegistryValue(RegistryRoot.LocalMachine, @"SOFTWARE\GitForWindows", "InstallPath", RegistryValue.FromText(InstallFolder))
        .WithFile(UserConfig, userConfig);

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    [TestMethod]
    public void WithoutGit_NeitherCheckApplies_AndNeitherRunsElevated()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Settings.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Passwords.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, Settings.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Passwords.Definition.Scope);
    }

    [TestMethod]
    public void GitIsFound_ByItsInstallRecord_ItsSettingsFile_OrScoop()
    {
        FakeProbes recordOnly = new FakeProbes().WithRegistryValue(
            RegistryRoot.LocalMachine, @"SOFTWARE\GitForWindows", "InstallPath", RegistryValue.FromText(InstallFolder));
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(recordOnly).Status);

        Assert.AreEqual(CheckStatus.Pass, Settings.Run(new FakeProbes().WithFile(UserConfig, "[user]\n\tname = Someone\n")).Status);

        string scoopGit = Profile + @"\scoop\apps\git\current";
        FakeProbes scoop = new FakeProbes()
            .WithFile(Profile + @"\scoop\apps\scoop\current\bin\scoop.ps1", "#")
            .WithFile(scoopGit + @"\etc\gitconfig", "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(scoop).Status, "the settings of a Git from Scoop are read");
    }

    // Settings

    [TestMethod]
    public void Settings_AnOrdinaryFile_Passes()
    {
        const string Text = "[user]\n\tname = Someone\n[core]\n\tautocrlf = true\n\tfsmonitor = true\n[http]\n\tsslVerify = true\n[safe]\n\tdirectory = D:/work/project\n[credential]\n\thelper = manager\n";

        CheckOutcome outcome = Settings.Run(Git(Text));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Git's settings keep its protections on.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("[http]\n\tsslVerify = false", "Git: TLS certificate checks: off.")]
    [DataRow("[http]\n\tsslverify = no", "Git: TLS certificate checks: off.")]
    [DataRow("[http \"https://git.example.test/\"]\n\tsslVerify = false", "Git: TLS certificate checks for git.example.test: off.")]
    [DataRow("[safe]\n\tdirectory = *", "Git: ownership check on repositories: off for every folder.")]
    [DataRow("[protocol]\n\tallow = always", "Git: transports a repository may ask for: all of them.")]
    [DataRow("[protocol \"ext\"]\n\tallow = always", "Git: the \"ext\" transport: always allowed: an address can run a command.")]
    [DataRow("[protocol \"file\"]\n\tallow = always", "Git: local-folder transport: always allowed, for submodules too.")]
    [DataRow("[url \"http://git.example.test/\"]\n\tinsteadOf = https://git.example.test/", "Git: address rewrite: secure addresses are sent unencrypted.")]
    [DataRow("[url \"git://git.example.test/\"]\n\tpushInsteadOf = git@git.example.test:", "Git: address rewrite: secure addresses are sent unencrypted.")]
    public void Settings_EachWeakSetting_Fails_AndIsNamed(string text, string summary)
    {
        CheckOutcome outcome = Settings.Run(Git(text + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual($"{UserConfig}, line 2", outcome.Findings[0].Source);
    }

    [TestMethod]
    [DataRow("[http]\n\tsslVerify = false\n\tsslVerify = true", DisplayName = "the last value wins")]
    [DataRow("[safe]\n\tdirectory = *\n\tdirectory =", DisplayName = "an empty value clears the list")]
    [DataRow("[protocol \"file\"]\n\tallow = user", DisplayName = "Git's own limit")]
    [DataRow("[url \"https://git.example.test/\"]\n\tinsteadOf = http://git.example.test/", DisplayName = "a rewrite towards HTTPS")]
    [DataRow("[url \"git@git.example.test:\"]\n\tinsteadOf = https://git.example.test/", DisplayName = "a rewrite towards SSH")]
    public void Settings_WhatIsNotAWeakness_Passes(string text)
    {
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Git(text + "\n")).Status);
    }

    [TestMethod]
    public void Settings_TheUsersFile_WinsOverThePcs_AndThePcsCountsWhenTheUsersIsSilent()
    {
        FakeProbes overridden = Git("[http]\n\tsslVerify = true\n").WithFile(SystemConfig, "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(overridden).Status);

        CheckOutcome fromThePc = Settings.Run(Git().WithFile(SystemConfig, "[http]\n\tsslVerify = false\n"));
        Assert.AreEqual(CheckStatus.Fail, fromThePc.Status);
        Assert.AreEqual($"{SystemConfig}, line 2", fromThePc.Findings[0].Source);

        CheckOutcome programData = Settings.Run(Git().WithFile(@"C:\ProgramData\Git\config", "[safe]\n\tdirectory = *\n"));
        Assert.AreEqual(CheckStatus.Fail, programData.Status);
    }

    [TestMethod]
    public void Settings_Variables_MoveOrSwitchOffTheFiles()
    {
        const string Moved = @"D:\settings\gitconfig";
        FakeProbes global = WithVariable(Git("[http]\n\tsslVerify = false\n"), "GIT_CONFIG_GLOBAL", Moved).WithFile(Moved, "[user]\n\tname = Someone\n");
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(global).Status, "the usual file is not read any more");

        FakeProbes noSystem = WithVariable(Git().WithFile(SystemConfig, "[http]\n\tsslVerify = false\n"), "GIT_CONFIG_NOSYSTEM", "1");
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(noSystem).Status);

        FakeProbes xdg = Git().WithFile(Profile + @"\.config\git\config", "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(xdg).Status, "the second user file counts");
    }

    [TestMethod]
    public void Settings_IncludedFiles_AreFollowed_InPlace()
    {
        FakeProbes probes = Git("[include]\n\tpath = ~/work.gitconfig\n\tpath = extra/more.gitconfig\n")
            .WithFile(Profile + @"\work.gitconfig", "[http]\n\tsslVerify = false\n")
            .WithFile(Profile + @"\extra\more.gitconfig", "[user]\n\tname = Someone\n");

        CheckOutcome outcome = Settings.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($@"{Profile}\work.gitconfig, line 2", outcome.Findings[0].Source);

        // What comes after the include wins over what it brought in.
        FakeProbes later = Git("[include]\n\tpath = ~/work.gitconfig\n[http]\n\tsslVerify = true\n")
            .WithFile(Profile + @"\work.gitconfig", "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(later).Status);

        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Git("[include]\n\tpath = ~/gone.gitconfig\n")).Status, "a missing include is skipped, as Git does");
    }

    [TestMethod]
    public void Settings_AFileIncludedForSomeRepositories_IsMarkedAsSuch()
    {
        FakeProbes probes = Git("[includeIf \"gitdir:D:/work/\"]\n\tpath = ~/work.gitconfig\n")
            .WithFile(Profile + @"\work.gitconfig", "[http]\n\tsslVerify = false\n");

        CheckOutcome outcome = Settings.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("TLS certificate checks (in some repositories)", outcome.Findings[0].Item);
    }

    [TestMethod]
    public void Settings_IncludesInACircle_AreCouldNotCheck_NotAHang()
    {
        FakeProbes probes = Git("[include]\n\tpath = ~/a.gitconfig\n")
            .WithFile(Profile + @"\a.gitconfig", "[include]\n\tpath = ~/a.gitconfig\n");

        Assert.AreEqual(CheckStatus.Error, Settings.Run(probes).Status);
    }

    [TestMethod]
    public void Settings_ThatMakeGitRunAProgram_AreListed_NotFailed()
    {
        const string Text = "[core]\n\thooksPath = ~/hooks\n\tsshCommand = C:/tools/ssh.exe\n\tfsmonitor = C:/tools/watch.exe\n";

        CheckOutcome outcome = Settings.Run(Git(Text));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Git's protections are on; 3 settings make Git run programs you chose.", outcome.Summary);
        Assert.AreEqual(3, outcome.Findings.Count(f => f.Status == FindingStatus.Note));
    }

    [TestMethod]
    public void Settings_AFileThatCannotBeUnderstood_IsCouldNotCheck_ButADefiniteProblemStillFails()
    {
        Assert.AreEqual(CheckStatus.Error, Settings.Run(Git("[http\n\tsslVerify = false\n")).Status);
        Assert.AreEqual(CheckStatus.Error, Settings.Run(new FakeProbes().WithFileFailure(UserConfig, ProbeFailure.AccessDenied())).Status);

        FakeProbes both = Git("[http\n").WithFile(SystemConfig, "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(both).Status);
    }

    [TestMethod]
    public void Settings_SeveralProblems_AreCounted()
    {
        CheckOutcome outcome = Settings.Run(Git("[http]\n\tsslVerify = false\n[safe]\n\tdirectory = *\n"));

        Assert.AreEqual("Git has 2 settings that weaken its protections.", outcome.Summary);
    }

    // Stored passwords

    [TestMethod]
    public void Passwords_KeptByWindows_Pass()
    {
        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(Git("[credential]\n\thelper = manager\n")).Status);
        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(Git()).Status);
    }

    [TestMethod]
    [DataRow("[credential]\n\thelper = store", "Git: password helper: \"store\": saves passwords in a plain file.")]
    [DataRow("[credential]\n\thelper = store --file ~/.my-credentials", "Git: password helper: \"store\": saves passwords in a plain file.")]
    [DataRow("[credential \"https://git.example.test\"]\n\thelper = store", "Git: password helper: \"store\": saves passwords in a plain file.")]
    [DataRow("[credential]\n\tcredentialStore = plaintext", "Git: Git Credential Manager: told to save passwords in plain files.")]
    public void Passwords_AHelperThatWritesPlainFiles_Fails(string text, string summary)
    {
        CheckOutcome outcome = Passwords.Run(Git(text + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Passwords_AHelperListThatWasCleared_IsReadAsGitReadsIt()
    {
        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(Git("[credential]\n\thelper = store\n\thelper =\n\thelper = manager\n")).Status);
        Assert.AreEqual(CheckStatus.Fail, Passwords.Run(Git("[credential]\n\thelper =\n\thelper = store\n")).Status);
    }

    [TestMethod]
    public void Passwords_InGitCredentials_Fail_WithoutShowingThem()
    {
        FakeProbes probes = Git().WithFile(
            Profile + @"\.git-credentials", "https://someone:made-up-token@git.example.test\nhttps://other:made-up-other@code.example.test\n\n");

        CheckOutcome outcome = Passwords.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Git: saved passwords (.git-credentials): 2, as plain text.", outcome.Summary);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("someone", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("example.test", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Passwords_InNetrc_Fail_EvenWithoutGit()
    {
        FakeProbes probes = new FakeProbes().WithFile(
            Profile + @"\_netrc", "machine git.example.test\n  login someone\n  password made-up-password\nmachine other.example.test login x password made-up-other\n");

        CheckOutcome outcome = Passwords.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Git: saved passwords (_netrc): 2, as plain text.", outcome.Summary);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Passwords_ANetrcWithoutPasswords_AndAnEmptyCredentialsFile_Pass()
    {
        FakeProbes probes = Git()
            .WithFile(Profile + @"\_netrc", "machine git.example.test login someone\n")
            .WithFile(Profile + @"\.git-credentials", "\n");

        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(probes).Status);
    }

    [TestMethod]
    public void Passwords_TheVariableForGitCredentialManager_Counts()
    {
        CheckOutcome outcome = Passwords.Run(WithVariable(Git(), "GCM_CREDENTIAL_STORE", "plaintext"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Source, "GCM_CREDENTIAL_STORE");
    }

    [TestMethod]
    public void Passwords_AFileThatCannotBeRead_IsCouldNotCheck()
    {
        Assert.AreEqual(
            CheckStatus.Error, Passwords.Run(Git().WithFileFailure(Profile + @"\.git-credentials", ProbeFailure.AccessDenied())).Status);
        Assert.AreEqual(CheckStatus.Error, Passwords.Run(Git("[credential\n")).Status);
    }

    // What the reviews found

    [TestMethod]
    public void Settings_AFileIncludedForSomeRepositories_NeverHidesWhatAppliesEverywhere()
    {
        FakeProbes tls = Git("[http]\n\tsslVerify = false\n[includeIf \"gitdir:D:/work/\"]\n\tpath = ~/work.gitconfig\n")
            .WithFile(Profile + @"\work.gitconfig", "[http]\n\tsslVerify = true\n[safe]\n\tdirectory =\n");
        CheckOutcome outcome = Settings.Run(tls);
        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("TLS certificate checks", outcome.Findings[0].Item);

        FakeProbes owner = Git("[safe]\n\tdirectory = *\n[includeIf \"gitdir:D:/work/\"]\n\tpath = ~/work.gitconfig\n")
            .WithFile(Profile + @"\work.gitconfig", "[safe]\n\tdirectory =\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(owner).Status);

        FakeProbes helper = Git("[credential]\n\thelper = store\n[includeIf \"gitdir:D:/work/\"]\n\tpath = ~/work.gitconfig\n")
            .WithFile(Profile + @"\work.gitconfig", "[credential]\n\thelper =\n");
        Assert.AreEqual(CheckStatus.Fail, Passwords.Run(helper).Status);
    }

    [TestMethod]
    public void GitsHome_IsTheHomeVariable_ThenTheSessionsHomeFolder_ThenTheProfile()
    {
        FakeProbes byVariable = WithVariable(Git(), "HOME", @"D:\home")
            .WithFile(@"D:\home\.gitconfig", "[http]\n\tsslVerify = false\n")
            .WithFile(@"D:\home\.git-credentials", "https://a:made-up@git.example.test\n");
        CheckOutcome settings = Settings.Run(byVariable);
        Assert.AreEqual(CheckStatus.Fail, settings.Status);
        Assert.AreEqual(@"D:\home\.gitconfig, line 2", settings.Findings[0].Source);
        Assert.AreEqual(CheckStatus.Fail, Passwords.Run(byVariable).Status);

        FakeProbes bySession = Git().WithVariable("HOMEDRIVE", "H:").WithVariable("HOMEPATH", @"\")
            .WithFile(@"H:\.gitconfig", "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(bySession).Status, "a drive alone is not a folder to read from");

        FakeProbes share = Git().WithVariable("HOMEDRIVE", "H:").WithVariable("HOMEPATH", @"\users\someone")
            .WithFile(@"H:\users\someone\.gitconfig", "[http]\n\tsslVerify = false\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(share).Status);
    }

    [TestMethod]
    public void Git_InstalledForOneUser_IsFound_AndItsSettingsAreRead()
    {
        FakeProbes probes = new FakeProbes()
            .WithRegistryValue(RegistryRoot.CurrentUser, @"SOFTWARE\GitForWindows", "InstallPath", RegistryValue.FromText(@"D:\apps\Git"))
            .WithFile(@"D:\apps\Git\etc\gitconfig", "[http]\n\tsslVerify = false\n");

        Assert.AreEqual(CheckStatus.Fail, Settings.Run(probes).Status);
    }

    [TestMethod]
    public void Settings_HandedToGitThroughVariables_CountAndWin()
    {
        FakeProbes probes = WithVariable(WithVariable(WithVariable(Git("[http]\n\tsslVerify = true\n"),
            "GIT_CONFIG_COUNT", "1"), "GIT_CONFIG_KEY_0", "http.sslVerify"), "GIT_CONFIG_VALUE_0", "false");

        CheckOutcome outcome = Settings.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Source, "GIT_CONFIG_KEY_0");

        FakeProbes perAddress = WithVariable(WithVariable(WithVariable(Git(),
            "GIT_CONFIG_COUNT", "1"), "GIT_CONFIG_KEY_0", "http.https://git.example.test/.sslVerify"), "GIT_CONFIG_VALUE_0", "false");
        Assert.AreEqual("TLS certificate checks for git.example.test", Settings.Run(perAddress).Findings[0].Item);
    }

    [TestMethod]
    [DataRow("00")]
    [DataRow("0x0")]
    [DataRow("-0")]
    [DataRow("0k")]
    public void Settings_ANumber_IsReadAsYesOrNo_AsGitDoes(string zero)
    {
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(Git($"[http]\n\tsslVerify = {zero}\n")).Status);
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Git("[http]\n\tsslVerify = 2\n")).Status);
    }

    [TestMethod]
    public void Settings_AnIncludedPathThatDependsOnHowGitWasStarted_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, Settings.Run(Git("[include]\n\tpath = /ProgramData/x/config\n")).Status);
        Assert.AreEqual(CheckStatus.Error, Settings.Run(Git("[include]\n\tpath = %(prefix)/etc/extra\n")).Status);
    }

    [TestMethod]
    public void Settings_MoreIncludedFilesThanAreRead_IsCouldNotCheck_NotAnEndlessRead()
    {
        // Every file includes the next ten times: without a budget that is ten to the power of the depth.
        string many = "[include]\n" + string.Concat(Enumerable.Repeat("\tpath = next.gitconfig\n", 10));
        FakeProbes probes = Git("[include]\n\tpath = ~/level0/next.gitconfig\n");
        string folder = Profile + @"\level0";
        for (int level = 0; level < 5; level++)
        {
            probes.WithFile(folder + @"\next.gitconfig", many.Replace("next.gitconfig", $"level{level + 1}/next.gitconfig", StringComparison.Ordinal));
            folder += $@"\level{level + 1}";
        }

        probes.WithFile(folder + @"\next.gitconfig", "[user]\n\tname = Someone\n");

        Assert.AreEqual(CheckStatus.Error, Settings.Run(probes).Status);
    }

    [TestMethod]
    [DataRow("store")]
    [DataRow("store\t--file=~/.my-credentials")]
    [DataRow("!git credential-store --file ~/.my-credentials")]
    [DataRow("C:/Program Files/Git/mingw64/libexec/git-core/git-credential-store.exe")]
    public void Passwords_ThePlainFileHelper_IsRecognised_HoweverItIsWritten(string helper)
    {
        Assert.AreEqual(CheckStatus.Fail, Passwords.Run(Git($"[credential]\n\thelper = \"{helper}\"\n")).Status);
    }

    [TestMethod]
    public void Passwords_AnEmptyHelper_ClearsEveryHelperBeforeIt()
    {
        const string Text = "[credential \"https://git.example.test\"]\n\thelper = store\n[credential]\n\thelper =\n\thelper = manager\n";

        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(Git(Text)).Status);
    }

    [TestMethod]
    public void Passwords_SeveralWays_AreCounted()
    {
        FakeProbes probes = Git("[credential]\n\thelper = store\n").WithFile(Profile + @"\.git-credentials", "https://a:made-up@git.example.test\n");

        Assert.AreEqual("Git keeps passwords as plain text in 2 ways.", Passwords.Run(probes).Summary);
    }
}
