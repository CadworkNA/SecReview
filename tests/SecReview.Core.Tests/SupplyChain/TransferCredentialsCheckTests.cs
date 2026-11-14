using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Credentials;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

/// <summary>Saved passwords of file transfer tools. Every name, host and value here is made up.</summary>
[TestClass]
public sealed class TransferCredentialsCheckTests
{
    private const string Secret = "made-up-secret";
    private const string Session = TransferCredentialsCheck.WinScpSessions + @"\user1@files.example.test";
    private const string PuttySession = TransferCredentialsCheck.PuttySessions + @"\Example";

    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);
    private static readonly string WinScpIni = Roaming + @"\WinSCP.ini";
    private static readonly string SiteManager = Roaming + @"\FileZilla\sitemanager.xml";
    private static readonly string RecentServers = Roaming + @"\FileZilla\recentservers.xml";

    private static readonly TransferCredentialsCheck Check = new();

    private static FakeProbes Text(FakeProbes probes, string key, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, key, name, RegistryValue.FromText(value));

    /// <summary>WinSCP with one saved site, and a password for it under the given name.</summary>
    private static FakeProbes WinScp(string? passwordName = "Password")
    {
        FakeProbes probes = Text(new FakeProbes(), Session, "HostName", "files.example.test");
        Text(probes, Session, "UserName", "user1");
        return passwordName is null ? probes : Text(probes, Session, passwordName, Secret);
    }

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    [TestMethod]
    public void WithNoToolSetUp_ItDoesNotApply_AndItReadsTheUsersOwnSettings()
    {
        CheckOutcome outcome = Check.Run(new FakeProbes());

        Assert.AreEqual(CheckStatus.NotApplicable, outcome.Status);
        Assert.AreEqual("No file transfer tool is set up for this user.", outcome.Summary);
        Assert.AreEqual(CheckScope.User, Check.Definition.Scope);
        Assert.AreEqual(AdminNeed.No, Check.Definition.NeedsAdmin);
    }

    [TestMethod]
    public void FileZilla_AnEncodedOrWrittenPassword_Fails_AnEncryptedOneDoesNot()
    {
        const string Sites = """
            <?xml version="1.0" encoding="UTF-8"?>
            <FileZilla3 version="3.60.0" platform="windows">
              <Servers>
                <Server>
                  <Host>files.example.test</Host>
                  <User>user1</User>
                  <Pass encoding="base64">bWFkZS11cA==</Pass>
                  <Name>Example site</Name>
                </Server>
                <Folder>Old
                  <Server>
                    <Host>old.example.test</Host>
                    <Pass>made-up-secret</Pass>
                  </Server>
                  <Server>
                    <Host>safe.example.test</Host>
                    <Pass encoding="crypt" pubkey="AAAA">BBBB</Pass>
                  </Server>
                  <Server>
                    <Host>ask.example.test</Host>
                    <Pass encoding="base64"></Pass>
                  </Server>
                </Folder>
              </Servers>
            </FileZilla3>
            """;

        CheckOutcome outcome = Check.Run(new FakeProbes().WithFile(SiteManager, Sites));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("File transfer tools: 2 secrets are stored as plain text.", outcome.Summary);
        CollectionAssert.AreEquivalent(
            (string[])["FileZilla password for files.example.test", "FileZilla password for old.example.test"],
            outcome.Findings.Select(f => f.Item).ToArray());
        StringAssert.StartsWith(outcome.Findings[0].Source, SiteManager + ", line ");
        Assert.IsFalse(Everything(outcome).Contains("bWFkZS11cA", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains(Secret, StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("Example site", StringComparison.Ordinal));
    }

    [TestMethod]
    public void FileZilla_RecentServersAreRead_AndAFileWithoutPasswordsPasses()
    {
        const string Recent = "<FileZilla3><RecentServers><Server><Host>files.example.test</Host><Pass encoding=\"base64\">bWFkZS11cA==</Pass></Server></RecentServers></FileZilla3>";
        const string Empty = "<FileZilla3><Servers /></FileZilla3>";

        Assert.AreEqual(CheckStatus.Fail, Check.Run(new FakeProbes().WithFile(RecentServers, Recent)).Status);
        Assert.AreEqual(CheckStatus.Pass, Check.Run(new FakeProbes().WithFile(SiteManager, Empty)).Status);
    }

    [TestMethod]
    public void Putty_AProxyPassword_Fails_NamingTheProxyOnly()
    {
        FakeProbes saved = Text(Text(new FakeProbes(), PuttySession, "ProxyHost", "proxy.example.test"), PuttySession, "ProxyPassword", Secret);
        FakeProbes none = Text(Text(new FakeProbes(), PuttySession, "ProxyHost", "proxy.example.test"), PuttySession, "ProxyPassword", string.Empty);

        CheckOutcome outcome = Check.Run(saved);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("PuTTY proxy password for proxy.example.test", outcome.Findings[0].Item);
        Assert.IsFalse(Everything(outcome).Contains(Secret, StringComparison.Ordinal));
        Assert.AreEqual(CheckStatus.Pass, Check.Run(none).Status);
    }

    [TestMethod]
    public void WinScp_ASavedSiteWithoutAPassword_Passes()
    {
        CheckOutcome outcome = Check.Run(WinScp(passwordName: null));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("File transfer tools: no passwords are stored as plain text.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("Password")]
    [DataRow("PasswordPlain")]
    [DataRow("TunnelPassword")]
    [DataRow("ProxyPasswordEnc")]
    [DataRow("EncryptKey")]
    public void WinScp_ASavedPassword_Fails_NamingTheServerOnly(string name)
    {
        CheckOutcome outcome = Check.Run(WinScp(name));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("File transfer tools: 1 secret is stored as plain text.", outcome.Summary);
        Assert.AreEqual("WinSCP password for files.example.test", outcome.Findings[0].Item);
        Assert.AreEqual($@"HKCU\{TransferCredentialsCheck.WinScpSessions}", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains(Secret, StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("user1", StringComparison.Ordinal), "neither the site's name nor the user name is shown");
    }

    [TestMethod]
    public void WinScp_WithAMasterPassword_OnlyWhatIsKeptAsWrittenCounts()
    {
        FakeProbes encrypted = WinScp("Password")
            .WithRegistryNumber(RegistryRoot.CurrentUser, TransferCredentialsCheck.WinScpSecurity, "UseMasterPassword", 1);
        FakeProbes written = WinScp("PasswordPlain")
            .WithRegistryNumber(RegistryRoot.CurrentUser, TransferCredentialsCheck.WinScpSecurity, "UseMasterPassword", 1);
        FakeProbes off = WinScp("Password")
            .WithRegistryNumber(RegistryRoot.CurrentUser, TransferCredentialsCheck.WinScpSecurity, "UseMasterPassword", 0);

        Assert.AreEqual(CheckStatus.Pass, Check.Run(encrypted).Status);
        Assert.AreEqual(CheckStatus.Fail, Check.Run(written).Status);
        Assert.AreEqual(CheckStatus.Fail, Check.Run(off).Status);
    }

    [TestMethod]
    public void WinScp_AMasterPasswordSettingThatIsNotANumber_IsCouldNotCheck()
    {
        FakeProbes probes = Text(WinScp("Password"), TransferCredentialsCheck.WinScpSecurity, "UseMasterPassword", "perhaps");

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes).Status);
    }

    [TestMethod]
    public void WinScp_TheSettingsFile_IsReadTheSameWay()
    {
        const string Saved = """
            [Configuration\Interface]
            Language=en

            [Sessions\user1@files.example.test]
            HostName=files.example.test
            UserName=user1
            Password=0B6E91D2C47F
            """;
        const string Protected = Saved + "\n[Configuration\\Security]\nUseMasterPassword=1\n";
        const string NoPassword = "[Sessions\\user1@files.example.test]\nHostName=files.example.test\n";

        CheckOutcome outcome = Check.Run(new FakeProbes().WithFile(WinScpIni, Saved));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("WinSCP password for files.example.test", outcome.Findings[0].Item);
        Assert.AreEqual($"{WinScpIni}, line 4", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("0B6E", StringComparison.Ordinal));
        Assert.AreEqual(CheckStatus.Pass, Check.Run(new FakeProbes().WithFile(WinScpIni, Protected)).Status);
        Assert.AreEqual(CheckStatus.Pass, Check.Run(new FakeProbes().WithFile(WinScpIni, NoPassword)).Status);
    }

    [TestMethod]
    public void AFileThatCannotBeRead_IsCouldNotCheck_UnlessAPasswordWasFoundElsewhere()
    {
        FakeProbes broken = new FakeProbes().WithFile(SiteManager, "<FileZilla3><Servers>");
        FakeProbes denied = new FakeProbes().WithFileFailure(WinScpIni, ProbeFailure.AccessDenied());
        FakeProbes both = WinScp("Password").WithFile(SiteManager, "<FileZilla3><Servers>");

        Assert.AreEqual(CheckStatus.Error, Check.Run(broken).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(denied).Status);
        Assert.AreEqual(CheckStatus.Fail, Check.Run(both).Status);
    }

    private static readonly string Profile = FakeProbes.FolderPath(KnownFolder.UserProfile);
    private static readonly string ScoopWinScp = Profile + @"\scoop\apps\winscp\current";
    private static readonly string ScoopFileZilla = Profile + @"\scoop\apps\filezilla\current";

    private const string WinScpSaved = "[Sessions\\user1@files.example.test]\nHostName=files.example.test\nPassword=0B6E91D2C47F\n";
    private const string FileZillaSaved =
        "<FileZilla3><Servers><Server><Host>files.example.test</Host><User>user1</User><Pass encoding=\"base64\">bWFkZS11cA==</Pass></Server></Servers></FileZilla3>";

    private static FakeProbes Scoop(FakeProbes probes) => probes.WithFile($@"{Profile}\scoop\apps\scoop\current\bin\scoop.ps1", "# scoop");

    private static FakeProbes SearchPath(FakeProbes probes, string folder) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "Path", RegistryValue.FromText($@"C:\Windows;{folder};relative\bin;\\server\share"));

    private static string FileZillaDefaults(string location) =>
        $"<FileZilla3><Settings><Setting name=\"Config Location\">{location}</Setting></Settings></FileZilla3>";

    [TestMethod]
    public void Portable_WinScpFromScoop_ReadsTheSettingsFileBesideTheProgram()
    {
        FakeProbes probes = Scoop(new FakeProbes())
            .WithFile($@"{ScoopWinScp}\WinSCP.exe", "x")
            .WithFile($@"{ScoopWinScp}\WinSCP.ini", WinScpSaved);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("WinSCP password for files.example.test", outcome.Findings[0].Item);
        Assert.AreEqual($@"{ScoopWinScp}\WinSCP.ini, line 1", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("0B6E", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Portable_FileZillaFromScoop_FollowsTheSettingsFolderItsDefaultsName()
    {
        FakeProbes probes = Scoop(new FakeProbes())
            .WithFile($@"{ScoopFileZilla}\filezilla.exe", "x")
            .WithFile($@"{ScoopFileZilla}\fzdefaults.xml", FileZillaDefaults(@"data\config"))
            .WithFile($@"{ScoopFileZilla}\data\config\sitemanager.xml", FileZillaSaved);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("FileZilla password for files.example.test", outcome.Findings[0].Item);
        StringAssert.StartsWith(outcome.Findings[0].Source, $@"{ScoopFileZilla}\data\config\sitemanager.xml");
        Assert.IsFalse(Everything(outcome).Contains("user1", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Portable_OnTheSearchPath_OnlyBesideTheProgram_AndNeverOnTheNetwork()
    {
        const string Tools = @"D:\Tools\WinSCP";
        FakeProbes beside = SearchPath(new FakeProbes(), Tools)
            .WithFile($@"{Tools}\WinSCP.exe", "x")
            .WithFile($@"{Tools}\WinSCP.ini", WinScpSaved);
        FakeProbes withoutProgram = SearchPath(new FakeProbes(), Tools).WithFile($@"{Tools}\WinSCP.ini", WinScpSaved);
        FakeProbes network = SearchPath(new FakeProbes(), Tools)
            .WithFolderFailure(@"\\server\share", ProbeFailure.Failed("Network paths are never opened."))
            .WithFile($@"{Tools}\WinSCP.exe", "x");

        Assert.AreEqual(CheckStatus.Fail, Check.Run(beside).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Check.Run(withoutProgram).Status, "a settings file without the program beside it is no copy of WinSCP");
        Assert.AreEqual(CheckStatus.NotApplicable, Check.Run(network).Status, "a network folder is not opened");
    }

    [TestMethod]
    public void Portable_FileZillaDefaults_CanHoldSites_AndNameAFolderThroughAVariable()
    {
        const string Tools = @"D:\Tools\FileZilla";
        FakeProbes sites = SearchPath(new FakeProbes(), Tools)
            .WithFile($@"{Tools}\filezilla.exe", "x")
            .WithFile($@"{Tools}\fzdefaults.xml", FileZillaSaved);
        FakeProbes variable = SearchPath(new FakeProbes(), Tools)
            .WithVariable("FZ_HOME", @"E:\Settings")
            .WithFile($@"{Tools}\filezilla.exe", "x")
            .WithFile($@"{Tools}\fzdefaults.xml", FileZillaDefaults("$FZ_HOME/filezilla/"))
            .WithFile(@"E:\Settings\filezilla\recentservers.xml", FileZillaSaved);
        FakeProbes unset = SearchPath(new FakeProbes(), Tools)
            .WithFile($@"{Tools}\filezilla.exe", "x")
            .WithFile($@"{Tools}\fzdefaults.xml", FileZillaDefaults("$NOT_SET/filezilla"));

        Assert.AreEqual(CheckStatus.Fail, Check.Run(sites).Status);
        Assert.AreEqual(CheckStatus.Fail, Check.Run(variable).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(unset).Status, "a settings folder that cannot be told is could not check");
    }

    [TestMethod]
    public void Portable_FileZillaDefaultsNamingTheUsualFolder_CountsEachPasswordOnce()
    {
        const string Tools = @"D:\Tools\FileZilla";
        FakeProbes probes = SearchPath(new FakeProbes(), Tools)
            .WithVariable("APPDATA", Roaming)
            .WithFile($@"{Tools}\filezilla.exe", "x")
            .WithFile($@"{Tools}\fzdefaults.xml", FileZillaDefaults(@"$APPDATA\FileZilla"))
            .WithFile(SiteManager, FileZillaSaved);

        Assert.AreEqual("File transfer tools: 1 secret is stored as plain text.", Check.Run(probes).Summary);
    }

    [TestMethod]
    [DataRow(@"data\config", @"D:\FileZilla\data\config")]
    [DataRow(@".", @"D:\FileZilla")]
    [DataRow(@"..\settings\", @"D:\settings")]
    [DataRow(@"E:/Settings/FileZilla/", @"E:\Settings\FileZilla")]
    [DataRow(@"E:\$$money\fz", @"E:\$money\fz")]
    [DataRow(@"$HOME_DIR\fz", @"E:\Home\fz")]
    public void Portable_FileZillasConfigLocation_IsResolvedAsFileZillaDoes(string location, string expected)
    {
        IEnvironmentProbe environment = new FakeProbes().WithVariable("HOME_DIR", @"E:\Home").Build().Environment;

        Assert.AreEqual(expected, TransferCredentialsCheck.SettingsFolder(location, @"D:\FileZilla", environment));
    }

    [TestMethod]
    public void WhenTheRegistryCannotBeRead_TheAnswerIsCouldNotCheck()
    {
        var probes = new FakeProbes { RegistryFailure = ProbeFailure.Failed("The registry did not answer.") };

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes).Status);
    }
}
