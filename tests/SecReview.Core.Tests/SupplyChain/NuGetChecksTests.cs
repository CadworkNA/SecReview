using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain.NuGet;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class NuGetChecksTests
{
    private static readonly string UserConfig = FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\NuGet\NuGet.Config";
    private const string MachineFolder = @"C:\Program Files (x86)\NuGet\Config";
    private const string SdkFolder = @"C:\Program Files\dotnet\sdk";

    private const string NuGetOrg = """<add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />""";
    private const string Private = """<add key="company feed" value="https://packages.example.test/v3/index.json" />""";

    private static readonly NuGetSourcesCheck Sources = new();
    private static readonly NuGetCredentialsCheck Passwords = new();
    private static readonly NuGetCooldownCheck Cooldown = new();

    private static string Config(string sources, string rest = "") =>
        $"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    {sources}\n  </packageSources>\n{rest}</configuration>\n";

    /// <summary>A PC with the given user settings and, unless told otherwise, .NET SDK 11.0.100.</summary>
    private static FakeProbes NuGet(string config, string? sdk = "11.0.100")
    {
        FakeProbes probes = new FakeProbes().WithFile(UserConfig, config);
        return sdk is null ? probes : probes.WithFile($@"{SdkFolder}\{sdk}\dotnet.dll", "binary");
    }

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    [TestMethod]
    public void WithoutNuGet_NoneOfTheChecksApply_AndNoneRunsElevated()
    {
        foreach (ICheck check in new ICheck[] { Sources, Passwords, Cooldown })
        {
            Assert.AreEqual(CheckStatus.NotApplicable, check.Run(new FakeProbes()).Status, check.Definition.Id);
            Assert.AreEqual(CheckScope.User, check.Definition.Scope);
        }
    }

    [TestMethod]
    public void WithTheSdkButNoSettingsFile_NuGetUsesItsDefaultSource()
    {
        FakeProbes probes = new FakeProbes().WithFile($@"{SdkFolder}\11.0.100\dotnet.dll", "binary");

        Assert.AreEqual("NuGet gets packages from one source, over HTTPS.", Sources.Run(probes).Summary);
        Assert.AreEqual(CheckStatus.Fail, Cooldown.Run(probes).Status);
    }

    // Sources

    [TestMethod]
    public void Sources_OneOverHttps_Passes()
    {
        CheckOutcome outcome = Sources.Run(NuGet(Config(NuGetOrg)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Package source mapping: Not needed with one source (expected Each package tied to a source) [ok]", outcome.Rows()[1]);
    }

    [TestMethod]
    public void Sources_PlainHttp_OrTlsChecksOff_Fails_AndIsNamed()
    {
        CheckOutcome http = Sources.Run(NuGet(Config("""<add key="old feed" value="http://packages.example.test/nuget" allowInsecureConnections="true" />""")));
        Assert.AreEqual("NuGet: source \"old feed\": plain HTTP.", http.Summary);
        Assert.AreEqual($"{UserConfig}, line 4", http.Findings[0].Source);

        CheckOutcome tls = Sources.Run(NuGet(Config("""<add key="feed" value="https://packages.example.test/v3/index.json" disableTLSCertificateValidation="true" />""")));
        Assert.AreEqual("NuGet: TLS certificate checks for source \"feed\": off.", tls.Summary);
    }

    [TestMethod]
    public void Sources_SeveralWithoutMapping_Fail_AndWithMappingPass()
    {
        CheckOutcome unmapped = Sources.Run(NuGet(Config(NuGetOrg + Private)));
        Assert.AreEqual(CheckStatus.Fail, unmapped.Status);
        Assert.AreEqual("NuGet: package source mapping: not set, with 2 sources: any of them can supply any package.", unmapped.Summary);

        const string Mapping = """
              <packageSourceMapping>
                <packageSource key="nuget.org"><package pattern="*" /></packageSource>
                <packageSource key="company feed"><package pattern="Company.*" /></packageSource>
              </packageSourceMapping>

            """;
        CheckOutcome mapped = Sources.Run(NuGet(Config(NuGetOrg + Private, Mapping)));
        Assert.AreEqual(CheckStatus.Pass, mapped.Status);
        Assert.AreEqual("NuGet gets packages from 2 sources over HTTPS, each package tied to one.", mapped.Summary);
    }

    [TestMethod]
    public void Sources_AFolderOnThisPc_OrADisabledSource_DoesNotCount()
    {
        const string Folder = """<add key="Offline Packages" value="C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\" />""";
        Assert.AreEqual(CheckStatus.Pass, Sources.Run(NuGet(Config(NuGetOrg + Folder))).Status);

        const string Disabled = """
              <disabledPackageSources>
                <add key="company feed" value="true" />
              </disabledPackageSources>

            """;
        Assert.AreEqual(CheckStatus.Pass, Sources.Run(NuGet(Config(NuGetOrg + Private, Disabled))).Status);
    }

    [TestMethod]
    public void Sources_ThePcsFilesCount_AndClearInTheUsersFileRemovesThem()
    {
        string machine = Config(Private);

        FakeProbes added = NuGet(Config(NuGetOrg)).WithFile($@"{MachineFolder}\Company.config", machine);
        Assert.AreEqual(CheckStatus.Fail, Sources.Run(added).Status, "two sources now, without mapping");

        FakeProbes cleared = NuGet(Config("<clear />" + NuGetOrg)).WithFile($@"{MachineFolder}\Company.config", machine);
        Assert.AreEqual(CheckStatus.Pass, Sources.Run(cleared).Status);
    }

    [TestMethod]
    public void AFileThatIsNotValidXml_IsCouldNotCheck_ButADefiniteProblemStillFails()
    {
        FakeProbes broken = NuGet("<configuration><packageSources>");
        foreach (ICheck check in new ICheck[] { Sources, Passwords, Cooldown })
        {
            Assert.AreEqual(CheckStatus.Error, check.Run(broken).Status, check.Definition.Id);
        }

        FakeProbes both = NuGet("<configuration><packageSources>")
            .WithFile($@"{MachineFolder}\Old.config", Config("""<add key="old" value="http://packages.example.test/nuget" />"""));
        Assert.AreEqual(CheckStatus.Fail, Sources.Run(both).Status);
    }

    [TestMethod]
    public void AFileThatReachesOutsideItself_IsRefused_NotFollowed()
    {
        const string WithEntity = "<?xml version=\"1.0\"?>\n<!DOCTYPE configuration [<!ENTITY x SYSTEM \"file:///C:/Windows/win.ini\">]>\n<configuration>&x;</configuration>";

        Assert.AreEqual(CheckStatus.Error, Sources.Run(NuGet(WithEntity)).Status);
    }

    [TestMethod]
    public void WithOnlyThePcsFiles_NuGetStillAddsItsDefaultSource()
    {
        const string Offline = """<add key="Offline Packages" value="C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\" />""";
        FakeProbes probes = new FakeProbes().WithFile($@"{MachineFolder}\Offline.config", Config(Offline));

        Assert.AreEqual("NuGet gets packages from one source, over HTTPS.", Sources.Run(probes).Summary);
        Assert.AreEqual(CheckStatus.Fail, Cooldown.Run(probes).Status);
    }

    [TestMethod]
    public void AnAttributeInAnotherLetterCase_IsNotTakenForTheRealOne()
    {
        // NuGet reads "value"; a decoy "Value" before it must not be what the check sees.
        const string Decoy = """<add key="feed" Value="https://ok.example.test/v3/index.json" value="http://packages.example.test/nuget" />""";

        Assert.AreEqual(CheckStatus.Fail, Sources.Run(NuGet(Config(Decoy))).Status);
    }

    // Passwords

    [TestMethod]
    public void Passwords_AnEncryptedPassword_OrNone_Passes()
    {
        const string Encrypted = """
              <packageSourceCredentials>
                <company_x0020_feed>
                  <add key="Username" value="someone" />
                  <add key="Password" value="AQAAANCMnd8BFdERjHoAwE" />
                </company_x0020_feed>
              </packageSourceCredentials>

            """;

        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(NuGet(Config(NuGetOrg + Private, Encrypted))).Status);
        Assert.AreEqual(CheckStatus.Pass, Passwords.Run(NuGet(Config(NuGetOrg))).Status);
    }

    [TestMethod]
    public void Passwords_APlainTextPassword_Fails_NamingTheSourceOnly()
    {
        const string Plain = """
              <packageSourceCredentials>
                <company_x0020_feed>
                  <add key="Username" value="someone" />
                  <add key="ClearTextPassword" value="made-up-password" />
                </company_x0020_feed>
              </packageSourceCredentials>

            """;

        CheckOutcome outcome = Passwords.Run(NuGet(Config(NuGetOrg + Private, Plain)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("NuGet keeps a source's password as plain text.", outcome.Summary);
        Assert.AreEqual("Password for source \"company feed\"", outcome.Findings[0].Item);
        Assert.AreEqual($"{UserConfig}, line 9", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
        Assert.IsFalse(Everything(outcome).Contains("someone", StringComparison.Ordinal));
    }

    // Release wait

    [TestMethod]
    public void Cooldown_AWeekOnEverySource_Passes_AndSaysWhatItCovers()
    {
        CheckOutcome outcome = Cooldown.Run(NuGet(Config("""<add key="nuget.org" value="https://api.nuget.org/v3/index.json" minPublishAgeHours="168" />""")));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("NuGet waits a week before it picks a new package version by itself.", outcome.Summary);
        Assert.AreEqual("Wait for source \"nuget.org\": 168 hours (expected 168 hours or more) [ok]", outcome.Rows()[0]);
        Assert.AreEqual(".NET SDK version: 11.0.100 (expected 11.0.100 or later) [ok]", outcome.Rows()[1]);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[^1].Status);
    }

    [TestMethod]
    [DataRow("", "Not set")]
    [DataRow(" minPublishAgeHours=\"24\"", "24 hours")]
    [DataRow(" minPublishAgeHours=\"1\"", "1 hour")]
    [DataRow(" minPublishAgeHours=\"a week\"", "Not set")]
    public void Cooldown_NotSetOrTooShort_Fails(string attribute, string found)
    {
        CheckOutcome outcome = Cooldown.Run(NuGet(Config($"<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\"{attribute} />")));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("NuGet picks new package versions the moment they are published.", outcome.Summary);
        Assert.AreEqual(found, outcome.Findings[0].Found);
    }

    [TestMethod]
    public void Cooldown_EverySourceOnTheNetworkMustWait()
    {
        string config = Config("""<add key="nuget.org" value="https://api.nuget.org/v3/index.json" minPublishAgeHours="168" />""" + Private);

        Assert.AreEqual(CheckStatus.Fail, Cooldown.Run(NuGet(config)).Status);
    }

    [TestMethod]
    public void Cooldown_AnOlderSdk_Fails_AndWithoutAnSdkTheResultSaysWhatItRestsOn()
    {
        string config = Config("""<add key="nuget.org" value="https://api.nuget.org/v3/index.json" minPublishAgeHours="168" />""");

        CheckOutcome old = Cooldown.Run(NuGet(config, sdk: "10.0.203"));
        Assert.AreEqual(CheckStatus.Fail, old.Status);
        Assert.AreEqual(".NET SDK 10.0.203 cannot wait before picking new package versions; update the SDK.", old.Summary);

        CheckOutcome unknown = Cooldown.Run(NuGet(config, sdk: null));
        Assert.AreEqual(CheckStatus.Pass, unknown.Status);
        Assert.IsTrue(unknown.Rows().Any(r => r.StartsWith(".NET SDK version: Not found", StringComparison.Ordinal)));

        FakeProbes newest = NuGet(config, sdk: "10.0.203").WithFile($@"{SdkFolder}\11.0.100\dotnet.dll", "binary");
        Assert.AreEqual(CheckStatus.Pass, Cooldown.Run(newest).Status, "the newest SDK is the one that counts");
    }
}
