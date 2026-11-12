using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Cargo;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class CargoChecksTests
{
    private static readonly string Home = FakeProbes.UserProfile + @"\.cargo";
    private static readonly string Config = Home + @"\config.toml";
    private static readonly string Credentials = Home + @"\credentials.toml";

    private static readonly CargoSettingsCheck Settings = new();
    private static readonly CargoCredentialsCheck Tokens = new();

    /// <summary>A PC with Cargo and the given settings.</summary>
    private static FakeProbes Cargo(string config = "[net]\nretry = 3\n") => new FakeProbes().WithFile(Config, config);

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    [TestMethod]
    public void WithoutCargo_NeitherCheckApplies_AndNeitherRunsElevated()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Settings.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Tokens.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, Settings.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Tokens.Definition.Scope);
    }

    [TestMethod]
    public void CargoIsFound_ByItsFolder_EvenWithoutSettings()
    {
        FakeProbes probes = new FakeProbes().WithFile(Home + @"\bin\cargo.exe", "binary");

        Assert.AreEqual(CheckStatus.Pass, Settings.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(probes).Status);
    }

    // Settings

    [TestMethod]
    public void Settings_Defaults_Pass()
    {
        Assert.AreEqual("Cargo gets crates over HTTPS and checks certificates for revocation.", Settings.Run(Cargo()).Summary);
    }

    [TestMethod]
    [DataRow("[http]\ncheck-revoke = false", "Cargo: certificate revocation checks: off.")]
    [DataRow("[registries.internal]\nindex = \"sparse+http://crates.example.test/index/\"", "Cargo: registry \"internal\": plain HTTP.")]
    [DataRow("[source.mirror]\nregistry = \"http://crates.example.test/index\"", "Cargo: source \"mirror\": plain HTTP.")]
    public void Settings_EachWeakSetting_Fails_AndIsNamed(string toml, string summary)
    {
        CheckOutcome outcome = Settings.Run(Cargo(toml + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual($"{Config}, line 2", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Settings_AReplacementForCratesIo_IsListed_NotFailed()
    {
        CheckOutcome outcome = Settings.Run(Cargo("[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("crates.io: Replaced by the source \"vendored-sources\" [note]", outcome.Rows()[^1]);
    }

    [TestMethod]
    public void Settings_TheVariable_WinsOverTheFile_AndTheOlderFileNameIsRead()
    {
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(WithVariable(Cargo(), "CARGO_HTTP_CHECK_REVOKE", "false")).Status);
        Assert.AreEqual(
            CheckStatus.Pass, Settings.Run(WithVariable(Cargo("[http]\ncheck-revoke = false\n"), "CARGO_HTTP_CHECK_REVOKE", "true")).Status);

        FakeProbes older = new FakeProbes().WithFile(Home + @"\config", "[http]\ncheck-revoke = false\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(older).Status);
    }

    [TestMethod]
    public void Settings_TheFolderCanBeMoved_AndABrokenFileIsCouldNotCheck()
    {
        FakeProbes moved = WithVariable(new FakeProbes(), "CARGO_HOME", @"D:\cargo").WithFile(@"D:\cargo\config.toml", "[http]\ncheck-revoke = false\n");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(moved).Status);

        Assert.AreEqual(CheckStatus.Error, Settings.Run(Cargo("[http\n")).Status);
    }

    [TestMethod]
    public void WhenBothFileNamesExist_TheOneWithoutTheExtensionIsTheOneCargoUses()
    {
        FakeProbes probes = Cargo()
            .WithFile(Home + @"\config", "[http]\ncheck-revoke = false\n")
            .WithFile(Credentials, "# nothing here\n")
            .WithFile(Home + @"\credentials", "[registry]\ntoken = \"made-up\"\n");

        Assert.AreEqual(CheckStatus.Fail, Settings.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Fail, Tokens.Run(probes).Status);
    }

    // Tokens

    [TestMethod]
    public void Tokens_InTheCredentialsFile_Fail_NamingTheRegistryOnly()
    {
        FakeProbes probes = Cargo().WithFile(
            Credentials, "[registry]\ntoken = \"made-up-token\"\n\n[registries.internal]\ntoken = \"made-up-other\"\n\n[registries.empty]\ntoken = \"\"\n");

        CheckOutcome outcome = Tokens.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Cargo: 2 secrets are stored as plain text.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "Token for crates.io", "Token for the registry \"internal\"" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.AreEqual($"{Credentials}, line 2", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Item + f.Found + f.Source).Contains("made-up", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Tokens_NoneStored_Pass_AndABrokenFileIsCouldNotCheck()
    {
        Assert.AreEqual("Cargo: no registry tokens are stored as plain text.", Tokens.Run(Cargo()).Summary);
        Assert.AreEqual(CheckStatus.Error, Tokens.Run(Cargo().WithFile(Credentials, "[registry\n")).Status);
        Assert.AreEqual(CheckStatus.Fail, Tokens.Run(Cargo("[registry]\ntoken = \"made-up\"\n")).Status, "a token in the settings file counts too");
    }
}
