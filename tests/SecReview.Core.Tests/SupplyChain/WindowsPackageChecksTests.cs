using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.WindowsPackages;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class WindowsPackageChecksTests
{
    private static readonly string Winget = FakeProbes.FolderPath(KnownFolder.LocalAppData) + @"\Microsoft\WindowsApps\winget.exe";
    private const string ChocoConfig = @"C:\ProgramData\chocolatey\config\chocolatey.config";

    private static readonly WingetPoliciesCheck WingetPolicies = new();
    private static readonly ChocolateySettingsCheck Chocolatey = new();

    private static FakeProbes WithWinget() => new FakeProbes().WithFile(Winget, "alias");

    private static string Choco(string features, string sources = """<source id="chocolatey" value="https://community.chocolatey.org/api/v2/" disabled="false" />""") =>
        $"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<chocolatey>\n  <sources>\n    {sources}\n  </sources>\n  <features>\n    {features}\n  </features>\n</chocolatey>\n";

    private const string Defaults =
        """<feature name="checksumFiles" enabled="true" setExplicitly="false" /><feature name="allowEmptyChecksums" enabled="false" setExplicitly="false" />""";

    [TestMethod]
    public void WithoutTheTool_NeitherCheckApplies()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, WingetPolicies.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Chocolatey.Run(new FakeProbes()).Status);
    }

    // winget

    [TestMethod]
    public void Winget_WithoutPolicies_Passes_AndSaysWhatItCannotSee()
    {
        CheckOutcome outcome = WingetPolicies.Run(WithWinget());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[^1].Status);
        StringAssert.Contains(outcome.Findings[^1].Found, "Not readable without running winget");
    }

    [TestMethod]
    [DataRow("EnableHashOverride", "A policy weakens winget: installer hash check: may be skipped.")]
    [DataRow("EnableLocalManifestFiles", "A policy weakens winget: installing from a manifest file: allowed: any file can say what to download.")]
    [DataRow("EnableBypassCertificatePinningForMicrosoftStore", "A policy weakens winget: Microsoft Store certificate check: may be skipped.")]
    [DataRow("EnableLocalArchiveMalwareScanOverride", "A policy weakens winget: malware scan of archives: may be skipped.")]
    public void Winget_APolicyThatAllowsSkippingACheck_Fails_AndIsMarkedAsManaged(string policy, string summary)
    {
        CheckOutcome outcome = WingetPolicies.Run(WithWinget().WithRegistryNumber(RegistryRoot.LocalMachine, WingetPoliciesCheck.PolicyKey, policy, 1));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.IsTrue(outcome.ManagedByPolicy);
        StringAssert.EndsWith(outcome.Findings[0].Source, policy);
    }

    [TestMethod]
    public void Winget_APolicySetToOff_Passes_AndSeveralAreCounted()
    {
        FakeProbes off = WithWinget().WithRegistryNumber(RegistryRoot.LocalMachine, WingetPoliciesCheck.PolicyKey, "EnableHashOverride", 0);
        Assert.AreEqual(CheckStatus.Pass, WingetPolicies.Run(off).Status);

        FakeProbes two = new FakeProbes()
            .WithRegistryNumber(RegistryRoot.LocalMachine, WingetPoliciesCheck.PolicyKey, "EnableHashOverride", 1)
            .WithRegistryNumber(RegistryRoot.LocalMachine, WingetPoliciesCheck.PolicyKey, "EnableLocalManifestFiles", 1);
        Assert.AreEqual("2 policies weaken what winget verifies before it installs.", WingetPolicies.Run(two).Summary);
    }

    // Chocolatey

    [TestMethod]
    public void Chocolatey_Defaults_Pass()
    {
        CheckOutcome outcome = Chocolatey.Run(new FakeProbes().WithFile(ChocoConfig, Choco(Defaults)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Chocolatey verifies checksums and uses HTTPS sources.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("""<feature name="checksumFiles" enabled="false" />""", "Chocolatey: checksum verification: off.")]
    [DataRow("""<feature name="allowEmptyChecksums" enabled="true" />""", "Chocolatey: packages without a checksum: allowed, over plain HTTP too.")]
    public void Chocolatey_AWeakFeature_Fails(string feature, string summary)
    {
        CheckOutcome outcome = Chocolatey.Run(new FakeProbes().WithFile(ChocoConfig, Choco(feature)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual($"{ChocoConfig}, line 7", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void Chocolatey_ASourceOverPlainHttp_Fails_UnlessDisabled()
    {
        const string Http = """<source id="internal" value="http://packages.example.test/nuget" disabled="false" />""";
        CheckOutcome outcome = Chocolatey.Run(new FakeProbes().WithFile(ChocoConfig, Choco(Defaults, Http)));
        Assert.AreEqual("Chocolatey: source \"internal\": plain HTTP.", outcome.Summary);

        const string Disabled = """<source id="internal" value="http://packages.example.test/nuget" disabled="true" />""";
        Assert.AreEqual(CheckStatus.Pass, Chocolatey.Run(new FakeProbes().WithFile(ChocoConfig, Choco(Defaults, Disabled))).Status);
    }

    [TestMethod]
    public void Chocolatey_ItsOwnWeakDefault_IsNoted_NotFailed()
    {
        CheckOutcome outcome = Chocolatey.Run(
            new FakeProbes().WithFile(ChocoConfig, Choco(Defaults + """<feature name="allowEmptyChecksumsSecure" enabled="true" />""")));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(1, outcome.Findings.Count(f => f.Status == FindingStatus.Note));
    }

    [TestMethod]
    public void Chocolatey_TheFolderCanBeMoved_AndABrokenFileIsCouldNotCheck()
    {
        FakeProbes moved = new FakeProbes()
            .WithRegistryValue(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, "ChocolateyInstall", RegistryValue.FromText(@"D:\choco"))
            .WithFile(@"D:\choco\config\chocolatey.config", Choco("""<feature name="checksumFiles" enabled="false" />"""));
        Assert.AreEqual(CheckStatus.Fail, Chocolatey.Run(moved).Status);

        Assert.AreEqual(CheckStatus.Error, Chocolatey.Run(new FakeProbes().WithFile(ChocoConfig, "<chocolatey><features>")).Status);
    }
}
