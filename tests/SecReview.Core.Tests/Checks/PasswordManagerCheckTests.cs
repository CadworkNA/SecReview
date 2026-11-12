using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class PasswordManagerCheckTests
{
    private const string ChromiumId = "abcdefghijklmnopabcdefghijklmnop";
    private const string OtherChromiumId = "ponmlkjihgfedcbaponmlkjihgfedcba";
    private const string FirefoxId = "{11111111-2222-3333-4444-555555555555}";

    private static readonly string Local = FakeProbes.FolderPath(KnownFolder.LocalAppData);
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);

    private static readonly PasswordManagers Known = new(
        new DateOnly(2026, 11, 11),
        [
            new PasswordManager("Example Vault", ["Example Vault"], [ChromiumId], [FirefoxId]),
            new PasswordManager("Other Keys", ["OtherKeys"], [OtherChromiumId], ["otherkeys@example.test"]),
        ]);

    private static readonly PasswordManagerCheck Check = new(Known);

    private static FakeProbes Program(FakeProbes probes, string displayName, RegistryRoot root = RegistryRoot.LocalMachine, string? key = null) =>
        probes.WithRegistryValue(
            root, $@"{key ?? PasswordManagerCheck.UninstallKey}\{{{Guid.NewGuid()}}}", "DisplayName", RegistryValue.FromText(displayName));

    private static FakeProbes ChromiumExtension(FakeProbes probes, string userData, string profile, string id) =>
        probes.WithFile($@"{Local}\{userData}\{profile}\Extensions\{id}\1.0_0\manifest.json", "{}");

    private static FakeProbes FirefoxExtension(FakeProbes probes, string id) =>
        probes.WithFile($@"{Roaming}\Mozilla\Firefox\Profiles\abcd.default-release\extensions\{id}.xpi", "zip");

    [TestMethod]
    public void ReadsTheUsersOwnProfiles_SoNeverRunsElevated()
    {
        Assert.AreEqual(CheckScope.User, Check.Definition.Scope);
    }

    [TestMethod]
    public void NothingInstalled_Fails_AndSaysWhatWasLookedFor()
    {
        FakeProbes probes = Program(new FakeProbes(), "Some Other Program");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("No password manager that SecReview knows was found.", outcome.Summary);
        Assert.AreEqual("Looked for: Example Vault and Other Keys [note]", outcome.Rows()[1]);
    }

    [TestMethod]
    [DataRow("Example Vault")]
    [DataRow("example vault 8.10.3 (x64)")]
    public void ADesktopApp_IsFound_ByTheStartOfItsName(string displayName)
    {
        CheckOutcome outcome = Check.Run(Program(new FakeProbes(), displayName));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Example Vault is installed.", outcome.Summary);
        Assert.AreEqual("Example Vault: Desktop app (expected Installed) [ok]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void ADesktopApp_InstalledForThisUserOnly_OrAs32Bit_IsFound()
    {
        Assert.AreEqual(CheckStatus.Pass, Check.Run(Program(new FakeProbes(), "OtherKeys", RegistryRoot.CurrentUser)).Status);
        Assert.AreEqual(
            CheckStatus.Pass,
            Check.Run(Program(new FakeProbes(), "OtherKeys", key: PasswordManagerCheck.UninstallKey32)).Status);
    }

    [TestMethod]
    public void AProgramThatOnlyMentionsTheName_IsNotIt()
    {
        Assert.AreEqual(CheckStatus.Fail, Check.Run(Program(new FakeProbes(), "Importer for Example Vault")).Status);
    }

    [TestMethod]
    [DataRow(@"Google\Chrome\User Data", "Default", "Chrome")]
    [DataRow(@"Google\Chrome\User Data", "Profile 3", "Chrome")]
    [DataRow(@"Microsoft\Edge\User Data", "Default", "Edge")]
    [DataRow(@"BraveSoftware\Brave-Browser\User Data", "Default", "Brave")]
    [DataRow(@"Vivaldi\User Data", "Default", "Vivaldi")]
    [DataRow(@"Chromium\User Data", "Default", "Chromium")]
    public void AnExtension_InAnyProfileOfAChromiumBrowser_IsFound(string userData, string profile, string browser)
    {
        CheckOutcome outcome = Check.Run(ChromiumExtension(new FakeProbes(), userData, profile, ChromiumId));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual($"Example Vault: Extension in {browser} (expected Installed) [ok]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void AnExtension_InFirefox_IsFound()
    {
        Assert.AreEqual(
            "Example Vault: Extension in Firefox (expected Installed) [ok]",
            Check.Run(FirefoxExtension(new FakeProbes(), FirefoxId)).Rows()[0]);
        Assert.AreEqual(CheckStatus.Pass, Check.Run(FirefoxExtension(new FakeProbes(), "otherkeys@example.test")).Status);
    }

    [TestMethod]
    public void OtherExtensions_DoNotCount()
    {
        FakeProbes probes = ChromiumExtension(new FakeProbes(), @"Google\Chrome\User Data", "Default", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        FirefoxExtension(probes, "something@else.test");

        Assert.AreEqual(CheckStatus.Fail, Check.Run(probes).Status);
    }

    [TestMethod]
    public void SeveralPlaces_AndSeveralProducts_AreAllListed()
    {
        FakeProbes probes = Program(new FakeProbes(), "Example Vault");
        ChromiumExtension(probes, @"Google\Chrome\User Data", "Default", ChromiumId);
        ChromiumExtension(probes, @"Google\Chrome\User Data", "Profile 1", ChromiumId);
        ChromiumExtension(probes, @"Microsoft\Edge\User Data", "Default", OtherChromiumId);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual("Example Vault and Other Keys are installed.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "Example Vault: Desktop app and Extension in Chrome (expected Installed) [ok]",
                "Other Keys: Extension in Edge (expected Installed) [ok]",
            },
            outcome.Rows());
    }

    [TestMethod]
    public void WhenPartOfTheSearchFails_NoneFoundIsCouldNotCheck_ButAFindStillPasses()
    {
        string chrome = $@"{Local}\Google\Chrome\User Data";
        FakeProbes nothing = new FakeProbes().WithFolderFailure(chrome, ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Error, Check.Run(nothing).Status);

        FakeProbes found = FirefoxExtension(new FakeProbes(), FirefoxId).WithFolderFailure(chrome, ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Pass, Check.Run(found).Status);
    }

    [TestMethod]
    public void InstalledProgramsUnreadable_IsCouldNotCheck()
    {
        var probes = new FakeProbes { RegistryFailure = ProbeFailure.Failed("Reading the registry failed.") };

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes).Status);
    }

    [TestMethod]
    public void TheShippedList_IsWellFormed()
    {
        PasswordManagers shipped = PasswordManagers.Current;

        Assert.IsTrue(shipped.Managers.Count >= 5);
        Assert.AreEqual(shipped.Managers.Count, shipped.Managers.Select(m => m.Name).Distinct().Count());
        foreach (PasswordManager manager in shipped.Managers)
        {
            Assert.IsTrue(
                manager.Apps.Count + manager.Chromium.Count + manager.Firefox.Count > 0, $"{manager.Name}: no way to recognise it");
            Assert.IsTrue(
                manager.Chromium.All(id => id.Length == 32 && id.All(c => c is >= 'a' and <= 'p')),
                $"{manager.Name}: a Chromium extension identifier is 32 letters a to p");
            Assert.IsTrue(manager.Apps.All(a => a.Trim().Length >= 5), $"{manager.Name}: an app name that short would match too much");
            Assert.IsTrue(manager.Firefox.All(id => id.Contains('@', StringComparison.Ordinal) || id.StartsWith('{')), manager.Name);
        }

        string[] identifiers = [.. shipped.Managers.SelectMany(m => m.Chromium.Concat(m.Firefox))];
        Assert.AreEqual(identifiers.Length, identifiers.Distinct(StringComparer.OrdinalIgnoreCase).Count(), "an identifier is listed twice");
    }
}
