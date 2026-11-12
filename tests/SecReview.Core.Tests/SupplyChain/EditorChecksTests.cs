using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain.Editors;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class EditorChecksTests
{
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);
    private static readonly string Local = FakeProbes.FolderPath(KnownFolder.LocalAppData);

    private static readonly string CodeSettings = Roaming + @"\Code\User\settings.json";
    private static readonly string CursorSettings = Roaming + @"\Cursor\User\settings.json";

    private static readonly EditorUpdatesCheck Updates = new();
    private static readonly EditorSettingsCheck Settings = new();

    /// <summary>A PC with VS Code: the given settings and, unless told otherwise, version 1.130.0 in the folder layout of newer builds.</summary>
    private static FakeProbes Code(string settings, string? version = "1.130.0")
    {
        FakeProbes probes = new FakeProbes().WithFile(CodeSettings, settings);
        return version is null
            ? probes
            : probes.WithFile(Local + @"\Programs\Microsoft VS Code\0123456789\resources\app\package.json", $$"""{ "name": "Code", "version": "{{version}}" }""");
    }

    private const string PolicyKey = @"SOFTWARE\Policies\Microsoft\VSCode";

    [TestMethod]
    public void WithoutAnEditor_NeitherCheckApplies_AndNeitherRunsElevated()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Updates.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Settings.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, Updates.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Settings.Definition.Scope);
    }

    // Extension updates

    [TestMethod]
    public void Updates_AWeek_Passes_AndSaysWhatTheWaitCovers()
    {
        CheckOutcome outcome = Updates.Run(Code("{\n  // my settings\n  \"editor.fontSize\": 13,\n  \"extensions.autoUpdateDelay\": 168,\n}"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("VS Code waits a week before installing extension updates, or does not update them by itself.", outcome.Summary);
        Assert.AreEqual("VS Code: wait before extension updates: 168 hours (expected 168 hours or more, or automatic updates off) [ok]", outcome.Rows()[0]);
        Assert.AreEqual(FindingStatus.Note, outcome.Findings[^1].Status);
    }

    [TestMethod]
    [DataRow("{ \"extensions.autoUpdate\": false }")]
    [DataRow("{ \"extensions.autoUpdate\": \"off\" }")]
    public void Updates_AutomaticUpdatesOff_Passes(string settings)
    {
        Assert.AreEqual(CheckStatus.Pass, Updates.Run(Code(settings)).Status);
    }

    [TestMethod]
    [DataRow("{}", "Not set (the editor's default is a few hours at most)")]
    [DataRow("{ \"extensions.autoUpdateDelay\": 12 }", "12 hours")]
    [DataRow("{ \"extensions.autoUpdate\": \"on\", \"extensions.autoUpdateDelay\": 1 }", "1 hour")]
    [DataRow("{ \"extensions.autoUpdate\": \"onlyEnabledExtensions\" }", "Not set (the editor's default is a few hours at most)")]
    public void Updates_NotSetOrTooShort_Fails(string settings, string found)
    {
        CheckOutcome outcome = Updates.Run(Code(settings));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("VS Code installs extension updates within hours of their release.", outcome.Summary);
        Assert.AreEqual(found, outcome.Findings[0].Found);
    }

    [TestMethod]
    public void Updates_WithoutASettingsFile_TheDefaultsApply_AndFail()
    {
        FakeProbes probes = new FakeProbes().WithFile(Roaming + @"\Code\User\keybindings.json", "[]");

        Assert.AreEqual(CheckStatus.Fail, Updates.Run(probes).Status);
    }

    [TestMethod]
    public void Updates_AnOlderVsCode_Fails_WhateverTheFileSays_AndAnUnknownVersionIsSaid()
    {
        CheckOutcome old = Updates.Run(Code("{ \"extensions.autoUpdateDelay\": 168 }", version: "1.120.2"));
        Assert.AreEqual(CheckStatus.Fail, old.Status);
        StringAssert.Contains(old.Findings[0].Found, "VS Code 1.120.2 cannot delay them");

        CheckOutcome unknown = Updates.Run(Code("{ \"extensions.autoUpdateDelay\": 168 }", version: null));
        Assert.AreEqual(CheckStatus.Pass, unknown.Status);
        Assert.IsTrue(unknown.Rows().Any(r => r.StartsWith("VS Code version: Not readable", StringComparison.Ordinal)));

        // The older folder layout is read too.
        FakeProbes flat = new FakeProbes()
            .WithFile(CodeSettings, "{ \"extensions.autoUpdateDelay\": 168 }")
            .WithFile(@"C:\Program Files\Microsoft VS Code\resources\app\package.json", """{ "version": "1.120.2" }""");
        Assert.AreEqual(CheckStatus.Fail, Updates.Run(flat).Status);
    }

    [TestMethod]
    public void Updates_Cursor_HasItsOwnSetting()
    {
        FakeProbes waits = new FakeProbes().WithFile(CursorSettings, "{ \"extensions.installCooldownHours\": 168 }");
        Assert.AreEqual(CheckStatus.Pass, Updates.Run(waits).Status);

        FakeProbes vsCodeKey = new FakeProbes().WithFile(CursorSettings, "{ \"extensions.autoUpdateDelay\": 168 }");
        CheckOutcome outcome = Updates.Run(vsCodeKey);
        Assert.AreEqual(CheckStatus.Fail, outcome.Status, "Cursor does not read VS Code's setting");
        Assert.AreEqual("Cursor installs extension updates within hours of their release.", outcome.Summary);
    }

    [TestMethod]
    public void Updates_EveryEditorMustWait_AndTheyAreNamed()
    {
        FakeProbes probes = Code("{ \"extensions.autoUpdateDelay\": 168 }")
            .WithFile(CursorSettings, "{}")
            .WithFile(Roaming + @"\VSCodium\User\settings.json", "{}");

        CheckOutcome outcome = Updates.Run(probes);

        Assert.AreEqual("VSCodium and Cursor install extension updates within hours of their release.", outcome.Summary);
    }

    [TestMethod]
    public void Updates_ThePolicyForVsCode_WinsOverTheFile()
    {
        FakeProbes managed = Code("{ \"extensions.autoUpdateDelay\": 1 }")
            .WithRegistryNumber(RegistryRoot.LocalMachine, PolicyKey, "ExtensionsAutoUpdateDelay", 336);
        CheckOutcome outcome = Updates.Run(managed);
        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Your organisation's policy for VS Code", outcome.Findings[0].Source);

        FakeProbes off = Code("{}").WithRegistryValue(RegistryRoot.CurrentUser, PolicyKey, "ExtensionsAutoUpdate", RegistryValue.FromText("off"));
        Assert.AreEqual(CheckStatus.Pass, Updates.Run(off).Status);
    }

    [TestMethod]
    public void Updates_AValueOrFileThatCannotBeUnderstood_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, Updates.Run(Code("{ \"extensions.autoUpdateDelay\": \"a week\" }")).Status);
        Assert.AreEqual(CheckStatus.Error, Updates.Run(Code("{ not json")).Status);
        Assert.AreEqual(CheckStatus.Error, Updates.Run(Code("[]")).Status);
    }

    // What the reviews found

    [TestMethod]
    public void Updates_TheWordOff_CountsOnlyWhereTheEditorKnowsIt_AndAPolicyMayBeANumber()
    {
        Assert.AreEqual(CheckStatus.Fail, Updates.Run(Code("{ \"extensions.autoUpdate\": \"off\" }", version: "1.120.2")).Status);
        Assert.AreEqual(CheckStatus.Pass, Updates.Run(Code("{ \"extensions.autoUpdate\": false }", version: "1.120.2")).Status);

        FakeProbes asText = Code("{}").WithRegistryValue(RegistryRoot.LocalMachine, PolicyKey, "ExtensionsAutoUpdateDelay", RegistryValue.FromText("168"));
        Assert.AreEqual(CheckStatus.Pass, Updates.Run(asText).Status);

        FakeProbes asNumber = Code("{}").WithRegistryNumber(RegistryRoot.LocalMachine, PolicyKey, "ExtensionsAutoUpdate", 0);
        CheckOutcome off = Updates.Run(asNumber);
        Assert.AreEqual(CheckStatus.Pass, off.Status);
        Assert.AreEqual("Your organisation's policy for VS Code", off.Findings[0].Source);

        // Off in the settings file is credited to the file, even when a policy sets the delay.
        FakeProbes mixed = Code("{ \"extensions.autoUpdate\": false }").WithRegistryNumber(RegistryRoot.LocalMachine, PolicyKey, "ExtensionsAutoUpdateDelay", 1);
        StringAssert.StartsWith(Updates.Run(mixed).Findings[0].Source, CodeSettings);
    }

    [TestMethod]
    public void TheEditorsDataFolder_FollowsItsVariable_AndUnlistableProfilesAreCouldNotCheck()
    {
        FakeProbes moved = new FakeProbes()
            .WithRegistryValue(RegistryRoot.CurrentUser, SecReview.SupplyChain.PersistentEnvironment.UserKey, "VSCODE_APPDATA", RegistryValue.FromText(@"D:\data"))
            .WithFile(@"D:\data\Code\User\settings.json", "{ \"extensions.verifySignature\": false }");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(moved).Status);

        FakeProbes closed = Code("{}").WithFolderFailure(Roaming + @"\Code\User\profiles", ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Error, Settings.Run(closed).Status);
    }

    [TestMethod]
    public void WithOnlyAnEditorThatHasNoWait_TheUpdatesCheckDoesNotApply_AndTwoNamesOfOneSettingAreOneRow()
    {
        FakeProbes windsurf = new FakeProbes().WithFile(Roaming + @"\Windsurf\User\settings.json", "{}");
        Assert.AreEqual(CheckStatus.NotApplicable, Updates.Run(windsurf).Status);
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(windsurf).Status);

        CheckOutcome both = Settings.Run(Code("{ \"chat.tools.global.autoApprove\": true, \"chat.tools.autoApprove\": true }"));
        Assert.AreEqual(1, both.Findings.Count);
    }

    // Protections

    [TestMethod]
    public void Settings_Defaults_Pass()
    {
        CheckOutcome outcome = Settings.Run(Code("{ \"editor.fontSize\": 13, \"task.allowAutomaticTasks\": \"off\" }"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("VS Code: signature checks and Workspace Trust are on, and the AI agent asks before it acts.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("\"extensions.verifySignature\": false", "VS Code: extension signature checks: off.")]
    [DataRow("\"security.workspace.trust.enabled\": false", "VS Code: Workspace Trust: off: every folder's code may run.")]
    [DataRow("\"chat.tools.global.autoApprove\": true", "VS Code: AI agent actions: all approved without asking.")]
    [DataRow("\"chat.tools.autoApprove\": true", "VS Code: AI agent actions: all approved without asking.")]
    public void Settings_EachProtectionSwitchedOff_Fails_AndIsNamed(string setting, string summary)
    {
        CheckOutcome outcome = Settings.Run(Code("{ " + setting + " }"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        StringAssert.StartsWith(outcome.Findings[0].Source, CodeSettings);
    }

    [TestMethod]
    public void Settings_AProfile_AndEveryEditor_Count()
    {
        FakeProbes probes = Code("{}")
            .WithFile(Roaming + @"\Code\User\profiles\1a2b3c\settings.json", "{ \"security.workspace.trust.enabled\": false }")
            .WithFile(Roaming + @"\Windsurf\User\settings.json", "{ \"extensions.verifySignature\": false }");

        CheckOutcome outcome = Settings.Run(probes);

        Assert.AreEqual("Your editors have 2 protections switched off.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "VS Code (a profile): Workspace Trust", "Windsurf: extension signature checks" }, outcome.Findings.Select(f => f.Item).ToArray());
    }

    [TestMethod]
    public void Settings_AFileThatCannotBeUnderstood_IsCouldNotCheck_ButADefiniteProblemStillFails()
    {
        Assert.AreEqual(CheckStatus.Error, Settings.Run(Code("{ not json")).Status);
        Assert.AreEqual(CheckStatus.Pass, Settings.Run(Code(string.Empty)).Status, "an empty settings file sets nothing");

        FakeProbes both = Code("{ not json").WithFile(CursorSettings, "{ \"extensions.verifySignature\": false }");
        Assert.AreEqual(CheckStatus.Fail, Settings.Run(both).Status);
    }
}
