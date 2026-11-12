using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Rules;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Rules;

[TestClass]
public sealed class RuleCheckTests
{
    private const string PolicyKey = @"SOFTWARE\Policies\Example\Feature";
    private const string LocalKey = @"SYSTEM\CurrentControlSet\Control\Example";
    private const string Value = "Protection";

    private static readonly CheckText Text = new(
        "Example protection", "Example protection is on", "Example protection is off", "It matters.", ["Turn it on."], "1 min", null, []);

    private static RuleDefinition Rule(
        RegistryRule? registry = null,
        ServiceRule? service = null,
        AccountPolicyRule? accountPolicy = null,
        AuditPolicyRule? auditPolicy = null,
        UserRightRule? userRight = null,
        DefenderRule? defender = null,
        DefenderRulesRule? defenderRules = null) => new(
            "harden.example",
            CheckCategory.Hardening,
            Severity.Medium,
            Text,
            "https://learn.microsoft.com/example",
            new DateOnly(2026, 11, 12),
            registry,
            service,
            accountPolicy,
            auditPolicy,
            userRight,
            defender,
            defenderRules);

    private static CheckOutcome Run(RuleDefinition rule, FakeProbes probes, bool elevated = false) =>
        new RuleCheck(rule).Run(probes, elevated);

    // Registry rules

    private static RuleDefinition Registry(bool absentPasses = false, RegistryRoot root = RegistryRoot.LocalMachine) => Rule(registry: new RegistryRule(
        "Example protection",
        root,
        [new RegistryLocation(PolicyKey, Value, Policy: true), new RegistryLocation(LocalKey, Value)],
        new Expectation(AnyOf: [1, 2]),
        "On",
        new AbsentValue(absentPasses ? "Not configured (Windows default: on)" : "Not configured (Windows default: off)", absentPasses),
        new Dictionary<string, string> { ["0"] = "Off", ["1"] = "On", ["2"] = "On, locked" }));

    [TestMethod]
    [DataRow(1L, CheckStatus.Pass, "Example protection: On.")]
    [DataRow(2L, CheckStatus.Pass, "Example protection: On, locked.")]
    [DataRow(0L, CheckStatus.Fail, "Example protection: Off. Expected: On.")]
    [DataRow(7L, CheckStatus.Fail, "Example protection: 7. Expected: On.")]
    public void Registry_ComparesTheValue_AndSaysItInWords(long value, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = Run(Registry(), new FakeProbes().WithRegistryNumber(RegistryRoot.LocalMachine, LocalKey, Value, value));

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual($@"HKLM\{LocalKey}\{Value}", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.ManagedByPolicy);
    }

    [TestMethod]
    public void Registry_ThePolicyLocationWins_AndIsMarkedAsManaged()
    {
        FakeProbes probes = new FakeProbes()
            .WithRegistryNumber(RegistryRoot.LocalMachine, PolicyKey, Value, 0)
            .WithRegistryNumber(RegistryRoot.LocalMachine, LocalKey, Value, 1);

        CheckOutcome outcome = Run(Registry(), probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.IsTrue(outcome.ManagedByPolicy);
        Assert.AreEqual($@"HKLM\{PolicyKey}\{Value}", outcome.Findings[0].Source);
    }

    [TestMethod]
    [DataRow(true, CheckStatus.Pass, "Example protection: Not configured (Windows default: on).")]
    [DataRow(false, CheckStatus.Fail, "Example protection: Not configured (Windows default: off). Expected: On.")]
    public void Registry_NotSetAnywhere_IsJudgedByWhatWindowsDoesThen(bool absentPasses, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = Run(Registry(absentPasses), new FakeProbes());

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Registry_Unreadable_OrOfAnUnexpectedKind_IsNeverAPass()
    {
        var denied = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied() };
        Assert.AreEqual(CheckStatus.NeedsAdmin, Run(Registry(absentPasses: true), denied).Status);

        FakeProbes text = new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, LocalKey, Value, RegistryValue.FromText("on"));
        Assert.AreEqual(CheckStatus.Error, Run(Registry(absentPasses: true), text).Status);
    }

    [TestMethod]
    public void Registry_NumbersWithoutALabel_GetTheirUnit()
    {
        RuleDefinition rule = Rule(registry: new RegistryRule(
            "Log size",
            RegistryRoot.LocalMachine,
            [new RegistryLocation(LocalKey, Value)],
            new Expectation(AtLeast: 196608),
            "196608 KB or more",
            new AbsentValue("Not configured (Windows default: 20480 KB)", false),
            Unit: "KB"));

        CheckOutcome outcome = Run(rule, new FakeProbes().WithRegistryNumber(RegistryRoot.LocalMachine, LocalKey, Value, 1024));

        Assert.AreEqual("Log size: 1024 KB. Expected: 196608 KB or more.", outcome.Summary);
    }

    [TestMethod]
    public void ARuleAboutTheUsersOwnSettings_NeverRunsElevated_AndOthersNeedNoAdministrator()
    {
        Assert.AreEqual(CheckScope.User, new RuleCheck(Registry(root: RegistryRoot.CurrentUser)).Definition.Scope);
        Assert.AreEqual(CheckScope.Machine, new RuleCheck(Registry()).Definition.Scope);
        Assert.AreEqual(AdminNeed.No, new RuleCheck(Registry()).Definition.NeedsAdmin);
    }

    // Expectations

    [TestMethod]
    public void Expectation_AllPartsThatAreSetMustHold()
    {
        Assert.IsTrue(new Expectation(Is: 1).Matches(1));
        Assert.IsFalse(new Expectation(Is: 1).Matches(2));
        Assert.IsTrue(new Expectation(AtLeast: 1, AtMost: 900).Matches(900));
        Assert.IsFalse(new Expectation(AtLeast: 1, AtMost: 900).Matches(0));
        Assert.IsFalse(new Expectation(AtLeast: 1, AtMost: 900).Matches(901));
        Assert.IsTrue(new Expectation(Not: 1).Matches(0));
        Assert.IsFalse(new Expectation(Not: 1).Matches(1));
        Assert.IsTrue(new Expectation(AnyOf: [2, 5]).Matches(5));
        Assert.IsFalse(new Expectation(AnyOf: [2, 5]).Matches(3));
    }

    [TestMethod]
    public void Expectation_ThatSaysNothing_MatchesNothing()
    {
        Assert.IsTrue(new Expectation().IsEmpty);
        Assert.IsFalse(new Expectation().Matches(0));
    }

    // Service rules

    private static RuleDefinition Service(ServiceRequirement require) =>
        Rule(service: new ServiceRule("Remote Registry", "RemoteRegistry", require));

    [TestMethod]
    public void Service_NotInstalled_Passes()
    {
        Assert.AreEqual("Remote Registry is not installed.", Run(Service(ServiceRequirement.Disabled), new FakeProbes()).Summary);
    }

    [TestMethod]
    [DataRow(ServiceStartType.Disabled, false, CheckStatus.Pass, "Remote Registry: Disabled.")]
    [DataRow(ServiceStartType.Manual, false, CheckStatus.Fail, "Remote Registry: Starts on demand, not running. Expected: Disabled.")]
    [DataRow(ServiceStartType.Automatic, true, CheckStatus.Fail, "Remote Registry: Starts automatically, running. Expected: Disabled.")]
    public void Service_MustBeDisabled(ServiceStartType startType, bool running, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = Run(
            Service(ServiceRequirement.Disabled), new FakeProbes().WithService("RemoteRegistry", startType, running));

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Service_NotRunning_IsEnoughWhenThatIsAllTheRuleAsks()
    {
        FakeProbes stopped = new FakeProbes().WithService("RemoteRegistry", ServiceStartType.Manual, isRunning: false);
        FakeProbes running = new FakeProbes().WithService("RemoteRegistry", ServiceStartType.Manual, isRunning: true);

        Assert.AreEqual(CheckStatus.Pass, Run(Service(ServiceRequirement.NotRunning), stopped).Status);
        Assert.AreEqual(CheckStatus.Fail, Run(Service(ServiceRequirement.NotRunning), running).Status);
    }

    [TestMethod]
    public void Service_Unreadable_IsCouldNotCheck()
    {
        var probes = new FakeProbes { ServicesFailure = ProbeFailure.Failed("Asking the service manager failed.") };

        Assert.AreEqual(CheckStatus.Error, Run(Service(ServiceRequirement.Disabled), probes).Status);
    }

    // Account policy rules

    private static FakeProbes Policy(
        int minimumLength = 14, int history = 24, int? maximumAgeDays = 60, int lockoutThreshold = 5, int? lockoutMinutes = 15) => new()
        {
            AccountPolicy = ProbeResult<AccountPolicy>.Ok(new AccountPolicy(
                minimumLength,
                maximumAgeDays is { } days ? TimeSpan.FromDays(days) : null,
                TimeSpan.Zero,
                history,
                lockoutThreshold,
                lockoutMinutes is { } minutes ? TimeSpan.FromMinutes(minutes) : null,
                TimeSpan.FromMinutes(15))),
        };

    private static RuleDefinition Account(AccountPolicyField field, Expectation expect, string expected, string? unit = null) =>
        Rule(accountPolicy: new AccountPolicyRule("Setting", field, expect, expected, unit));

    [TestMethod]
    public void AccountPolicy_MinimumLength()
    {
        RuleDefinition rule = Account(AccountPolicyField.MinimumPasswordLength, new Expectation(AtLeast: 14), "14 or more", "characters");

        Assert.AreEqual("Setting: 14 characters.", Run(rule, Policy(minimumLength: 14)).Summary);
        Assert.AreEqual("Setting: 8 characters. Expected: 14 or more.", Run(rule, Policy(minimumLength: 8)).Summary);
        Assert.AreEqual("Setting: No minimum. Expected: 14 or more.", Run(rule, Policy(minimumLength: 0)).Summary);
    }

    [TestMethod]
    public void AccountPolicy_MaximumAge_NeverExpiringIsZero()
    {
        RuleDefinition rule = Account(AccountPolicyField.MaximumPasswordAgeDays, new Expectation(AtLeast: 1, AtMost: 365), "365 days or fewer");

        Assert.AreEqual(CheckStatus.Pass, Run(rule, Policy(maximumAgeDays: 60)).Status);
        Assert.AreEqual(CheckStatus.Fail, Run(rule, Policy(maximumAgeDays: 400)).Status);
        Assert.AreEqual("Setting: Passwords never expire. Expected: 365 days or fewer.", Run(rule, Policy(maximumAgeDays: null)).Summary);
    }

    [TestMethod]
    public void AccountPolicy_Lockout()
    {
        RuleDefinition threshold = Account(AccountPolicyField.LockoutThreshold, new Expectation(AtLeast: 1, AtMost: 10), "10 or fewer");
        Assert.AreEqual(CheckStatus.Pass, Run(threshold, Policy(lockoutThreshold: 10)).Status);
        Assert.AreEqual("Setting: Accounts never lock. Expected: 10 or fewer.", Run(threshold, Policy(lockoutThreshold: 0)).Summary);

        RuleDefinition duration = Account(AccountPolicyField.LockoutDurationMinutes, new Expectation(AtLeast: 15), "15 minutes or more", "minutes");
        Assert.AreEqual(CheckStatus.Pass, Run(duration, Policy(lockoutMinutes: 15)).Status);
        Assert.AreEqual(CheckStatus.Fail, Run(duration, Policy(lockoutMinutes: 5)).Status);
        Assert.AreEqual("Setting: Until an administrator unlocks it.", Run(duration, Policy(lockoutMinutes: null)).Summary);
        Assert.AreEqual(CheckStatus.NotApplicable, Run(duration, Policy(lockoutThreshold: 0)).Status);
    }

    [TestMethod]
    public void AccountPolicy_Unreadable_IsCouldNotCheck()
    {
        RuleDefinition rule = Account(AccountPolicyField.PasswordHistoryLength, new Expectation(AtLeast: 24), "24 or more");

        Assert.AreEqual(CheckStatus.Error, Run(rule, new FakeProbes()).Status);
    }

    // Audit policy and user rights (administrator readings)

    private static readonly Guid Subcategory = new("0cce9215-69ae-11d9-bed3-505054503030");

    private static RuleDefinition Audit(bool success, bool failure) =>
        Rule(auditPolicy: new AuditPolicyRule("Logon", Subcategory, success, failure));

    [TestMethod]
    public void AuditAndUserRightRules_NeedAdministratorRights()
    {
        Assert.AreEqual(AdminNeed.Yes, new RuleCheck(Audit(true, true)).Definition.NeedsAdmin);
        Assert.AreEqual(
            AdminNeed.Yes,
            new RuleCheck(Rule(userRight: new UserRightRule("Debug programs", "SeDebugPrivilege", ["S-1-5-32-544"]))).Definition.NeedsAdmin);
    }

    [TestMethod]
    [DataRow(AuditSetting.Success | AuditSetting.Failure, true, true, CheckStatus.Pass)]
    [DataRow(AuditSetting.Success, true, true, CheckStatus.Fail)]
    [DataRow(AuditSetting.Success, true, false, CheckStatus.Pass)]
    [DataRow(AuditSetting.Success | AuditSetting.Failure, false, true, CheckStatus.Pass)]
    [DataRow(AuditSetting.None, false, true, CheckStatus.Fail)]
    public void Audit_MustRecordWhatTheRuleAsks(AuditSetting setting, bool success, bool failure, CheckStatus expected)
    {
        var probes = new FakeProbes { AuditPolicy = ProbeResult<AuditSetting>.Ok(setting) };

        Assert.AreEqual(expected, Run(Audit(success, failure), probes, elevated: true).Status);
    }

    [TestMethod]
    public void Audit_SaysWhatIsRecorded()
    {
        var probes = new FakeProbes { AuditPolicy = ProbeResult<AuditSetting>.Ok(AuditSetting.Success) };

        CheckOutcome outcome = Run(Audit(true, true), probes, elevated: true);

        Assert.AreEqual("Audit: Logon records success. Expected: success and failure.", outcome.Summary);
        Assert.AreEqual("Audit: Logon: Success (expected Success and failure) [problem]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void Audit_WithoutAdministratorRights_SaysSo()
    {
        var probes = new FakeProbes { AuditPolicy = ProbeFailure.AccessDenied() };

        Assert.AreEqual(CheckStatus.NeedsAdmin, Run(Audit(true, true), probes).Status);
    }

    private static readonly RuleDefinition DebugRight =
        Rule(userRight: new UserRightRule("Debug programs", "SeDebugPrivilege", ["S-1-5-32-544"]));

    [TestMethod]
    public void UserRight_HeldOnlyByAllowedGroups_Passes()
    {
        FakeProbes probes = new FakeProbes().WithUserRight("SeDebugPrivilege", new AccountReference("S-1-5-32-544", @"BUILTIN\Administrators"));

        CheckOutcome outcome = Run(DebugRight, probes, elevated: true);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(@"BUILTIN\Administrators: Has the right (expected Allowed) [ok]", outcome.Rows()[0]);
    }

    [TestMethod]
    public void UserRight_HeldByNobody_Passes()
    {
        Assert.AreEqual(CheckStatus.Pass, Run(DebugRight, new FakeProbes().WithUserRight("SeDebugPrivilege"), elevated: true).Status);
    }

    [TestMethod]
    public void UserRight_HeldByOthers_Fails_WithoutNamingPersonalAccounts()
    {
        FakeProbes probes = new FakeProbes().WithUserRight(
            "SeDebugPrivilege",
            new AccountReference("S-1-5-32-544", @"BUILTIN\Administrators"),
            new AccountReference("S-1-5-32-545", @"BUILTIN\Users"),
            new AccountReference("S-1-5-21-1-2-3-1001", null));

        CheckOutcome outcome = Run(DebugRight, probes, elevated: true);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("\"Debug programs\" is held by 2 accounts or groups that should not have it.", outcome.Summary);
        Assert.AreEqual("Another account: Has the right (expected Does not have it) [problem]", outcome.Rows()[2]);
    }

    [TestMethod]
    public void UserRight_WithoutAdministratorRights_SaysSo()
    {
        FakeProbes probes = new FakeProbes().WithUserRightFailure("SeDebugPrivilege", ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.NeedsAdmin, Run(DebugRight, probes).Status);
    }

    // Microsoft Defender rules

    private static FakeProbes DefenderWith(params (string Name, object? Value)[] settings) => new FakeProbes()
        .WithWmiObjects(
            DefenderCheck.WmiNamespace,
            DefenderCheck.StatusClass,
            FakeProbes.Wmi(("AMRunningMode", "Normal"), ("AntivirusEnabled", true)))
        .WithWmiObjects(DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, FakeProbes.Wmi(settings));

    private static readonly RuleDefinition Pua = Rule(defender: new DefenderRule(
        "Blocking of unwanted apps",
        "PUAProtection",
        new Expectation(Is: 1),
        "Block",
        new Dictionary<string, string> { ["0"] = "Off", ["1"] = "Block", ["2"] = "Audit only" }));

    [TestMethod]
    [DataRow(1L, CheckStatus.Pass, "Blocking of unwanted apps: Block.")]
    [DataRow(0L, CheckStatus.Fail, "Blocking of unwanted apps: Off. Expected: Block.")]
    [DataRow(2L, CheckStatus.Fail, "Blocking of unwanted apps: Audit only. Expected: Block.")]
    public void Defender_ANumberSetting(long value, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = Run(Pua, DefenderWith(("PUAProtection", value)));

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Defender_AYesNoSetting_IsReadAsOneOrZero()
    {
        RuleDefinition rule = Rule(defender: new DefenderRule(
            "Behaviour monitoring",
            "DisableBehaviorMonitoring",
            new Expectation(Is: 0),
            "On",
            new Dictionary<string, string> { ["0"] = "On", ["1"] = "Off" }));

        Assert.AreEqual(CheckStatus.Pass, Run(rule, DefenderWith(("DisableBehaviorMonitoring", false))).Status);
        Assert.AreEqual("Behaviour monitoring: Off. Expected: On.", Run(rule, DefenderWith(("DisableBehaviorMonitoring", true))).Summary);
    }

    [TestMethod]
    public void Defender_NotTheAntivirusInUse_DoesNotApply()
    {
        FakeProbes probes = new FakeProbes().WithWmiObjects(
            DefenderCheck.WmiNamespace,
            DefenderCheck.StatusClass,
            FakeProbes.Wmi(("AMRunningMode", "Passive"), ("AntivirusEnabled", true)));

        Assert.AreEqual(CheckStatus.NotApplicable, Run(Pua, probes).Status);
    }

    [TestMethod]
    public void Defender_SettingNotReported_OrUnreadable_IsNeverAPass()
    {
        Assert.AreEqual(CheckStatus.Error, Run(Pua, DefenderWith(("SomethingElse", 1L))).Status);
        Assert.AreEqual(CheckStatus.Error, Run(Pua, new FakeProbes()).Status);

        FakeProbes denied = DefenderWith().WithWmiFailure(
            DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.NeedsAdmin, Run(Pua, denied).Status);
    }

    private static readonly Guid RuleA = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid RuleB = new("22222222-2222-2222-2222-222222222222");

    private static readonly RuleDefinition Asr = Rule(defenderRules: new DefenderRulesRule(
        [new AttackSurfaceRule(RuleA, "Block example A"), new AttackSurfaceRule(RuleB, "Block example B")]));

    private static FakeProbes AsrSettings(string[] ids, long[] actions) => DefenderWith(
        ("AttackSurfaceReductionRules_Ids", (IReadOnlyList<string>)ids),
        ("AttackSurfaceReductionRules_Actions", (IReadOnlyList<long>)actions));

    [TestMethod]
    public void DefenderRules_AllBlocking_Pass()
    {
        CheckOutcome outcome = Run(Asr, AsrSettings([RuleA.ToString(), RuleB.ToString().ToUpperInvariant()], [1, 1]));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("All 2 attack surface reduction rules block.", outcome.Summary);
    }

    [TestMethod]
    public void DefenderRules_EachRuleGetsItsOwnRow()
    {
        CheckOutcome outcome = Run(Asr, AsrSettings([RuleA.ToString()], [2]));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("2 of 2 attack surface reduction rules do not block.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "Block example A: Audit only (expected Block) [problem]",
                "Block example B: Not configured (expected Block) [problem]",
            },
            outcome.Rows());
    }

    [TestMethod]
    public void DefenderRules_NoneConfigured_Fails_AndInconsistentListsAreCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Fail, Run(Asr, AsrSettings([], [])).Status);
        Assert.AreEqual(CheckStatus.Error, Run(Asr, AsrSettings([RuleA.ToString()], [])).Status);
    }

    [TestMethod]
    public void ARuleThatSaysNothingToRead_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, Run(Rule(), new FakeProbes()).Status);
    }
}
