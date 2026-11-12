using System.Text.Json;
using System.Text.Json.Serialization;
using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.Rules;

/// <summary>One file of rules, as stored under <c>rules/</c>.</summary>
/// <param name="Rules">The rules, in the order they are shown.</param>
public sealed record RuleFile(IReadOnlyList<RuleDefinition> Rules);

/// <summary>
/// A check written as data: what to read, what is expected, and the wording. Exactly one of
/// the "what to read" parts is set. Every rule names the Microsoft page it was verified
/// against and the day that was done.
/// </summary>
/// <param name="Id">Stable identifier, for example "harden.lsa.protection".</param>
/// <param name="Category">The group it is shown under.</param>
/// <param name="Severity">How much a failure matters.</param>
/// <param name="Text">Titles, why it matters and how to fix it.</param>
/// <param name="Source">The documentation page the rule rests on.</param>
/// <param name="Verified">The day the rule was checked against that page.</param>
/// <param name="Registry">A registry value compared with what is expected.</param>
/// <param name="Service">A Windows service that should be disabled or not running.</param>
/// <param name="AccountPolicy">A password or lockout policy value.</param>
/// <param name="AuditPolicy">An audit policy subcategory (read with administrator rights).</param>
/// <param name="UserRight">Who holds a user right (read with administrator rights).</param>
/// <param name="Defender">A Microsoft Defender Antivirus setting.</param>
/// <param name="DefenderRules">Microsoft Defender attack surface reduction rules.</param>
/// <param name="NeedsAdmin">
/// Set when the rule reads something a normal user may not, so that the administrator scan
/// includes it. Audit policy and user right rules always need administrator rights.
/// </param>
public sealed record RuleDefinition(
    string Id,
    CheckCategory Category,
    Severity Severity,
    CheckText Text,
    string Source,
    DateOnly Verified,
    RegistryRule? Registry = null,
    ServiceRule? Service = null,
    AccountPolicyRule? AccountPolicy = null,
    AuditPolicyRule? AuditPolicy = null,
    UserRightRule? UserRight = null,
    DefenderRule? Defender = null,
    DefenderRulesRule? DefenderRules = null,
    AdminNeed? NeedsAdmin = null);

/// <summary>
/// What a number must be. All parts that are set must hold; a rule with none set is invalid.
/// </summary>
/// <param name="Is">Exactly this value.</param>
/// <param name="AnyOf">One of these values.</param>
/// <param name="AtLeast">This value or more.</param>
/// <param name="AtMost">This value or less.</param>
/// <param name="Not">Any value but this one.</param>
public sealed record Expectation(
    long? Is = null, IReadOnlyList<long>? AnyOf = null, long? AtLeast = null, long? AtMost = null, long? Not = null)
{
    [JsonIgnore]
    public bool IsEmpty => Is is null && AnyOf is null && AtLeast is null && AtMost is null && Not is null;

    public bool Matches(long value) =>
        !IsEmpty &&
        (Is is null || value == Is) &&
        (AnyOf is null || AnyOf.Contains(value)) &&
        (AtLeast is null || value >= AtLeast) &&
        (AtMost is null || value <= AtMost) &&
        (Not is null || value != Not);
}

/// <summary>One place a setting can be stored.</summary>
/// <param name="Key">The registry key.</param>
/// <param name="Value">The value name.</param>
/// <param name="Policy">
/// True when this is where an organisation's policy puts the setting. A value found here is
/// marked as managed: the user cannot change it, and the advice is to contact IT.
/// </param>
/// <param name="DivideBy">
/// Brings this location's number to the rule's unit when places differ: a size kept in bytes
/// here and in kilobytes elsewhere is divided by 1024.
/// </param>
public sealed record RegistryLocation(string Key, string Value, bool Policy = false, long DivideBy = 1);

/// <summary>What happens when the setting is stored nowhere.</summary>
/// <param name="Found">What to show, for example "Not configured (Windows default: on)".</param>
/// <param name="Passes">Whether Windows' behaviour without the setting is the expected one.</param>
public sealed record AbsentValue(string Found, bool Passes);

/// <summary>
/// Another setting a rule depends on. Where it does not hold the rule says nothing: a rule
/// about how a prompt looks does not apply while prompts are switched off altogether.
/// </summary>
/// <param name="Key">The registry key, under the same root as the rule.</param>
/// <param name="Value">The value name.</param>
/// <param name="Expect">What the number must be for the rule to apply.</param>
/// <param name="HoldsWhenAbsent">Whether the rule applies when the value is not set.</param>
/// <param name="Otherwise">What to say when the rule does not apply.</param>
public sealed record RegistryCondition(string Key, string Value, Expectation Expect, bool HoldsWhenAbsent, string Otherwise);

/// <summary>A registry number compared with what is expected.</summary>
/// <param name="Item">What the setting is, in words: "LSA protection".</param>
/// <param name="Root">Machine or user. A user rule never runs elevated.</param>
/// <param name="Locations">Where the setting can be stored; the first place that has it decides.</param>
/// <param name="Expect">What the number must be.</param>
/// <param name="Expected">The expectation in words: "On".</param>
/// <param name="Absent">What it means when no location has the setting.</param>
/// <param name="Labels">Words for particular values ("0": "Off"); other values are shown as numbers.</param>
/// <param name="Unit">A unit shown after a number without a label: "seconds".</param>
/// <param name="OnlyWhen">Another setting that must hold for the rule to apply.</param>
public sealed record RegistryRule(
    string Item,
    RegistryRoot Root,
    IReadOnlyList<RegistryLocation> Locations,
    Expectation Expect,
    string Expected,
    AbsentValue Absent,
    IReadOnlyDictionary<string, string>? Labels = null,
    string? Unit = null,
    RegistryCondition? OnlyWhen = null);

/// <summary>What a service must be.</summary>
public enum ServiceRequirement
{
    /// <summary>Its start type is Disabled and it is not running.</summary>
    Disabled,

    /// <summary>It is not running now, whatever its start type.</summary>
    NotRunning,
}

/// <summary>A Windows service that should be off. A service that is not installed passes.</summary>
/// <param name="Item">The service's display name.</param>
/// <param name="Name">The service's short name.</param>
/// <param name="Require">What it must be.</param>
public sealed record ServiceRule(string Item, string Name, ServiceRequirement Require);

/// <summary>The password and lockout policy values a rule can look at.</summary>
public enum AccountPolicyField
{
    MinimumPasswordLength,
    PasswordHistoryLength,

    /// <summary>In days; 0 means passwords never expire.</summary>
    MaximumPasswordAgeDays,

    /// <summary>Failed sign-ins before lockout; 0 means accounts never lock.</summary>
    LockoutThreshold,

    /// <summary>In minutes. Does not apply while accounts never lock.</summary>
    LockoutDurationMinutes,
}

/// <summary>A password or lockout policy value compared with what is expected.</summary>
/// <param name="Item">What the setting is, in words.</param>
/// <param name="Field">Which value.</param>
/// <param name="Expect">What it must be.</param>
/// <param name="Expected">The expectation in words.</param>
/// <param name="Unit">A unit shown after the number.</param>
public sealed record AccountPolicyRule(
    string Item, AccountPolicyField Field, Expectation Expect, string Expected, string? Unit = null);

/// <summary>An audit policy subcategory that must record successes, failures or both.</summary>
/// <param name="Item">The subcategory's name.</param>
/// <param name="Subcategory">Its identifier.</param>
/// <param name="Success">Successes must be recorded.</param>
/// <param name="Failure">Failures must be recorded.</param>
public sealed record AuditPolicyRule(string Item, Guid Subcategory, bool Success, bool Failure);

/// <summary>A user right that only certain accounts may hold.</summary>
/// <param name="Item">The right's name in words: "Debug programs".</param>
/// <param name="Right">Its constant name: "SeDebugPrivilege".</param>
/// <param name="Allowed">The identifiers (SIDs) of the groups that may hold it.</param>
public sealed record UserRightRule(string Item, string Right, IReadOnlyList<string> Allowed);

/// <summary>
/// A Microsoft Defender Antivirus setting compared with what is expected. Does not apply
/// when another antivirus is in charge.
/// </summary>
/// <param name="Item">What the setting is, in words.</param>
/// <param name="Property">The property of Defender's settings (a number, or yes/no read as 1/0).</param>
/// <param name="Expect">What it must be.</param>
/// <param name="Expected">The expectation in words.</param>
/// <param name="Labels">Words for particular values.</param>
public sealed record DefenderRule(
    string Item, string Property, Expectation Expect, string Expected, IReadOnlyDictionary<string, string>? Labels = null);

/// <summary>One attack surface reduction rule.</summary>
/// <param name="Id">Its identifier, as Microsoft publishes it.</param>
/// <param name="Name">What it does, in words.</param>
public sealed record AttackSurfaceRule(Guid Id, string Name);

/// <summary>Attack surface reduction rules that must be set to block.</summary>
/// <param name="Rules">The rules that are expected.</param>
public sealed record DefenderRulesRule(IReadOnlyList<AttackSurfaceRule> Rules);

// Every constructor parameter without a default must be in the file, and none may be null:
// a rule with its severity or verification date left out is refused, not given a default.
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true,
    ReadCommentHandling = JsonCommentHandling.Disallow,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(RuleFile))]
internal sealed partial class RulesJson : JsonSerializerContext;
