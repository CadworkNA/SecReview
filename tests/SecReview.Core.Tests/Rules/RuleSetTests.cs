using System.Text;
using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;
using SecReview.Rules;

namespace SecReview.Tests.Rules;

/// <summary>
/// The rules are data. These tests keep the shipped ones honest: each says where it was
/// verified, what absence means, and never asks for rights it should not have.
/// </summary>
[TestClass]
public sealed class RuleSetTests
{
    private static IEnumerable<object[]> ShippedRules => RuleSet.Shipped.Select(r => new object[] { r.Id });

    private static RuleDefinition Shipped(string id) => RuleSet.Shipped.Single(r => r.Id == id);

    [TestMethod]
    public void TheShippedRules_Load_AndAreThere()
    {
        Assert.IsTrue(RuleSet.Shipped.Count >= 50, $"only {RuleSet.Shipped.Count} rules");
        Assert.AreEqual(RuleSet.Shipped.Count, RuleSet.Shipped.Select(r => r.Id).Distinct().Count());
    }

    [TestMethod]
    [DynamicData(nameof(ShippedRules))]
    public void EveryRule_HoldsTogether(string id)
    {
        RuleDefinition rule = Shipped(id);

        Assert.IsNull(RuleSet.Problem(rule));
        Assert.IsTrue(id.StartsWith("harden.", StringComparison.Ordinal), "a hardening rule's identifier starts with harden.");
        Assert.AreEqual(CheckCategory.Hardening, rule.Category);
    }

    [TestMethod]
    [DynamicData(nameof(ShippedRules))]
    public void EveryRule_SaysWhereAndWhenItWasVerified(string id)
    {
        RuleDefinition rule = Shipped(id);

        Assert.IsTrue(
            rule.Source.StartsWith("https://learn.microsoft.com/", StringComparison.Ordinal) ||
            rule.Source.StartsWith("https://support.microsoft.com/", StringComparison.Ordinal),
            $"{id}: the source is a Microsoft documentation page");
        Assert.IsTrue(rule.Verified >= new DateOnly(2026, 11, 1), $"{id}: no verification date");
    }

    [TestMethod]
    [DynamicData(nameof(ShippedRules))]
    public void EveryRule_AsksOnlyForTheRightsItNeeds(string id)
    {
        RuleDefinition rule = Shipped(id);
        CheckDefinition definition = new RuleCheck(rule).Definition;

        bool needsAdministrator = rule.AuditPolicy is not null || rule.UserRight is not null;
        bool defender = rule.Defender is not null || rule.DefenderRules is not null;
        Assert.AreEqual(
            needsAdministrator ? AdminNeed.Yes : rule.NeedsAdmin ?? (defender ? AdminNeed.ForFullDetail : AdminNeed.No),
            definition.NeedsAdmin);

        // A rule about the user's own settings must never be read under an administrator's account.
        if (rule.Registry?.Root == RegistryRoot.CurrentUser)
        {
            Assert.AreEqual(CheckScope.User, definition.Scope);
            Assert.AreEqual(AdminNeed.No, definition.NeedsAdmin);
        }
    }

    [TestMethod]
    [DynamicData(nameof(ShippedRules))]
    public void EveryRegistryRule_SaysWhatAbsenceMeans_InWords(string id)
    {
        if (Shipped(id).Registry is not { } registry)
        {
            return;
        }

        StringAssert.StartsWith(registry.Absent.Found, "Not ", $"{id}: absence is worded as \"Not configured ...\" or \"Not set ...\"");
        Assert.IsTrue(registry.Item.Length <= 50, $"{id}: the item is longer than 50: {registry.Item}");
        Assert.IsTrue(registry.Expected.Length <= 40, $"{id}: the expectation is longer than 40: {registry.Expected}");

        // Whatever the rule expects must have words, so "found 2, expected On" never appears.
        if (registry.Labels is not null && registry.Expect.Is is { } expected)
        {
            Assert.IsTrue(registry.Labels.ContainsKey(expected.ToString(System.Globalization.CultureInfo.InvariantCulture)), $"{id}: the expected value has no label");
        }
    }

    private static IReadOnlyList<RuleDefinition> Parse(string json) =>
        RuleSet.Parse(new MemoryStream(Encoding.UTF8.GetBytes(json)), "test.json");

    private const string Text =
        """{ "name": "N", "titlePass": "P", "titleFail": "F", "why": "W.", "fix": ["Do it."], "timeToFix": "1 min", "settingsLink": null, "references": [] }""";

    private static string RuleJson(string kind) =>
        $$"""{ "rules": [ { "id": "harden.test", "category": "hardening", "severity": "low", "text": {{Text}}, "source": "https://learn.microsoft.com/x", "verified": "2026-11-12"{{kind}} } ] }""";

    [TestMethod]
    public void AWellFormedRule_Parses()
    {
        IReadOnlyList<RuleDefinition> rules = Parse(RuleJson(
            """, "service": { "item": "Remote Registry", "name": "RemoteRegistry", "require": "disabled" }"""));

        Assert.AreEqual(1, rules.Count);
        Assert.AreEqual(ServiceRequirement.Disabled, rules[0].Service!.Require);
        Assert.AreEqual(Severity.Low, rules[0].Severity);
    }

    [TestMethod]
    public void ARuleThatReadsWhatANormalUserMayNot_JoinsTheAdministratorScan()
    {
        // The security log's own settings are closed to normal users on current Windows.
        Assert.AreEqual(AdminNeed.ForFullDetail, new RuleCheck(Shipped("harden.log.security-size")).Definition.NeedsAdmin);
    }

    [TestMethod]
    [DataRow("", "exactly one of", DisplayName = "nothing to read")]
    [DataRow(
        """, "service": { "item": "A", "name": "a", "require": "disabled" }, "userRight": { "item": "B", "right": "SeX", "allowed": [] }""",
        "exactly one of",
        DisplayName = "two things to read")]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        "locations",
        DisplayName = "no location")]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [ { "key": "SYSTEM\\X", "value": "V" } ], "expect": { }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        "says nothing",
        DisplayName = "an expectation that says nothing")]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [ { "key": "HKLM\\SYSTEM\\X", "value": "V" } ], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        "without its root",
        DisplayName = "a key written with its root")]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [ { "key": "SOFTWARE\\Policies\\X", "value": "V" } ], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        "marked as policy",
        DisplayName = "a policy key not marked as policy")]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [ { "key": "SYSTEM\\X", "value": "V", "policy": true } ], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        "marked as policy",
        DisplayName = "an ordinary key marked as policy")]
    [DataRow(
        """, "auditPolicy": { "item": "Logon", "subcategory": "0cce9215-69ae-11d9-bed3-505054503030", "success": false, "failure": false }""",
        "success or failure",
        DisplayName = "an audit rule that asks for nothing")]
    [DataRow(
        """, "userRight": { "item": "Debug", "right": "SeDebugPrivilege", "allowed": [ "Administrators" ] }""",
        "S-1-",
        DisplayName = "a group given by name")]
    [DataRow(
        """, "defender": { "item": "A", "property": "X; DROP", "expect": { "is": 1 }, "expected": "On" }""",
        "property name",
        DisplayName = "a property that is not a plain name")]
    [DataRow(""", "defenderRules": { "rules": [] }""", "at least one rule", DisplayName = "no Defender rules")]
    [DataRow(
        """, "needsAdmin": "yes", "registry": { "item": "A", "root": "currentUser", "locations": [ { "key": "Software\\X", "value": "V" } ], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        "user's own settings",
        DisplayName = "a user rule that asks for administrator rights")]
    public void ARuleThatDoesNotHoldTogether_StopsTheLoad_WithTheReason(string kind, string reason)
    {
        JsonException exception = Assert.ThrowsExactly<JsonException>(() => Parse(RuleJson(kind)));

        StringAssert.Contains(exception.Message, "test.json");
        StringAssert.Contains(exception.Message, "harden.test");
        StringAssert.Contains(exception.Message, reason);
    }

    [TestMethod]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [ null ], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false } }""",
        DisplayName = "an empty location")]
    [DataRow(""", "userRight": { "item": "Debug", "right": "SeDebugPrivilege", "allowed": [ null ] }""", DisplayName = "an empty identifier")]
    [DataRow(""", "defenderRules": { "rules": [ null ] }""", DisplayName = "an empty Defender rule")]
    [DataRow(
        """, "accountPolicy": { "item": "A", "field": 99, "expect": { "atMost": 10 }, "expected": "10 or fewer" }""",
        DisplayName = "a field given as an unknown number")]
    [DataRow(
        """, "registry": { "item": "A", "root": "localMachine", "locations": [ { "key": "SYSTEM\\X", "value": "V" } ], "expect": { "is": 1 }, "expected": "On", "absent": { "found": "Not configured", "passes": false }, "onlyWhen": { "key": "SYSTEM\\X", "value": "W", "expect": { }, "holdsWhenAbsent": true, "otherwise": "Off." } }""",
        DisplayName = "a condition that says nothing")]
    public void AMalformedRule_IsRefusedByName_NeverACrash(string kind)
    {
        JsonException exception = Assert.ThrowsExactly<JsonException>(() => Parse(RuleJson(kind)));

        StringAssert.Contains(exception.Message, "test.json");
    }

    [TestMethod]
    [DataRow("\"severity\": \"low\", ", DisplayName = "severity")]
    [DataRow("\"category\": \"hardening\", ", DisplayName = "category")]
    [DataRow(", \"verified\": \"2026-11-12\"", DisplayName = "the verification date")]
    [DataRow(", \"source\": \"https://learn.microsoft.com/x\"", DisplayName = "the source")]
    public void ARuleWithARequiredPartLeftOut_IsRefused_NotGivenADefault(string part)
    {
        string json = RuleJson(""", "service": { "item": "A", "name": "a", "require": "disabled" }""");
        Assert.IsTrue(json.Contains(part, StringComparison.Ordinal), "the test removes a part that is there");

        JsonException exception = Assert.ThrowsExactly<JsonException>(() => Parse(json.Replace(part, string.Empty, StringComparison.Ordinal)));

        StringAssert.Contains(exception.Message, "test.json");
    }

    [TestMethod]
    [DataRow("\"severity\": \"low\"", "\"severity\": 99", DisplayName = "an unknown severity number")]
    [DataRow("\"category\": \"hardening\"", "\"category\": 99", DisplayName = "an unknown category number")]
    [DataRow("\"require\": \"disabled\"", "\"require\": 99", DisplayName = "an unknown requirement number")]
    public void AnUnknownNumberWhereANameBelongs_IsRefused(string old, string replacement)
    {
        string json = RuleJson(""", "service": { "item": "A", "name": "a", "require": "disabled" }""");

        Assert.ThrowsExactly<JsonException>(() => Parse(json.Replace(old, replacement, StringComparison.Ordinal)));
    }

    [TestMethod]
    [DataRow("""{ "rules": [ { "id": "x", "unknownMember": 1 } ] }""", DisplayName = "an unknown member")]
    [DataRow("""{ "rules": [ { "id": "x" } ] // comment""", DisplayName = "a comment")]
    [DataRow("not json", DisplayName = "not JSON")]
    [DataRow("null", DisplayName = "nothing")]
    public void AFileThatIsNotAValidRuleFile_IsRefused(string json)
    {
        JsonException exception = Assert.ThrowsExactly<JsonException>(() => Parse(json));

        StringAssert.Contains(exception.Message, "test.json");
    }
}
