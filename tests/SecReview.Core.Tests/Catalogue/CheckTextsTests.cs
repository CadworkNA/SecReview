using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecReview.Catalogue;
using SecReview.Checks.BuiltIn;

namespace SecReview.Tests.Catalogue;

/// <summary>
/// The wording of the checks is data. These tests keep it complete and short: every check has
/// wording, nothing is orphaned, and the limits that make the screen readable are enforced.
/// </summary>
[TestClass]
public sealed partial class CheckTextsTests
{
    private const int MaximumTitleLength = 60;
    private const int MaximumWhyLength = 200;
    private const int MaximumWhySentences = 2;
    private const int MaximumFixSteps = 5;
    private const int MaximumFixStepLength = 140;

    private static readonly CheckTexts Texts = CheckTexts.Load();

    private static IEnumerable<object[]> CheckIds => BuiltInChecks.All.Select(c => new object[] { c.Definition.Id });

    [TestMethod]
    public void EveryCheckHasWording_AndNoWordingIsOrphaned()
    {
        string[] checks = [.. BuiltInChecks.All.Select(c => c.Definition.Id).Order(StringComparer.Ordinal)];
        string[] worded = [.. Texts.Ids.Order(StringComparer.Ordinal)];

        CollectionAssert.AreEqual(checks, worded);
    }

    [TestMethod]
    public void CheckIdsAreUnique_AndWellFormed()
    {
        string[] ids = [.. BuiltInChecks.All.Select(c => c.Definition.Id)];

        Assert.AreEqual(ids.Length, ids.Distinct(StringComparer.Ordinal).Count(), "duplicate check id");
        foreach (string id in ids)
        {
            Assert.IsTrue(IdPattern().IsMatch(id), $"'{id}' is not lower-case words separated by dots");
        }
    }

    [TestMethod]
    [DynamicData(nameof(CheckIds))]
    public void Titles_AreOneShortSentenceWithoutAFullStop(string id)
    {
        CheckText text = Texts[id];

        // The neutral name states no verdict: it is used when the check could not be answered.
        Assert.IsFalse(string.IsNullOrWhiteSpace(text.Name), $"{id}: no name");
        Assert.IsTrue(text.Name.Length <= 40, $"{id}: name longer than 40: {text.Name}");
        Assert.IsFalse(text.Name.EndsWith('.'), $"{id}: a name has no full stop");
        Assert.AreNotEqual(text.TitlePass, text.Name, $"{id}: the name must not be the passing title");
        Assert.AreNotEqual(text.TitleFail, text.Name, $"{id}: the name must not be the failing title");

        foreach (string title in new[] { text.TitlePass, text.TitleFail })
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(title), $"{id}: empty title");
            Assert.IsTrue(title.Length <= MaximumTitleLength, $"{id}: title longer than {MaximumTitleLength}: {title}");
            Assert.IsFalse(title.EndsWith('.'), $"{id}: a title has no full stop: {title}");
            Assert.AreEqual(title.Trim(), title, $"{id}: title has surrounding spaces");
        }

        Assert.AreNotEqual(text.TitlePass, text.TitleFail, $"{id}: the pass and fail titles are the same");
    }

    [TestMethod]
    [DynamicData(nameof(CheckIds))]
    public void Why_IsAtMostTwoShortSentences(string id)
    {
        string why = Texts[id].Why;

        Assert.IsFalse(string.IsNullOrWhiteSpace(why), $"{id}: no explanation");
        Assert.IsTrue(why.Length <= MaximumWhyLength, $"{id}: explanation longer than {MaximumWhyLength}");
        Assert.IsTrue(why.EndsWith('.'), $"{id}: explanation must end with a full stop");
        Assert.IsTrue(SentenceEnd().Count(why) <= MaximumWhySentences, $"{id}: more than {MaximumWhySentences} sentences");
    }

    [TestMethod]
    [DynamicData(nameof(CheckIds))]
    public void FixSteps_AreAFewShortActions(string id)
    {
        IReadOnlyList<string> steps = Texts[id].Fix;

        Assert.IsTrue(steps.Count is >= 1 and <= MaximumFixSteps, $"{id}: {steps.Count} fix steps");
        foreach (string step in steps)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(step), $"{id}: empty fix step");
            Assert.IsTrue(step.Length <= MaximumFixStepLength, $"{id}: fix step longer than {MaximumFixStepLength}: {step}");
            Assert.IsTrue(step.EndsWith('.'), $"{id}: a fix step ends with a full stop: {step}");
        }

        Assert.IsFalse(string.IsNullOrWhiteSpace(Texts[id].TimeToFix), $"{id}: no time to fix");
    }

    [TestMethod]
    [DynamicData(nameof(CheckIds))]
    public void SettingsLink_OnlyOpensAWindowsSettingsPage(string id)
    {
        string? link = Texts[id].SettingsLink;
        if (link is null)
        {
            return;
        }

        // The app opens this address when the user asks, so it may be nothing but a Settings page.
        Assert.IsTrue(SettingsLinkPattern().IsMatch(link), $"{id}: '{link}' is not a plain ms-settings address");
    }

    [TestMethod]
    public void UnknownCheck_Throws_RatherThanShowingBlankText()
    {
        Assert.ThrowsExactly<KeyNotFoundException>(() => Texts["no.such.check"]);
        Assert.IsFalse(Texts.Contains("no.such.check"));
    }

    [TestMethod]
    public void WordingWithAnUnknownField_IsRejected()
    {
        // A misspelt field must not be silently dropped, leaving a check without its text.
        const string Json = """
            { "x.y": { "name": "n", "titlePass": "a", "titleFail": "b", "why": "c.", "fix": ["d."],
                       "timeToFix": "1 min", "settingsLink": null, "references": [], "tittlePass": "typo" } }
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(Json));

        Assert.ThrowsExactly<JsonException>(() => CheckTexts.Parse(stream));
    }

    [GeneratedRegex(@"^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*)+$")]
    private static partial Regex IdPattern();

    [GeneratedRegex(@"^ms-settings:[a-z][a-z-]*$")]
    private static partial Regex SettingsLinkPattern();

    [GeneratedRegex(@"[.!?](\s|$)")]
    private static partial Regex SentenceEnd();
}
