using System.Resources;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecReview.Catalogue;

/// <summary>The wording of one check, kept as data so it can be reviewed and translated.</summary>
/// <param name="Name">What the check is about, without a verdict, for example "Firewall".</param>
/// <param name="TitlePass">The check's title when it passes, for example "Firewall is on".</param>
/// <param name="TitleFail">Its title when it fails, for example "Firewall is off".</param>
/// <param name="Why">Why it matters, in at most two sentences.</param>
/// <param name="Fix">How to fix it, as short numbered actions.</param>
/// <param name="TimeToFix">Roughly how long the fix takes.</param>
/// <param name="SettingsLink">The Windows Settings page to open (an <c>ms-settings:</c> address).</param>
/// <param name="References">Benchmark sections this check relates to.</param>
public sealed record CheckText(
    string Name,
    string TitlePass,
    string TitleFail,
    string Why,
    IReadOnlyList<string> Fix,
    string TimeToFix,
    string? SettingsLink,
    IReadOnlyList<string> References)
{
    /// <summary>
    /// The title for an outcome. Only a pass gets the passing title and only a failure the
    /// failing one: a check that could not be answered is named neutrally, so "could not check"
    /// is never shown as "Firewall is off".
    /// </summary>
    public string TitleFor(Checks.CheckStatus status) => status switch
    {
        Checks.CheckStatus.Pass => TitlePass,
        Checks.CheckStatus.Fail => TitleFail,
        _ => Name,
    };
}

/// <summary>The wording of every check, loaded from the data embedded in this assembly.</summary>
public sealed class CheckTexts
{
    private const string ResourceName = "SecReview.Catalogue.checks.en.json";

    private readonly Dictionary<string, CheckText> _texts;

    private CheckTexts(Dictionary<string, CheckText> texts) => _texts = texts;

    /// <summary>The identifiers that have wording.</summary>
    public IReadOnlyCollection<string> Ids => _texts.Keys;

    /// <summary>The wording of a check; throws for an identifier that has none.</summary>
    public CheckText this[string checkId] => _texts.TryGetValue(checkId, out CheckText? text)
        ? text
        : throw new KeyNotFoundException($"No wording for check '{checkId}'.");

    public bool Contains(string checkId) => _texts.ContainsKey(checkId);

    /// <summary>This wording plus that of more checks. An identifier may have wording only once.</summary>
    public CheckTexts With(IEnumerable<KeyValuePair<string, CheckText>> more)
    {
        ArgumentNullException.ThrowIfNull(more);

        var texts = new Dictionary<string, CheckText>(_texts, StringComparer.Ordinal);
        foreach ((string id, CheckText text) in more)
        {
            if (!texts.TryAdd(id, text))
            {
                throw new ArgumentException($"The check '{id}' has wording twice.", nameof(more));
            }
        }

        return new CheckTexts(texts);
    }

    /// <summary>Loads the embedded English wording.</summary>
    public static CheckTexts Load()
    {
        using Stream stream = typeof(CheckTexts).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new MissingManifestResourceException($"Embedded resource '{ResourceName}' is missing.");
        return Parse(stream);
    }

    internal static CheckTexts Parse(Stream json)
    {
        Dictionary<string, CheckText> texts =
            JsonSerializer.Deserialize(json, CatalogueJson.Default.DictionaryStringCheckText)
            ?? throw new JsonException("The check wording is empty.");
        return new CheckTexts(new Dictionary<string, CheckText>(texts, StringComparer.Ordinal));
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    ReadCommentHandling = JsonCommentHandling.Disallow,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(Dictionary<string, CheckText>))]
internal sealed partial class CatalogueJson : JsonSerializerContext;
