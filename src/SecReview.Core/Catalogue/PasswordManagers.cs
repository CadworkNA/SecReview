using System.Resources;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecReview.Catalogue;

/// <summary>One password manager and the ways it shows up on a PC.</summary>
/// <param name="Name">The product's name.</param>
/// <param name="Apps">How the desktop app's name starts in the list of installed programs.</param>
/// <param name="Chromium">Extension identifiers in Chrome, Edge and other Chromium browsers (both stores).</param>
/// <param name="Firefox">Extension identifiers in Firefox.</param>
public sealed record PasswordManager(
    string Name, IReadOnlyList<string> Apps, IReadOnlyList<string> Chromium, IReadOnlyList<string> Firefox);

/// <summary>
/// The password managers SecReview recognises. Extension identifiers were looked up in the
/// browser stores' own listings and the vendors' pages, app names in the vendors' package
/// descriptions; <see cref="Verified"/> says when. A wrong entry can only make a product go
/// unnoticed: an identifier belongs to one extension only.
/// </summary>
/// <param name="Verified">The day the identifiers were confirmed.</param>
/// <param name="Managers">The products.</param>
public sealed record PasswordManagers(DateOnly Verified, IReadOnlyList<PasswordManager> Managers)
{
    private const string ResourceName = "SecReview.Catalogue.password-managers.json";

    private static readonly Lazy<PasswordManagers> Shipped = new(Load);

    /// <summary>The list shipped with this build.</summary>
    public static PasswordManagers Current => Shipped.Value;

    internal static PasswordManagers Parse(Stream json) =>
        JsonSerializer.Deserialize(json, PasswordManagersJson.Default.PasswordManagers)
        ?? throw new JsonException("The password manager list is empty.");

    private static PasswordManagers Load()
    {
        using Stream stream = typeof(PasswordManagers).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new MissingManifestResourceException($"Embedded resource '{ResourceName}' is missing.");
        return Parse(stream);
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    ReadCommentHandling = JsonCommentHandling.Disallow,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(PasswordManagers))]
internal sealed partial class PasswordManagersJson : JsonSerializerContext;
