using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecReview.Updates;

/// <summary>
/// What the small file <c>latest.json</c> says about the newest release: its version, where
/// its setup program is, that program's SHA-256, when it was published and what is new.
/// Written by the release workflow; read by the update check and, again, by the helper that
/// installs an update.
/// </summary>
/// <param name="Version">The newest version, a semantic version without a leading "v".</param>
/// <param name="Url">Where the setup program is. HTTPS, on a host the build allows.</param>
/// <param name="Sha256">The setup program's SHA-256, 64 lower-case hexadecimal digits.</param>
/// <param name="Published">When the release was published.</param>
/// <param name="Notes">What is new, as plain text; may be empty.</param>
public sealed record UpdateManifest(string Version, Uri Url, string Sha256, DateTimeOffset Published, string Notes)
{
    /// <summary>A manifest larger than this is not one.</summary>
    public const int MaximumBytes = 64 * 1024;

    /// <summary>The longest text of "what is new" that is kept.</summary>
    public const int MaximumNotesLength = 2000;

    private const int MaximumUrlLength = 500;

    /// <summary>
    /// The manifest, or null with the reason. Everything must be there and well-formed; a
    /// manifest that is only partly right is not used at all.
    /// </summary>
    /// <param name="utf8">The file's bytes.</param>
    /// <param name="source">Which hosts the setup program may be on.</param>
    /// <param name="now">The current time; a release dated after tomorrow is not believed.</param>
    /// <param name="problem">Why there is no manifest; null when there is one.</param>
    public static UpdateManifest? Parse(ReadOnlySpan<byte> utf8, UpdateSource source, DateTimeOffset now, out string? problem)
    {
        ArgumentNullException.ThrowIfNull(source);

        if (utf8.Length > MaximumBytes)
        {
            problem = "the answer is too large to be the list of versions";
            return null;
        }

        Stored? stored;
        try
        {
            stored = JsonSerializer.Deserialize(utf8, UpdateJson.Default.Stored);
        }
        catch (JsonException)
        {
            problem = "the answer is not the list of versions";
            return null;
        }

        if (stored is not { Version: not null, Url: not null, Sha256: not null, Published: not null })
        {
            problem = "the list of versions is incomplete";
            return null;
        }

        if (!UpdateRules.IsReleaseVersion(stored.Version))
        {
            problem = "the list of versions names no proper version";
            return null;
        }

        if (stored.Url.Length > MaximumUrlLength || !Uri.TryCreate(stored.Url, UriKind.Absolute, out Uri? url) || !source.Allows(url))
        {
            problem = "the list of versions points somewhere this build does not download from";
            return null;
        }

        if (stored.Sha256.Length != 64 || !stored.Sha256.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f')))
        {
            problem = "the list of versions has no proper checksum";
            return null;
        }

        if (!DateTimeOffset.TryParse(stored.Published, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset published) ||
            published.Year < 2025 || published > now.AddDays(1))
        {
            problem = "the list of versions has no proper date";
            return null;
        }

        problem = null;
        return new UpdateManifest(stored.Version, url, stored.Sha256, published, CleanNotes(stored.Notes));
    }

    /// <summary>The bytes of a manifest, as the release workflow writes it and <see cref="Parse"/> reads it.</summary>
    public byte[] ToBytes() => JsonSerializer.SerializeToUtf8Bytes(
        new Stored(Version, Url.AbsoluteUri, Sha256, Published.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture), Notes),
        UpdateJson.Default.Stored);

    /// <summary>Plain text of a sensible length: no control characters other than line breaks.</summary>
    private static string CleanNotes(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return string.Empty;
        }

        string clean = new([.. notes.Where(c => c == '\n' || !char.IsControl(c))]);
        clean = clean.Trim();
        return clean.Length <= MaximumNotesLength ? clean : clean[..(MaximumNotesLength - 1)] + "…";
    }

    internal sealed record Stored(string? Version, string? Url, string? Sha256, string? Published, string? Notes);
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    ReadCommentHandling = JsonCommentHandling.Disallow)]
[JsonSerializable(typeof(UpdateManifest.Stored))]
[JsonSerializable(typeof(UpdateState))]
internal sealed partial class UpdateJson : JsonSerializerContext;
