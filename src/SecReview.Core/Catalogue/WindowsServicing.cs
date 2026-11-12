using System.Resources;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecReview.Catalogue;

/// <summary>One Windows feature release and when Microsoft stops updating it.</summary>
/// <param name="Build">The build number, for example 26100.</param>
/// <param name="Name">The name, for example "Windows 11, version 24H2".</param>
/// <param name="HomePro">Last day of security updates for Home and Pro editions.</param>
/// <param name="Enterprise">Last day for Enterprise and Education editions.</param>
public sealed record WindowsRelease(int Build, string Name, DateOnly HomePro, DateOnly Enterprise);

/// <summary>One long-term servicing release (LTSC), which keeps its own dates.</summary>
/// <param name="Build">The build number.</param>
/// <param name="Name">The name.</param>
/// <param name="Enterprise">Last day of security updates for Enterprise LTSC.</param>
/// <param name="Iot">Last day for IoT Enterprise LTSC.</param>
public sealed record WindowsLongTermRelease(int Build, string Name, DateOnly Enterprise, DateOnly Iot);

/// <summary>
/// When each Windows release stops getting security updates, from Microsoft's release
/// information pages. Shipped with the app: it is right as of <see cref="Verified"/>, and a
/// release newer than the list is reported as unknown, not guessed at.
/// </summary>
/// <param name="Verified">The day the list was checked against Microsoft's pages.</param>
/// <param name="Source">The page it was checked against.</param>
/// <param name="Releases">The ordinary releases.</param>
/// <param name="LongTerm">The long-term servicing releases.</param>
public sealed record WindowsServicing(
    DateOnly Verified,
    string Source,
    IReadOnlyList<WindowsRelease> Releases,
    IReadOnlyList<WindowsLongTermRelease> LongTerm)
{
    private const string ResourceName = "SecReview.Catalogue.windows-servicing.json";

    private static readonly Lazy<WindowsServicing> Shipped = new(Load);

    /// <summary>The list shipped with this build.</summary>
    public static WindowsServicing Current => Shipped.Value;

    internal static WindowsServicing Parse(Stream json) =>
        JsonSerializer.Deserialize(json, ServicingJson.Default.WindowsServicing)
        ?? throw new JsonException("The Windows servicing list is empty.");

    private static WindowsServicing Load()
    {
        using Stream stream = typeof(WindowsServicing).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new MissingManifestResourceException($"Embedded resource '{ResourceName}' is missing.");
        return Parse(stream);
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    ReadCommentHandling = JsonCommentHandling.Disallow,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(WindowsServicing))]
internal sealed partial class ServicingJson : JsonSerializerContext;
