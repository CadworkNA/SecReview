using System.Reflection;

namespace SecReview;

/// <summary>Name and version of this build.</summary>
public static class ProductInfo
{
    public const string Name = "SecReview";

    /// <summary>The version as built, for example <c>1.2.3</c> or <c>0.0.0-dev</c>.</summary>
    public static string Version { get; } = StripBuildMetadata(
        typeof(ProductInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    /// <summary>Removes the <c>+commit</c> suffix the SDK appends to the informational version.</summary>
    internal static string StripBuildMetadata(string? informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion))
        {
            return "0.0.0";
        }

        int plus = informationalVersion.IndexOf('+', StringComparison.Ordinal);
        return plus < 0 ? informationalVersion : informationalVersion[..plus];
    }
}
