namespace SecReview.Probing.Windows;

/// <summary>
/// The oldest Windows SecReview runs on: Windows 10, version 2004. Everything under
/// Probing/Windows is marked with it, and entry points check it once before creating probes.
/// </summary>
internal static class MinimumWindows
{
    /// <summary>For <see cref="System.Runtime.Versioning.SupportedOSPlatformAttribute"/>.</summary>
    public const string Platform = "windows10.0.19041";

    public const int Major = 10;
    public const int Minor = 0;
    public const int Build = 19041;

    public const string DisplayName = "Windows 10, version 2004";
}
