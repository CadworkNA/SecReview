using System.Runtime.Versioning;

namespace SecReview.Probing.Windows;

/// <summary>The probes that read the real machine.</summary>
public static class WindowsProbes
{
    /// <summary>Whether this Windows is recent enough for <see cref="Create"/>.</summary>
    [SupportedOSPlatformGuard(MinimumWindows.Platform)]
    public static bool IsSupported =>
        OperatingSystem.IsWindowsVersionAtLeast(MinimumWindows.Major, MinimumWindows.Minor, MinimumWindows.Build);

    /// <summary>The oldest supported Windows, for messages.</summary>
    public static string MinimumWindowsName => MinimumWindows.DisplayName;

    [SupportedOSPlatform(MinimumWindows.Platform)]
    public static SystemProbes Create() => new(
        Registry: new WindowsRegistryProbe(),
        Services: new WindowsServiceProbe(),
        Firewall: new WindowsFirewallProbe(),
        SecurityCenter: new WindowsSecurityCenterProbe(),
        AccountPolicy: new WindowsAccountPolicyProbe(),
        Power: new WindowsPowerProbe());
}
