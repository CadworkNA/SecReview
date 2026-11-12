using System.Runtime.Versioning;

namespace SecReview.Probing.Windows;

/// <summary>The probes that read the real machine.</summary>
public static class WindowsProbes
{
    /// <summary>Whether this Windows is recent enough for <see cref="Create"/>.</summary>
    [SupportedOSPlatformGuard(MinimumWindows.Platform)]
    public static bool IsSupported =>
        OperatingSystem.IsWindowsVersionAtLeast(MinimumWindows.Major, MinimumWindows.Minor, MinimumWindows.Build);

    /// <summary>
    /// Whether this process has administrator rights right now. With User Account Control an
    /// administrator's ordinary programs do not: only an elevated one does.
    /// </summary>
    [SupportedOSPlatform(MinimumWindows.Platform)]
    public static bool IsProcessElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>The oldest supported Windows, for messages.</summary>
    public static string MinimumWindowsName => MinimumWindows.DisplayName;

    [SupportedOSPlatform(MinimumWindows.Platform)]
    public static SystemProbes Create()
    {
        var wmi = new WindowsWmiProbe();
        return new SystemProbes(
            Registry: new WindowsRegistryProbe(),
            Services: new WindowsServiceProbe(),
            Wmi: wmi,
            Firewall: new WindowsFirewallProbe(),
            SecurityCenter: new WindowsSecurityCenterProbe(wmi),
            AccountPolicy: new WindowsAccountPolicyProbe(),
            Power: new WindowsPowerProbe(),
            DriveEncryption: new WindowsDriveEncryptionProbe(),
            WindowsUpdate: new WindowsUpdateProbe(),
            AuditPolicy: new WindowsAuditPolicyProbe(),
            UserRights: new WindowsUserRightsProbe());
    }
}
