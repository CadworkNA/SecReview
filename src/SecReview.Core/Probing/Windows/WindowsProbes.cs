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

    /// <summary>
    /// Whether this process got its administrator rights through the Windows prompt: the user
    /// has an ordinary side as well, and this process is not on it. False for an ordinary
    /// process, and where administrators are always elevated (User Account Control off).
    /// False too when Windows does not say.
    /// </summary>
    [SupportedOSPlatform(MinimumWindows.Platform)]
    public static unsafe bool IsElevatedByPrompt()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        global::Windows.Win32.Security.TOKEN_ELEVATION_TYPE type = default;
        uint length;
        return global::Windows.Win32.PInvoke.GetTokenInformation(
                new global::Windows.Win32.Foundation.HANDLE(identity.Token),
                global::Windows.Win32.Security.TOKEN_INFORMATION_CLASS.TokenElevationType,
                &type,
                sizeof(uint),
                &length)
            && type == global::Windows.Win32.Security.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull;
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
            UserRights: new WindowsUserRightsProbe(),
            Files: new DiskFileProbe(),
            Environment: new ProcessEnvironmentProbe(),
            Platform: new WindowsPlatformProbe());
    }
}
