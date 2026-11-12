namespace SecReview.Probing;

/// <summary>
/// Every way SecReview reads the machine. Checks receive this instead of calling Windows, so
/// tests substitute fakes and never read the real machine.
/// </summary>
public sealed record SystemProbes(
    IRegistryProbe Registry,
    IServiceProbe Services,
    IWmiProbe Wmi,
    IFirewallProbe Firewall,
    ISecurityCenterProbe SecurityCenter,
    IAccountPolicyProbe AccountPolicy,
    IPowerProbe Power,
    IDriveEncryptionProbe DriveEncryption,
    IWindowsUpdateProbe WindowsUpdate,
    IAuditPolicyProbe AuditPolicy,
    IUserRightsProbe UserRights,
    IFileProbe Files,
    IEnvironmentProbe Environment,
    IPlatformProbe Platform);
