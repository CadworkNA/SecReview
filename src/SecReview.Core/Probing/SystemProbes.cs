namespace SecReview.Probing;

/// <summary>
/// Every way SecReview reads the machine. Checks receive this instead of calling Windows, so
/// tests substitute fakes and never read the real machine.
/// </summary>
public sealed record SystemProbes(
    IFirewallProbe Firewall,
    ISecurityCenterProbe SecurityCenter,
    IAccountPolicyProbe AccountPolicy);
