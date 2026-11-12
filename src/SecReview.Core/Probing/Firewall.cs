namespace SecReview.Probing;

/// <summary>The three Windows Firewall profiles; a network connection is in exactly one.</summary>
[Flags]
public enum FirewallProfiles
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
}

/// <summary>Effective settings of one firewall profile (after Group Policy).</summary>
public sealed record FirewallProfileState(FirewallProfiles Profile, bool Enabled, bool BlocksInboundByDefault);

/// <summary>Effective Windows Firewall state.</summary>
/// <param name="Profiles">Domain, Private and Public, in that order.</param>
/// <param name="ActiveProfiles">The profiles the current network connections use.</param>
public sealed record FirewallState(IReadOnlyList<FirewallProfileState> Profiles, FirewallProfiles ActiveProfiles);

public interface IFirewallProbe
{
    ProbeResult<FirewallState> GetState();
}
