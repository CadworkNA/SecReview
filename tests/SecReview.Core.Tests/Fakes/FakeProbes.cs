using SecReview.Probing;

namespace SecReview.Tests.Fakes;

/// <summary>
/// Stand-ins for the machine. Each returns what the test set; anything a test did not set
/// answers "not supported", so a check that reads more than the test expects is visible.
/// </summary>
internal sealed class FakeProbes
{
    private static readonly ProbeFailure NotSetUp = ProbeFailure.NotSupported("Not set up in this test.");

    public ProbeResult<FirewallState> Firewall { get; set; } = NotSetUp;

    public ProbeResult<IReadOnlyList<SecurityProduct>> AntivirusProducts { get; set; } = NotSetUp;

    public ProbeResult<IReadOnlyList<SecurityProduct>> FirewallProducts { get; set; } = NotSetUp;

    public ProbeResult<AccountPolicy> AccountPolicy { get; set; } = NotSetUp;

    public SystemProbes Build() => new(
        Firewall: new FirewallProbe(this),
        SecurityCenter: new SecurityCenterProbe(this),
        AccountPolicy: new AccountPolicyProbe(this));

    /// <summary>A firewall state with all three profiles set the same way.</summary>
    public static FirewallState FirewallAll(bool enabled, bool blocksInbound = true) => new(
        [
            new FirewallProfileState(FirewallProfiles.Domain, enabled, blocksInbound),
            new FirewallProfileState(FirewallProfiles.Private, enabled, blocksInbound),
            new FirewallProfileState(FirewallProfiles.Public, enabled, blocksInbound),
        ],
        FirewallProfiles.Private);

    public static AccountPolicy DefaultAccountPolicy() => new(
        MinimumPasswordLength: 0,
        MaximumPasswordAge: TimeSpan.FromDays(42),
        MinimumPasswordAge: TimeSpan.Zero,
        PasswordHistoryLength: 0,
        LockoutThreshold: 10,
        LockoutDuration: TimeSpan.FromMinutes(10),
        LockoutObservationWindow: TimeSpan.FromMinutes(10));

    private sealed class FirewallProbe(FakeProbes owner) : IFirewallProbe
    {
        public ProbeResult<FirewallState> GetState() => owner.Firewall;
    }

    private sealed class SecurityCenterProbe(FakeProbes owner) : ISecurityCenterProbe
    {
        public ProbeResult<IReadOnlyList<SecurityProduct>> GetProducts(SecurityProductKind kind) =>
            kind == SecurityProductKind.Antivirus ? owner.AntivirusProducts : owner.FirewallProducts;
    }

    private sealed class AccountPolicyProbe(FakeProbes owner) : IAccountPolicyProbe
    {
        public ProbeResult<AccountPolicy> GetPolicy() => owner.AccountPolicy;
    }
}
