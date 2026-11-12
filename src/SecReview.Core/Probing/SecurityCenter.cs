namespace SecReview.Probing;

/// <summary>The kinds of protection software that register with Windows Security Center.</summary>
public enum SecurityProductKind
{
    Antivirus,
    Firewall,
}

public enum SecurityProductState
{
    On,
    Off,
    Snoozed,
    Expired,
}

/// <summary>A protection product as Windows Security Center reports it.</summary>
/// <param name="Name">The product's display name, for example "Microsoft Defender Antivirus".</param>
/// <param name="State">Whether the product is protecting the PC right now.</param>
/// <param name="SignaturesUpToDate">Whether its definitions are current (antivirus).</param>
public sealed record SecurityProduct(string Name, SecurityProductState State, bool SignaturesUpToDate);

public interface ISecurityCenterProbe
{
    /// <summary>
    /// The registered products of one kind. Windows Server has no Security Center: the result
    /// is <see cref="ProbeStatus.NotSupported"/> there.
    /// </summary>
    ProbeResult<IReadOnlyList<SecurityProduct>> GetProducts(SecurityProductKind kind);
}
