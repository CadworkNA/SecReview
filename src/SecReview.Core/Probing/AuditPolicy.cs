namespace SecReview.Probing;

/// <summary>Which outcomes of an audited activity are written to the Security log.</summary>
[Flags]
public enum AuditSetting
{
    None = 0,
    Success = 1,
    Failure = 2,
}

public interface IAuditPolicyProbe
{
    /// <summary>
    /// The effective audit setting of each subcategory (what <c>auditpol /get</c> shows).
    /// Needs administrator rights: <see cref="ProbeStatus.AccessDenied"/> otherwise.
    /// </summary>
    ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>> GetSubcategories(IReadOnlyList<Guid> subcategories);
}
