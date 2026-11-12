namespace SecReview.Probing;

/// <summary>An account or group, by security identifier and, when it resolves, by name.</summary>
/// <param name="Sid">For example "S-1-5-32-544".</param>
/// <param name="Name">For example "BUILTIN\Administrators"; null if the identifier has no name here.</param>
public sealed record AccountReference(string Sid, string? Name);

public interface IUserRightsProbe
{
    /// <summary>
    /// The accounts that hold a user right such as "SeDebugPrivilege" (the "User Rights
    /// Assignment" policy). An empty list means nobody holds it. Needs administrator rights:
    /// <see cref="ProbeStatus.AccessDenied"/> otherwise.
    /// </summary>
    ProbeResult<IReadOnlyList<AccountReference>> GetAccountsWithRight(string right);
}
