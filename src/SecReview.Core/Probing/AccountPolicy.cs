namespace SecReview.Probing;

/// <summary>The local password and lockout policy (what <c>net accounts</c> shows).</summary>
/// <param name="MinimumPasswordLength">Characters; 0 allows an empty password.</param>
/// <param name="MaximumPasswordAge">Null when passwords never expire.</param>
/// <param name="MinimumPasswordAge">Zero when a password may be changed at once.</param>
/// <param name="PasswordHistoryLength">Previous passwords that cannot be reused.</param>
/// <param name="LockoutThreshold">Failed sign-ins before lockout; 0 means never locked out.</param>
/// <param name="LockoutDuration">Null when a locked account stays locked until an administrator unlocks it.</param>
/// <param name="LockoutObservationWindow">Time after which the failed sign-in count resets.</param>
public sealed record AccountPolicy(
    int MinimumPasswordLength,
    TimeSpan? MaximumPasswordAge,
    TimeSpan MinimumPasswordAge,
    int PasswordHistoryLength,
    int LockoutThreshold,
    TimeSpan? LockoutDuration,
    TimeSpan LockoutObservationWindow);

public interface IAccountPolicyProbe
{
    ProbeResult<AccountPolicy> GetPolicy();
}
