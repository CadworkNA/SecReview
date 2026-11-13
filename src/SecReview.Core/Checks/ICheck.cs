using SecReview.Probing;

namespace SecReview.Checks;

/// <summary>What a check is, apart from its wording (which lives in the check catalogue).</summary>
/// <param name="Id">Stable identifier, for example "firewall.enabled". Never reused or renamed.</param>
/// <param name="Category">The group it is shown under.</param>
/// <param name="Severity">How much a failure matters.</param>
/// <param name="NeedsAdmin">Whether administrator rights are needed.</param>
/// <param name="Scope">Whether it reads the machine or the signed-in user.</param>
/// <param name="KeepsAdministratorAnswer">
/// For a check that goes through a list and reads most of it as a normal user: when an ordinary
/// scan finds no problem and can only say that the rest needs administrator rights, the answer
/// of an earlier administrator scan says more and stays on screen, as it does for a check that
/// only an elevated scan answers. An ordinary scan that finds a problem always shows it.
/// </param>
public sealed record CheckDefinition(
    string Id,
    CheckCategory Category,
    Severity Severity,
    AdminNeed NeedsAdmin = AdminNeed.No,
    CheckScope Scope = CheckScope.Machine,
    bool KeepsAdministratorAnswer = false);

/// <summary>What a check gets to work with.</summary>
/// <param name="Probes">How to read the machine.</param>
/// <param name="Clock">The current time (a fake in tests).</param>
/// <param name="IsElevated">Whether this run has administrator rights.</param>
/// <param name="Cancellation">Signalled when the run is abandoned.</param>
public sealed record CheckContext(
    SystemProbes Probes,
    TimeProvider Clock,
    bool IsElevated,
    CancellationToken Cancellation);

/// <summary>
/// One security check. It only reads, through <see cref="CheckContext.Probes"/>, and returns
/// what it found. It must not throw for an expected condition; the runner turns an unexpected
/// exception or a timeout into "could not check".
/// </summary>
public interface ICheck
{
    CheckDefinition Definition { get; }

    CheckOutcome Run(CheckContext context);
}
