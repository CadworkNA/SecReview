namespace SecReview.Probing;

/// <summary>What the Windows Update agent reports about itself.</summary>
/// <param name="AutomaticUpdatesEnabled">Whether the automatic update service is enabled.</param>
/// <param name="RebootRequired">Whether installed updates are waiting for a restart.</param>
/// <param name="LastSuccessfulSearch">When Windows last checked for updates successfully; null if never.</param>
/// <param name="LastSuccessfulInstall">When Windows last installed updates successfully; null if never.</param>
public sealed record WindowsUpdateStatus(
    bool AutomaticUpdatesEnabled,
    bool RebootRequired,
    DateTimeOffset? LastSuccessfulSearch,
    DateTimeOffset? LastSuccessfulInstall);

public interface IWindowsUpdateProbe
{
    ProbeResult<WindowsUpdateStatus> GetStatus();
}
