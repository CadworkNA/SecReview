namespace SecReview.Probing;

/// <summary>How Windows is set to handle updates (the update agent's notification level).</summary>
public enum AutomaticUpdateMode
{
    /// <summary>Nothing is configured; Windows uses its default, which installs automatically.</summary>
    NotConfigured,

    /// <summary>Automatic updating is turned off.</summary>
    Disabled,

    /// <summary>Windows asks before downloading.</summary>
    NotifyBeforeDownload,

    /// <summary>Windows downloads, then asks before installing.</summary>
    NotifyBeforeInstall,

    /// <summary>Windows downloads and installs on a schedule.</summary>
    Scheduled,
}

/// <summary>What the Windows Update agent reports about itself.</summary>
/// <param name="Mode">How updates are handled.</param>
/// <param name="ServiceAvailable">Whether the update service and its components are present and usable.</param>
/// <param name="RebootRequired">Whether installed updates are waiting for a restart.</param>
/// <param name="LastSuccessfulSearch">When Windows last checked for updates successfully; null if never.</param>
/// <param name="LastSuccessfulInstall">When Windows last installed updates successfully; null if never.</param>
public sealed record WindowsUpdateStatus(
    AutomaticUpdateMode Mode,
    bool ServiceAvailable,
    bool RebootRequired,
    DateTimeOffset? LastSuccessfulSearch,
    DateTimeOffset? LastSuccessfulInstall);

public interface IWindowsUpdateProbe
{
    ProbeResult<WindowsUpdateStatus> GetStatus();
}
