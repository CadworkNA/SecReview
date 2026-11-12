using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.UpdateAgent;
using Windows.Win32.System.Variant;

namespace SecReview.Probing.Windows;

/// <summary>
/// Asks the Windows Update agent (its COM interface) how updates are handled, when it last
/// searched and installed, and whether a restart is pending. No update search is started and
/// nothing is changed.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsUpdateProbe : IWindowsUpdateProbe
{
    private const string What = "Asking Windows Update";

    public unsafe ProbeResult<WindowsUpdateStatus> GetStatus()
    {
        using ComScope com = ComScope.Enter();

        IAutomaticUpdates2* updates = null;
        IAutomaticUpdatesSettings* settings = null;
        IAutomaticUpdatesResults* results = null;
        ISystemInformation* system = null;
        try
        {
            HRESULT created = AutomaticUpdates.CreateInstance(out updates);
            if (created.Failed)
            {
                return WindowsError.FromHResult(created.Value, What);
            }

            created = SystemInformation.CreateInstance(out system);
            if (created.Failed)
            {
                return WindowsError.FromHResult(created.Value, What);
            }

            // ServiceEnabled only says the update components are usable. Whether updating is
            // turned on is the notification level.
            bool serviceAvailable = updates->ServiceEnabled != VARIANT_BOOL.VARIANT_FALSE;
            settings = updates->Settings;
            AutomaticUpdateMode? mode = ToMode(settings->NotificationLevel);
            if (mode is null)
            {
                return ProbeFailure.Failed($"{What} failed: unknown update setting.");
            }

            bool rebootRequired = system->RebootRequired != VARIANT_BOOL.VARIANT_FALSE;

            results = updates->Results;
            if (TakeDate(results->LastSearchSuccessDate, out DateTimeOffset? lastSearch) is { } searchFailed)
            {
                return searchFailed;
            }

            if (TakeDate(results->LastInstallationSuccessDate, out DateTimeOffset? lastInstall) is { } installFailed)
            {
                return installFailed;
            }

            return ProbeResult<WindowsUpdateStatus>.Ok(new WindowsUpdateStatus(
                mode.Value, serviceAvailable, rebootRequired, lastSearch, lastInstall));
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (results is not null)
            {
                results->Release();
            }

            if (settings is not null)
            {
                settings->Release();
            }

            if (system is not null)
            {
                system->Release();
            }

            if (updates is not null)
            {
                updates->Release();
            }
        }
    }

    private static AutomaticUpdateMode? ToMode(AutomaticUpdatesNotificationLevel level) => level switch
    {
        AutomaticUpdatesNotificationLevel.aunlNotConfigured => AutomaticUpdateMode.NotConfigured,
        AutomaticUpdatesNotificationLevel.aunlDisabled => AutomaticUpdateMode.Disabled,
        AutomaticUpdatesNotificationLevel.aunlNotifyBeforeDownload => AutomaticUpdateMode.NotifyBeforeDownload,
        AutomaticUpdatesNotificationLevel.aunlNotifyBeforeInstallation => AutomaticUpdateMode.NotifyBeforeInstall,
        AutomaticUpdatesNotificationLevel.aunlScheduledInstallation => AutomaticUpdateMode.Scheduled,
        _ => null,
    };

    /// <summary>
    /// The agent returns a UTC date, or an empty value when there has been none. Only an empty
    /// value means "never": anything else that is not a valid date is a failed reading.
    /// </summary>
    /// <returns>Null when the reading worked (<paramref name="date"/> is null for "never"), else the failure.</returns>
    private static ProbeFailure? TakeDate(VARIANT value, out DateTimeOffset? date)
    {
        date = null;
        try
        {
            VARENUM type = value.Anonymous.Anonymous.vt;
            if (type is VARENUM.VT_EMPTY or VARENUM.VT_NULL)
            {
                return null;
            }

            if (type != VARENUM.VT_DATE)
            {
                return ProbeFailure.Failed($"{What} failed: a date came back as type {(int)type}.");
            }

            date = WindowsUpdateDates.FromAutomationDate(value.Anonymous.Anonymous.Anonymous.date);
            return null;
        }
        catch (ArgumentException)
        {
            return ProbeFailure.Failed($"{What} failed: a date was not valid.");
        }
        finally
        {
            _ = PInvoke.VariantClear(ref value);
        }
    }
}
