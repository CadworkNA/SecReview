using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.UpdateAgent;
using Windows.Win32.System.Variant;

namespace SecReview.Probing.Windows;

/// <summary>
/// Asks the Windows Update agent (its COM interface) whether automatic updates are enabled,
/// when it last searched and installed, and whether a restart is pending. No update search is
/// started and nothing is changed.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsUpdateProbe : IWindowsUpdateProbe
{
    private const string What = "Asking Windows Update";

    public unsafe ProbeResult<WindowsUpdateStatus> GetStatus()
    {
        using ComScope com = ComScope.Enter();

        IAutomaticUpdates2* updates = null;
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

            bool enabled = updates->ServiceEnabled != VARIANT_BOOL.VARIANT_FALSE;
            bool rebootRequired = system->RebootRequired != VARIANT_BOOL.VARIANT_FALSE;

            results = updates->Results;
            DateTimeOffset? lastSearch = TakeDate(results->LastSearchSuccessDate);
            DateTimeOffset? lastInstall = TakeDate(results->LastInstallationSuccessDate);

            return ProbeResult<WindowsUpdateStatus>.Ok(
                new WindowsUpdateStatus(enabled, rebootRequired, lastSearch, lastInstall));
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

    /// <summary>The agent returns dates in UTC, or an empty value when there is none.</summary>
    private static DateTimeOffset? TakeDate(VARIANT value)
    {
        try
        {
            if (value.Anonymous.Anonymous.vt != VARENUM.VT_DATE)
            {
                return null;
            }

            double automationDate = value.Anonymous.Anonymous.Anonymous.date;
            return new DateTimeOffset(DateTime.FromOADate(automationDate), TimeSpan.Zero);
        }
        catch (ArgumentException)
        {
            // Not a valid automation date: treat as "no date".
            return null;
        }
        finally
        {
            _ = PInvoke.VariantClear(ref value);
        }
    }
}
