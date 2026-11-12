using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.NetworkManagement.NetManagement;

namespace SecReview.Probing.Windows;

/// <summary>Reads the local password and lockout policy with <c>NetUserModalsGet</c>.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsAccountPolicyProbe : IAccountPolicyProbe
{
    private const string What = "Reading the password policy";

    /// <summary>The API's marker for "no limit" (TIMEQ_FOREVER).</summary>
    private const uint Forever = uint.MaxValue;

    public unsafe ProbeResult<AccountPolicy> GetPolicy()
    {
        byte* passwordBuffer = null;
        byte* lockoutBuffer = null;
        try
        {
            uint error = PInvoke.NetUserModalsGet(null, 0, out passwordBuffer);
            if (error != 0)
            {
                return WindowsError.FromWin32((int)error, What);
            }

            error = PInvoke.NetUserModalsGet(null, 3, out lockoutBuffer);
            if (error != 0)
            {
                return WindowsError.FromWin32((int)error, What);
            }

            USER_MODALS_INFO_0 password = *(USER_MODALS_INFO_0*)passwordBuffer;
            USER_MODALS_INFO_3 lockout = *(USER_MODALS_INFO_3*)lockoutBuffer;

            return ProbeResult<AccountPolicy>.Ok(new AccountPolicy(
                MinimumPasswordLength: (int)password.usrmod0_min_passwd_len,
                MaximumPasswordAge: SecondsOrNull(password.usrmod0_max_passwd_age),
                MinimumPasswordAge: TimeSpan.FromSeconds(password.usrmod0_min_passwd_age),
                PasswordHistoryLength: (int)password.usrmod0_password_hist_len,
                LockoutThreshold: (int)lockout.usrmod3_lockout_threshold,
                LockoutDuration: SecondsOrNull(lockout.usrmod3_lockout_duration),
                LockoutObservationWindow: TimeSpan.FromSeconds(lockout.usrmod3_lockout_observation_window)));
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (passwordBuffer is not null)
            {
                _ = PInvoke.NetApiBufferFree(passwordBuffer);
            }

            if (lockoutBuffer is not null)
            {
                _ = PInvoke.NetApiBufferFree(lockoutBuffer);
            }
        }
    }

    private static TimeSpan? SecondsOrNull(uint seconds) =>
        seconds == Forever ? null : TimeSpan.FromSeconds(seconds);
}
