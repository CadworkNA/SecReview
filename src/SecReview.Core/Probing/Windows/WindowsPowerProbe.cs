using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Power;
using Windows.Win32.System.Registry;

namespace SecReview.Probing.Windows;

/// <summary>Reads the active power plan (what <c>powercfg /query</c> shows).</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsPowerProbe : IPowerProbe
{
    private const string What = "Reading the power plan";

    /// <summary>SYSTEM_POWER_STATUS.BatteryFlag bit: the PC has no battery.</summary>
    private const byte NoSystemBattery = 128;

    // Setting identifiers documented for powercfg (SUB_VIDEO/VIDEOIDLE, SUB_SLEEP/STANDBYIDLE,
    // SUB_NONE/CONSOLELOCK).
    private static readonly Guid VideoSubgroup = new("7516b95f-f776-4464-8c53-06167f40cc99");
    private static readonly Guid VideoIdleTimeout = new("3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e");
    private static readonly Guid SleepSubgroup = new("238c9fa8-0aad-41ed-83f4-97be242c8f20");
    private static readonly Guid StandbyIdleTimeout = new("29f6c1db-86da-48c5-9fdb-f2b67b1f44da");
    private static readonly Guid NoSubgroup = new("fea3413e-7e05-4911-9a71-700331f1c294");
    private static readonly Guid ConsoleLock = new("0e796bdb-100d-47d6-a2d5-f7d2daa51f51");

    private delegate uint ReadValue(HKEY root, Guid? scheme, Guid? subgroup, Guid? setting, out uint value);

    public unsafe ProbeResult<PowerSettings> GetSettings()
    {
        Guid* activeScheme = null;
        try
        {
            uint error = (uint)PInvoke.PowerGetActiveScheme(default, out activeScheme);
            if (error != 0)
            {
                return WindowsError.FromWin32((int)error, What);
            }

            Guid scheme = *activeScheme;

            ProbeResult<PowerSourceSettings> pluggedIn = ReadSource(scheme, ReadPluggedIn);
            if (!pluggedIn.IsOk)
            {
                return pluggedIn.ToFailure();
            }

            ProbeResult<PowerSourceSettings> onBattery = ReadSource(scheme, ReadOnBattery);
            if (!onBattery.IsOk)
            {
                return onBattery.ToFailure();
            }

            if (!PInvoke.GetSystemPowerStatus(out SYSTEM_POWER_STATUS status))
            {
                return WindowsError.FromWin32(Marshal.GetLastPInvokeError(), What);
            }

            bool hasBattery = (status.BatteryFlag & NoSystemBattery) == 0;
            return ProbeResult<PowerSettings>.Ok(new PowerSettings(pluggedIn.Value!, onBattery.Value!, hasBattery));
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (activeScheme is not null)
            {
                PInvoke.LocalFree((HLOCAL)(void*)activeScheme);
            }
        }
    }

    private static uint ReadPluggedIn(HKEY root, Guid? scheme, Guid? subgroup, Guid? setting, out uint value) =>
        (uint)PInvoke.PowerReadACValueIndex(root, scheme, subgroup, setting, out value);

    private static uint ReadOnBattery(HKEY root, Guid? scheme, Guid? subgroup, Guid? setting, out uint value) =>
        PInvoke.PowerReadDCValueIndex(root, scheme, subgroup, setting, out value);

    private static ProbeResult<PowerSourceSettings> ReadSource(Guid scheme, ReadValue read)
    {
        uint error = read(default, scheme, VideoSubgroup, VideoIdleTimeout, out uint displaySeconds);
        if (error != 0)
        {
            return WindowsError.FromWin32((int)error, What);
        }

        error = read(default, scheme, SleepSubgroup, StandbyIdleTimeout, out uint sleepSeconds);
        if (error != 0)
        {
            return WindowsError.FromWin32((int)error, What);
        }

        error = read(default, scheme, NoSubgroup, ConsoleLock, out uint consoleLock);
        if (error != 0)
        {
            return WindowsError.FromWin32((int)error, What);
        }

        return ProbeResult<PowerSourceSettings>.Ok(new PowerSourceSettings(
            DisplayOff: SecondsOrNever(displaySeconds),
            Sleep: SecondsOrNever(sleepSeconds),
            RequirePasswordOnWake: consoleLock != 0));
    }

    /// <summary>The power plan stores "never" as zero seconds.</summary>
    private static TimeSpan? SecondsOrNever(uint seconds) => seconds == 0 ? null : TimeSpan.FromSeconds(seconds);
}
