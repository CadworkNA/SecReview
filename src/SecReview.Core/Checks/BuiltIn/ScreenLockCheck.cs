using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// An idle PC must lock itself within <see cref="MaximumIdle"/>, on mains power and on battery.
/// Windows has several ways to get there, and the earliest one that applies counts:
/// <list type="bullet">
/// <item>the machine inactivity limit, which also locks as soon as the display turns off;</item>
/// <item>a screen saver that asks for sign-in (it needs a screen saver program to be set);</item>
/// <item>sleep, when waking asks for sign-in;</item>
/// <item>on a Modern Standby PC, the display turning off, when waking asks for sign-in; the
/// user's "when should Windows require you to sign in again" delay is added.</item>
/// </list>
/// </summary>
public sealed class ScreenLockCheck : ICheck
{
    public const string Id = "lock.screen";

    public static readonly TimeSpan MaximumIdle = TimeSpan.FromMinutes(15);

    internal const string SystemPolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    internal const string InactivityValue = "InactivityTimeoutSecs";
    internal const string DesktopKey = @"Control Panel\Desktop";
    internal const string DesktopPolicyKey = @"Software\Policies\Microsoft\Windows\Control Panel\Desktop";
    internal const string DelayValue = "DelayLockInterval";

    private const string What = "the screen lock settings";
    private const string Expected = "15 min or less";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.Access, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;

        ProbeResult<PowerSettings> powerRead = context.Probes.Power.GetSettings();
        if (!powerRead.IsOk)
        {
            return ProbeOutcomes.FromFailure(powerRead, "the power settings");
        }

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, SystemPolicyKey, InactivityValue, What, out long? limitSeconds) is { } f1)
        {
            return f1;
        }

        if (ScreenSaver(registry, out TimeSpan? screenSaver) is { } f2)
        {
            return f2;
        }

        if (RegistryReader.Number(registry, RegistryRoot.CurrentUser, DesktopKey, DelayValue, What, out long? delaySeconds) is { } f3)
        {
            return f3;
        }

        PowerSettings power = powerRead.Value!;
        TimeSpan? limit = limitSeconds is > 0 ? TimeSpan.FromSeconds(limitSeconds.Value) : null;
        TimeSpan delay = TimeSpan.FromSeconds(Math.Clamp(delaySeconds ?? 0, 0, int.MaxValue));

        (TimeSpan After, string Because)? pluggedIn = LocksAfter(power.PluggedIn, power.ModernStandby, limit, screenSaver, delay);
        (TimeSpan After, string Because)? onBattery = LocksAfter(power.OnBattery, power.ModernStandby, limit, screenSaver, delay);

        var findings = new List<Finding> { Row(power.HasBattery ? "Plugged in" : "When idle", pluggedIn) };
        if (power.HasBattery)
        {
            findings.Add(Row("On battery", onBattery));
        }

        findings.Add(Finding.Note(
            "Inactivity limit", limit is { } l ? Wording.Duration(l) : "Not set", $@"HKLM\{SystemPolicyKey}\{InactivityValue}"));
        findings.Add(Finding.Note(
            "Screen saver that asks for sign-in", screenSaver is { } s ? $"After {Wording.Duration(s)}" : "Off"));
        if (!power.PluggedIn.RequirePasswordOnWake || (power.HasBattery && !power.OnBattery.RequirePasswordOnWake))
        {
            findings.Add(Finding.Note("Sign-in when the PC wakes", "Not required"));
        }

        bool pluggedInFine = pluggedIn is { } p && p.After <= MaximumIdle;
        bool onBatteryFine = !power.HasBattery || (onBattery is { } b && b.After <= MaximumIdle);
        if (pluggedInFine && onBatteryFine)
        {
            TimeSpan longest = power.HasBattery && onBattery!.Value.After > pluggedIn!.Value.After
                ? onBattery.Value.After
                : pluggedIn!.Value.After;
            return CheckOutcome.Pass($"This PC locks after {Wording.Duration(longest)} without use.", findings);
        }

        if (!power.HasBattery)
        {
            return CheckOutcome.Fail($"This PC {Problem(pluggedIn)}.", findings);
        }

        if (!pluggedInFine && !onBatteryFine)
        {
            return CheckOutcome.Fail(
                pluggedIn?.After == onBattery?.After
                    ? $"This PC {Problem(pluggedIn)}."
                    : $"This PC {Problem(pluggedIn)} when plugged in and {Problem(onBattery)} on battery.",
                findings);
        }

        return CheckOutcome.Fail(
            pluggedInFine ? $"On battery, this PC {Problem(onBattery)}." : $"When plugged in, this PC {Problem(pluggedIn)}.",
            findings);
    }

    private static string Problem((TimeSpan After, string Because)? lockTime) => lockTime is { } time
        ? $"locks only after {Wording.Duration(time.After)} without use"
        : "never locks by itself";

    private static Finding Row(string item, (TimeSpan After, string Because)? lockTime)
    {
        if (lockTime is not { } time)
        {
            return Finding.Problem(item, "Never locks", Expected);
        }

        string found = $"Locks after {Wording.Duration(time.After)} ({time.Because})";
        return time.After <= MaximumIdle ? Finding.Ok(item, found, Expected) : Finding.Problem(item, found, Expected);
    }

    /// <summary>The earliest way an idle PC locks on this power source, or null if none does.</summary>
    private static (TimeSpan After, string Because)? LocksAfter(
        PowerSourceSettings source, bool modernStandby, TimeSpan? limit, TimeSpan? screenSaver, TimeSpan delay)
    {
        var ways = new List<(TimeSpan After, string Because)>(4);
        if (limit is { } inactivity)
        {
            ways.Add((inactivity, "inactivity limit"));
        }

        if (screenSaver is { } saver)
        {
            ways.Add((saver, "screen saver"));
        }

        if (source.Sleep is { } sleep && source.RequirePasswordOnWake)
        {
            ways.Add((sleep, "sleep"));
        }

        if (source.DisplayOff is { } displayOff)
        {
            if (limit is not null)
            {
                // With an inactivity limit, Windows also locks when the display turns off.
                ways.Add((displayOff, "display turns off"));
            }
            else if (modernStandby && source.RequirePasswordOnWake)
            {
                ways.Add((displayOff + delay, "display turns off"));
            }
        }

        return ways.Count == 0 ? null : ways.MinBy(w => w.After);
    }

    /// <summary>
    /// When the screen saver locks the PC, or null if it does not: it must be on, ask for
    /// sign-in, have a program set and a timeout. A policy value wins over the user's own.
    /// </summary>
    private static CheckOutcome? ScreenSaver(IRegistryProbe registry, out TimeSpan? after)
    {
        after = null;

        if (Setting(registry, "ScreenSaveActive", out string? active) is { } f1)
        {
            return f1;
        }

        if (Setting(registry, "ScreenSaverIsSecure", out string? secure) is { } f2)
        {
            return f2;
        }

        if (Setting(registry, "ScreenSaveTimeOut", out string? timeout) is { } f3)
        {
            return f3;
        }

        if (Setting(registry, "SCRNSAVE.EXE", out string? program) is { } f4)
        {
            return f4;
        }

        if (active == "1" && secure == "1" && program is not null &&
            int.TryParse(timeout, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int seconds) &&
            seconds > 0)
        {
            after = TimeSpan.FromSeconds(seconds);
        }

        return null;
    }

    /// <summary>A screen saver setting as text: the policy value if there is one, else the user's.</summary>
    private static CheckOutcome? Setting(IRegistryProbe registry, string name, out string? value)
    {
        value = null;
        foreach (string key in (string[])[DesktopPolicyKey, DesktopKey])
        {
            ProbeResult<RegistryValue> result = registry.GetValue(RegistryRoot.CurrentUser, key, name);
            if (result.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!result.IsOk)
            {
                return ProbeOutcomes.FromFailure(result, What);
            }

            // Windows writes these as text; a policy may write a number.
            value = result.Value!.Type switch
            {
                RegistryValueType.Text => result.Value.Text.Trim(),
                RegistryValueType.Number => result.Value.Number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                _ => null,
            };
            if (value is { Length: 0 })
            {
                value = null;
            }

            return null;
        }

        return null;
    }
}
