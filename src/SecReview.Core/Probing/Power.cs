namespace SecReview.Probing;

/// <summary>Timeouts of the active power plan for one power source.</summary>
/// <param name="DisplayOff">Idle time before the display turns off; null means never.</param>
/// <param name="Sleep">Idle time before the PC sleeps; null means never.</param>
/// <param name="RequirePasswordOnWake">Whether waking the PC asks for sign-in.</param>
public sealed record PowerSourceSettings(TimeSpan? DisplayOff, TimeSpan? Sleep, bool RequirePasswordOnWake);

/// <summary>The active power plan's settings that decide when an idle PC locks.</summary>
/// <param name="PluggedIn">Settings while on mains power.</param>
/// <param name="OnBattery">Settings while on battery.</param>
/// <param name="HasBattery">False for a desktop PC, where the battery settings never apply.</param>
public sealed record PowerSettings(PowerSourceSettings PluggedIn, PowerSourceSettings OnBattery, bool HasBattery);

public interface IPowerProbe
{
    ProbeResult<PowerSettings> GetSettings();
}
