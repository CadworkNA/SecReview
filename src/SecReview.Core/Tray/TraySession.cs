using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Scanning;
using SecReview.Settings;

namespace SecReview.Tray;

/// <summary>What the user, or the clock, asks of the notification-area icon.</summary>
public enum TrayCommand
{
    /// <summary>Open the window (a click on the icon, or "Open").</summary>
    Open,

    CheckNow,

    PauseHour,

    PauseDay,

    Resume,

    Quit,

    /// <summary>The notification about a check that started failing was clicked.</summary>
    NotificationClicked,

    /// <summary>The clock ticked, or the window changed something: see what is due and what to show.</summary>
    Tick,
}

/// <summary>The icon as the rules see it; Windows' own is <c>NotificationAreaIcon</c>.</summary>
public interface ITrayIcon
{
    /// <summary>Shows the icon in a state, with a tooltip and the menu that goes with it.</summary>
    void Update(TrayState state, bool darkTaskbar, string tooltip, bool paused, bool busy);

    /// <summary>Shows a notification next to the icon.</summary>
    void Notify(string title, string text);

    /// <summary>Runs an action on the icon's thread. Safe to call from any thread.</summary>
    void Post(Action action);

    /// <summary>Removes the icon and ends the process's work.</summary>
    void Quit();
}

/// <summary>What a <see cref="TraySession"/> works with.</summary>
public sealed class TrayEnvironment
{
    public required SettingsStore Settings { get; init; }

    public required ResultsStore Results { get; init; }

    /// <summary>Runs the checks an ordinary scan runs. Called off the icon's thread.</summary>
    public required Func<Task<ScanResult>> Scan { get; init; }

    public required TimeProvider Clock { get; init; }

    /// <summary>Opens the window, on a check when one is named.</summary>
    public required Action<string?> OpenWindow { get; init; }

    /// <summary>Told what went wrong and where. Must not throw.</summary>
    public required Action<string, Exception> OnError { get; init; }

    /// <summary>Whether the taskbar is dark right now.</summary>
    public Func<bool> DarkTaskbar { get; init; } = () => true;

    /// <summary>Told the settings whenever they were read, and whether the file could be read.</summary>
    public Action<AppSettings, bool>? OnSettings { get; init; }

    public IReadOnlyList<ICheck> Checks { get; init; } = CheckCatalogue.Checks;

    public CheckTexts Texts { get; init; } = CheckCatalogue.Texts;
}

/// <summary>
/// What the process behind the notification-area icon does: runs the checks again when they
/// are due, keeps the results the window shows, shows how the PC is doing on the icon, and
/// says so when a check starts failing. It shares the settings and results files with the
/// window and reads them again on every tick, so each sees what the other did.
/// </summary>
/// <remarks>Everything except the scan itself runs on the icon's thread.</remarks>
public sealed class TraySession
{
    /// <summary>How often the icon looks at the clock and the shared files.</summary>
    public static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(30);

    /// <summary>After a scan that could not run, the next one by the clock waits this long.</summary>
    public static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(15);

    private readonly ITrayIcon _icon;
    private readonly TrayEnvironment _environment;

    private AppSettings _settings = new();
    private ScanResult? _last;
    private DateTimeOffset? _lastStamp;
    private DateTimeOffset _started;
    private DateTimeOffset? _notBefore;
    private bool _scanning;
    private Task _scan = Task.CompletedTask;
    private string? _notifiedCheck;
    private (TrayState State, bool Dark, string Tooltip, bool Paused, bool Busy)? _shown;

    public TraySession(ITrayIcon icon, TrayEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(icon);
        ArgumentNullException.ThrowIfNull(environment);
        _icon = icon;
        _environment = environment;
    }

    /// <summary>Completes when no scan is running.</summary>
    public Task Idle => _scan;

    /// <summary>The last results this session knows of; null when there are none.</summary>
    public ScanResult? Last => _last;

    /// <summary>
    /// Reads what is known and shows the icon. False when the user has switched the icon
    /// off: the process then has nothing to do.
    /// </summary>
    public bool Start()
    {
        _started = _environment.Clock.GetUtcNow();
        Reload();
        if (!_settings.RunInNotificationArea)
        {
            return false;
        }

        Show();
        return true;
    }

    /// <summary>Carries out a command. Never throws: what goes wrong is handed to <see cref="TrayEnvironment.OnError"/>.</summary>
    public void Handle(TrayCommand command)
    {
        try
        {
            DateTimeOffset now = _environment.Clock.GetUtcNow();
            switch (command)
            {
                case TrayCommand.Open:
                    _environment.OpenWindow(null);
                    break;

                case TrayCommand.NotificationClicked:
                    _environment.OpenWindow(_notifiedCheck);
                    break;

                case TrayCommand.CheckNow:
                    BeginScan();
                    break;

                case TrayCommand.PauseHour:
                    Pause(now + TimeSpan.FromHours(1));
                    break;

                case TrayCommand.PauseDay:
                    Pause(now + TimeSpan.FromDays(1));
                    break;

                case TrayCommand.Resume:
                    Pause(null);
                    break;

                case TrayCommand.Quit:
                    _icon.Quit();
                    break;

                case TrayCommand.Tick:
                    Tick(now);
                    break;
            }
        }
#pragma warning disable CA1031 // The icon must outlive whatever goes wrong in one command.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _environment.OnError($"The notification-area icon could not carry out '{command}'", exception);
        }
    }

    private void Tick(DateTimeOffset now)
    {
        Reload();
        if (!_settings.RunInNotificationArea)
        {
            // Switched off in the window's settings.
            _icon.Quit();
            return;
        }

        if (!_scanning && (_notBefore is null || now >= _notBefore) && now >= TrayLogic.NextRun(_last?.FinishedAt, _settings, now, _started))
        {
            BeginScan();
        }

        Show();
    }

    private void Pause(DateTimeOffset? until)
    {
        AppSettings changed = _environment.Settings.Update(settings => settings with { SnoozedUntil = until }, out string? problem);
        if (problem is not null)
        {
            _environment.OnError("The pause could not be saved", new IOException(problem));
        }

        // Kept for this session even when it could not be saved: the user asked for it.
        _settings = changed;
        Show();
    }

    private void BeginScan()
    {
        if (_scanning)
        {
            return;
        }

        _scanning = true;
        Show();
        _scan = Task.Run(async () =>
        {
            try
            {
                ScanResult after = await _environment.Scan().ConfigureAwait(false);
                _icon.Post(() => Finished(after));
            }
#pragma warning disable CA1031 // A scan that cannot run is said on the icon; the icon stays.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                _icon.Post(() => Failed(exception));
            }
        });
    }

    private void Finished(ScanResult after)
    {
        try
        {
            DateTimeOffset now = _environment.Clock.GetUtcNow();
            ReloadSettings();

            // Read again: the window may have scanned, or run the administrator checks, meanwhile.
            ScanResult? before = _environment.Results.Load(_environment.Checks, _environment.Texts);
            ScanResult kept = TrayLogic.Merge(before, after, now);
            if (!_environment.Results.Save(kept))
            {
                _environment.OnError("The results could not be saved", new IOException("Writing the results file failed."));
            }

            _last = kept;
            _lastStamp = _environment.Results.Stamp();
            _notBefore = null;

            IReadOnlyList<ScannedCheck> news = TrayLogic.NewFailures(before, kept, _settings.IgnoredIds());
            if (_settings.NotifyNewFailures && !TrayLogic.IsSnoozed(_settings, now) && TrayLogic.Notification(news) is { } notification)
            {
                _notifiedCheck = news.Count == 1 ? news[0].Definition.Id : null;
                _icon.Notify(notification.Title, notification.Text);
            }
        }
#pragma warning disable CA1031 // Posted to the icon's thread, where nothing may be thrown.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _environment.OnError("The scan's results could not be taken in", exception);
        }
        finally
        {
            _scanning = false;
            Show();
        }
    }

    private void Failed(Exception exception)
    {
        _scanning = false;
        _notBefore = _environment.Clock.GetUtcNow() + RetryAfterFailure;
        _environment.OnError("The scan could not run", exception);
        Show();
    }

    private void Reload()
    {
        ReloadSettings();

        DateTimeOffset? stamp = _environment.Results.Stamp();
        if (stamp != _lastStamp)
        {
            _lastStamp = stamp;
            _last = _environment.Results.Load(_environment.Checks, _environment.Texts) ?? _last;
        }
    }

    private void ReloadSettings()
    {
        AppSettings read = _environment.Settings.Load(out string? problem);

        // A file that could not be read just now says nothing; what was read before stands.
        if (problem is null)
        {
            _settings = read;
        }

        _environment.OnSettings?.Invoke(_settings, problem is null);
    }

    /// <summary>Brings the icon in line with what is known. Does nothing when it already is.</summary>
    private void Show()
    {
        DateTimeOffset now = _environment.Clock.GetUtcNow();
        IReadOnlySet<string> ignored = _settings.IgnoredIds();
        bool snoozed = TrayLogic.IsSnoozed(_settings, now);
        (TrayState, bool, string, bool, bool) wanted = (
            TrayLogic.State(_last, ignored, snoozed, stale: _last is not null && TrayLogic.IsStale(_last, _settings, now)),
            _environment.DarkTaskbar(),
            TrayLogic.Tooltip(_last, ignored, _settings, now, _scanning),
            snoozed,
            _scanning);
        if (_shown != wanted)
        {
            _shown = wanted;
            _icon.Update(wanted.Item1, wanted.Item2, wanted.Item3, wanted.Item4, wanted.Item5);
        }
    }
}
