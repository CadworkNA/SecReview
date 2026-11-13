using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Elevation;
using SecReview.Instances;
using SecReview.Probing.Windows;
using SecReview.Reporting;
using SecReview.Scanning;
using SecReview.Settings;
using SecReview.Updates;

namespace SecReview.App.ViewModels;

/// <summary>
/// What the main window shows: a headline, the checks in groups, and whether a scan is running.
/// The last results are shown at once; a new scan then replaces them check by check.
/// </summary>
public sealed partial class MainViewModel : INotifyPropertyChanged
{
    /// <summary>While results arrive, the list is redrawn at most this often.</summary>
    private static readonly TimeSpan RedrawInterval = TimeSpan.FromMilliseconds(250);

    private readonly UiRole _role;
    private readonly AppLog _log;
    private readonly Action<Action> _onWindowThread;
    private readonly ErrorReporter _reporter;
    private readonly bool _previousRunCrashed;
    private readonly SettingsStore? _settingsStore;
    private readonly ResultsStore? _resultsStore;

    /// <summary>The newest answer per check; empty until there are results.</summary>
    private readonly Dictionary<string, ScannedCheck> _results = new(StringComparer.Ordinal);
    private readonly HashSet<string> _beingChecked = new(StringComparer.Ordinal);

    /// <summary>Rows to open the next time they are drawn, whatever state they were in.</summary>
    private readonly HashSet<string> _openNext = new(StringComparer.Ordinal);

    private AppSettings _settings = new();
    private DateTimeOffset? _finishedAt;
    private bool _elevated;
    private ScanFilter _filter = ScanFilter.All;
    private long _lastRedraw;
    private bool _redrawPending;
    private long _lastAgeShown;

    /// <summary>The results file as this window last read or wrote it; another stamp means the icon saved since.</summary>
    private DateTimeOffset? _resultsStamp;
    private long _lastLookAtDisk;

    private string _headline = "Checking this PC…";
    private string _detail = string.Empty;
    private bool _isBusy;
    private bool _hasFailed;
    private string _failure = string.Empty;
    private string _notice = string.Empty;
    private string _settingsProblem = string.Empty;
    private string _emptyText = string.Empty;
    private bool _showFirstRun;
    private bool _administratorBusy;
    private string _administratorProblem = string.Empty;
    private readonly UpdateService? _updates;
    private UpdateState _update = new();
    private string _updateMessage = string.Empty;
    private string _updateProblem = string.Empty;
    private bool _updateBusy;

    /// <summary>Why the administrator checks cannot be run from this copy; null when they can.</summary>
    private readonly string? _administratorUnavailable;

    /// <param name="role">How the window was started.</param>
    /// <param name="log">The local log.</param>
    /// <param name="onWindowThread">Runs an action on the window's thread; results arrive on others.</param>
    /// <param name="reporter">Reports errors of SecReview itself, when that is on.</param>
    /// <param name="previousRunCrashed">Whether the previous run never closed down.</param>
    internal MainViewModel(UiRole role, AppLog log, Action<Action> onWindowThread, ErrorReporter reporter, bool previousRunCrashed)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(onWindowThread);
        ArgumentNullException.ThrowIfNull(reporter);

        _role = role;
        _log = log;
        _onWindowThread = onWindowThread;
        _reporter = reporter;
        _previousRunCrashed = previousRunCrashed;

        // Made-up results are never written anywhere and never mixed with real ones.
        if (!role.Demo)
        {
            _settingsStore = new SettingsStore(AppData.Directory);
            _resultsStore = new ResultsStore(AppData.Directory);
            if (WindowsProbes.IsSupported)
            {
                _updates = UpdateService.ForThisBuild(AppData.Directory, WindowsProbes.Create().Registry);
            }

            _administratorUnavailable = WindowsProbes.IsSupported
                ? AdministratorScan.WhyUnavailable(
                    AppContext.BaseDirectory,
                    new[]
                    {
                        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    },
                    File.Exists,
                    WindowsProbes.Create().Access)
                : $"SecReview needs {WindowsProbes.MinimumWindowsName} or later.";
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// The groups (<see cref="SectionItem"/>). Typed as objects because WinUI list controls reject a
    /// collection of a custom type ("not a supported vector").
    /// </summary>
    public ObservableCollection<object> Sections { get; } = [];

    public string Headline
    {
        get => _headline;
        private set => Set(ref _headline, value, nameof(Headline));
    }

    /// <summary>The line under the headline: counts and when the scan finished.</summary>
    public string Detail
    {
        get => _detail;
        private set => Set(ref _detail, value, nameof(Detail));
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (Set(ref _isBusy, value, nameof(IsBusy)))
            {
                Changed(nameof(CanRun));
            }
        }
    }

    /// <summary>A scan can start when none is running and no single check is being run again.</summary>
    public bool CanRun => !IsBusy && !_administratorBusy && _beingChecked.Count == 0;

    /// <summary>
    /// Whether the button for the administrator checks is shown: when this copy can run them.
    /// Made-up results show it too, so it can be looked at; pressing it does nothing there.
    /// </summary>
    public bool ShowAdministratorButton => _role.Demo || _administratorUnavailable is null;

    /// <summary>Whether the administrator checks can be started right now.</summary>
    public bool CanRunAdministratorChecks => ShowAdministratorButton && CanRun && HasResults;

    /// <summary>What went wrong with the administrator checks; empty when nothing did.</summary>
    public string AdministratorProblem
    {
        get => _administratorProblem;
        private set
        {
            if (Set(ref _administratorProblem, value, nameof(AdministratorProblem)))
            {
                Changed(nameof(HasAdministratorProblem));
            }
        }
    }

    public bool HasAdministratorProblem => AdministratorProblem.Length > 0;

    /// <summary>True when the scan itself could not run; <see cref="Failure"/> says why.</summary>
    public bool HasFailed
    {
        get => _hasFailed;
        private set => Set(ref _hasFailed, value, nameof(HasFailed));
    }

    public string Failure
    {
        get => _failure;
        private set => Set(ref _failure, value, nameof(Failure));
    }

    /// <summary>What is worth saying above the list, for example that some checks wait for administrator rights.</summary>
    public string Notice
    {
        get => _notice;
        private set
        {
            if (Set(ref _notice, value, nameof(Notice)))
            {
                Changed(nameof(HasNotice));
            }
        }
    }

    public bool HasNotice => Notice.Length > 0;

    /// <summary>Why the saved settings could not be used or written; empty when all is well.</summary>
    public string SettingsProblem
    {
        get => _settingsProblem;
        private set
        {
            if (Set(ref _settingsProblem, value, nameof(SettingsProblem)))
            {
                Changed(nameof(HasSettingsProblem));
            }
        }
    }

    public bool HasSettingsProblem => SettingsProblem.Length > 0;

    /// <summary>Shown in place of the list when the chosen filter has nothing to show.</summary>
    public string EmptyText
    {
        get => _emptyText;
        private set
        {
            if (Set(ref _emptyText, value, nameof(EmptyText)))
            {
                Changed(nameof(IsEmpty));
            }
        }
    }

    public bool IsEmpty => EmptyText.Length > 0;

    /// <summary>Whether there are results to filter and list.</summary>
    public bool HasResults => _results.Count > 0;

    /// <summary>Whether the notice of the very first start is on screen.</summary>
    public bool ShowFirstRun
    {
        get => _showFirstRun;
        private set => Set(ref _showFirstRun, value, nameof(ShowFirstRun));
    }

    /// <summary>What the first-run notice says. It names error reporting only when that is on.</summary>
    public string FirstRunMessage =>
        "It checks this PC's security settings and explains what it finds. It never changes a setting, and the results stay on this PC." +
        (_reporter.State is ErrorReportsState.On or ErrorReportsState.NotYetKnown
            ? " Once you close this notice, errors of SecReview itself are reported to its developers, never your results; Settings has the switch."
            : string.Empty);

    /// <summary>Whether error reports are on right now.</summary>
    public bool ErrorReportsOn => _reporter.State == ErrorReportsState.On;

    /// <summary>Whether the user's switch decides: not when the build has nowhere to send, or the organisation said no.</summary>
    public bool CanChangeErrorReports => _reporter.State is ErrorReportsState.On or ErrorReportsState.OffBySetting or ErrorReportsState.NotYetKnown;

    /// <summary>Where the user has left the switch, whether or not reports are being sent yet.</summary>
    public bool ErrorReportsSwitch => _settings.SendErrorReports;

    /// <summary>The state of error reporting in a sentence.</summary>
    public string ErrorReportsDescription => ErrorReports.Describe(_reporter.State);

    /// <summary>Whether "Send feedback" has somewhere to go. Made-up results show it so it can be looked at; nothing is sent.</summary>
    public bool CanSendFeedback => _role.Demo || _reporter.State == ErrorReportsState.On;

    public string AllLabel => Label("All", ScanFilter.All);

    public string AttentionLabel => Label("Needs attention", ScanFilter.NeedsAttention);

    public string AdminLabel => Label("Needs administrator", ScanFilter.NeedsAdmin);

    public string PassedLabel => Label("Passed", ScanFilter.Passed);

    public string IgnoredLabel => Label("Ignored", ScanFilter.Ignored);

    public ScanFilter Filter
    {
        get => _filter;
        set
        {
            if (_filter != value)
            {
                _filter = value;
                Redraw();
            }
        }
    }

    /// <summary>The ignored checks, for the settings dialog.</summary>
    public IReadOnlyList<IgnoredRow> IgnoredRows =>
        _settings.Ignored.Select(entry => new IgnoredRow(
            entry.CheckId,
            CheckCatalogue.Texts.Contains(entry.CheckId) ? CheckCatalogue.Texts[entry.CheckId].Name : entry.CheckId,
            entry.Reason.Length > 0 ? entry.Reason : "No reason given")).ToArray();

    /// <summary>
    /// Shows what is known already (settings, the last results), then scans. Never throws: a
    /// failure is shown in the window.
    /// </summary>
    public async Task StartAsync()
    {
        if (_role.Demo)
        {
            ShowDemo();
            return;
        }

        _settings = _settingsStore!.Load(out string? problem);
        SettingsProblem = problem ?? string.Empty;
        ApplyErrorReports();

        // A run nobody looks at (the build's smoke test, a screenshot) starts nothing else and
        // asks no server: it shows the window and ends.
        bool automated = _role.SmokeTest || _role.ScreenshotPath is not null;

        // An installed SecReview keeps its icon in the notification area when that is switched
        // on: after an update, or when the icon was quit, opening the window brings it back.
        // (A copy that is not installed never starts one by itself.)
        if (!automated && _settings.RunInNotificationArea && _administratorUnavailable is null && !StartsIconLater)
        {
            StartTray();
        }

        // What is known about updates is shown at once; looking again, when it is time, goes on beside the scan.
        if (!automated)
        {
            _ = LookForUpdatesAsync(now: false);
        }
        if (_previousRunCrashed)
        {
            _reporter.ReportAbnormalEnd();
        }

        ShowFirstRun = !_settings.FirstRunDone;

        try
        {
            _resultsStamp = _resultsStore!.Stamp();
            if (_resultsStore.Load(CheckCatalogue.Checks, CheckCatalogue.Texts) is { } last)
            {
                Take(last);
                Redraw();
            }
        }
#pragma warning disable CA1031 // Old results are a convenience; whatever is wrong with them, the scan goes ahead.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The last results could not be shown", exception);
        }

        await RunAsync().ConfigureAwait(true);
    }

    /// <summary>Runs a scan and shows it as it answers. Never throws: a failure is shown in the window.</summary>
    public async Task RunAsync()
    {
        if (!CanRun || _role.Demo)
        {
            return;
        }

        IsBusy = true;
        HasFailed = false;
        ShowHeadline();

        try
        {
            ScanResult scan = await Task.Run(() => ScanThisPcAsync(Arrived)).ConfigureAwait(true);
            TakeOver(scan);
            Changed(nameof(HasResults));

            // What is saved is what is shown: the new answers, and for checks an ordinary scan
            // cannot read, what the administrator checks said earlier.
            SaveResults();
        }
#pragma warning disable CA1031 // The window must stay usable whatever goes wrong in a scan.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The scan could not run", exception);
            if (exception is not PlatformNotSupportedException)
            {
                _reporter.Report(exception);
            }

            Failure = exception.Message;
            HasFailed = true;
        }
        finally
        {
            IsBusy = false;
            Redraw();
        }
    }

    /// <summary>Runs one check again and shows its new answer.</summary>
    public async Task CheckAgainAsync(string checkId)
    {
        // During a scan every check is being run again already.
        if (_role.Demo || IsBusy || _administratorBusy || !_results.ContainsKey(checkId) || !_beingChecked.Add(checkId))
        {
            return;
        }

        Changed(nameof(CanRun));
        Redraw();
        try
        {
            ScannedCheck again = await Task.Run(() => NewScanner().RunOneAsync(checkId, WindowsProbes.IsProcessElevated())).ConfigureAwait(true);
            _results[checkId] = ScanPresentation.Newer(_results.GetValueOrDefault(checkId), again, DateTimeOffset.UtcNow);
            SaveResults();
        }
#pragma warning disable CA1031 // One check failing to run again must not take the window down.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error($"Check '{checkId}' could not be run again", exception);
            _reporter.Report(exception, checkId);
        }
        finally
        {
            _beingChecked.Remove(checkId);
            Changed(nameof(CanRun));
            Redraw();
        }
    }

    /// <summary>
    /// Runs the checks that need administrator rights, through the Windows prompt, and shows
    /// their answers. Saying no at the prompt changes nothing. Never throws.
    /// </summary>
    public async Task RunAdministratorChecksAsync()
    {
        if (_role.Demo || !CanRunAdministratorChecks)
        {
            return;
        }

        SetAdministratorBusy(true);
        AdministratorProblem = string.Empty;
        try
        {
            var launcher = new WindowsElevatedLauncher(Path.Combine(AppContext.BaseDirectory, AdministratorScan.HelperFileName));
            AdministratorScanResult result = await AdministratorScan
                .RunAsync(launcher, CheckCatalogue.Checks, CheckCatalogue.Texts)
                .ConfigureAwait(true);

            switch (result.Outcome)
            {
                case AdministratorScanOutcome.Completed:
                    foreach (ScannedCheck check in result.Scan!.Checks)
                    {
                        _results[check.Definition.Id] = check;
                    }

                    SaveResults();
                    break;

                case AdministratorScanOutcome.Failed:
                    AdministratorProblem = result.Problem ?? "The administrator checks could not be run.";
                    _log.Error("The administrator checks failed", new InvalidOperationException(AdministratorProblem));
                    break;
            }
        }
#pragma warning disable CA1031 // Whatever goes wrong here, the window and its other results stay.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The administrator checks could not be run", exception);
            _reporter.Report(exception);
            AdministratorProblem = "The administrator checks could not be run.";
        }
        finally
        {
            SetAdministratorBusy(false);
            Redraw();
        }
    }

    /// <summary>Whether the notice of a newer version is on screen.</summary>
    public bool HasUpdate => _updateMessage.Length > 0;

    /// <summary>"Version 1.4.0 is available, released 3 days ago.", or how far installing it is.</summary>
    public string UpdateMessage
    {
        get => _updateMessage;
        private set
        {
            if (Set(ref _updateMessage, value, nameof(UpdateMessage)))
            {
                Changed(nameof(HasUpdate));
            }
        }
    }

    /// <summary>What is new in the newer version; empty when the release says nothing.</summary>
    public string UpdateNotes => _update.Notes ?? string.Empty;

    public bool HasUpdateNotes => UpdateNotes.Length > 0;

    /// <summary>
    /// Whether "Update now" is offered: this build installs updates, the organisation allows
    /// it, and SecReview is installed (the helper that installs runs from Program Files only).
    /// Made-up results show the button so it can be looked at; pressing it does nothing there.
    /// </summary>
    public bool ShowUpdateNow =>
        _role.Demo || (_updates is { MayInstall: true } && PublisherIdentity.Compiled.IsConfigured && _administratorUnavailable is null);

    public bool CanUpdateNow => ShowUpdateNow && !_updateBusy && _update.Outcome == UpdateOutcome.Available;

    /// <summary>Why an update was not installed; empty when nothing went wrong.</summary>
    public string UpdateProblem
    {
        get => _updateProblem;
        private set
        {
            if (Set(ref _updateProblem, value, nameof(UpdateProblem)))
            {
                Changed(nameof(HasUpdateProblem));
            }
        }
    }

    public bool HasUpdateProblem => UpdateProblem.Length > 0;

    public void DismissUpdateProblem() => UpdateProblem = string.Empty;

    /// <summary>Where SecReview stands on updates, in a sentence, for the About dialog.</summary>
    public string UpdateStatus
    {
        get
        {
            if (_updates is not { IsOn: true })
            {
                return UpdateSource.Compiled.IsConfigured ? "Your organisation has switched off the look for updates." : "This build does not look for updates.";
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            return _update.Outcome switch
            {
                UpdateOutcome.Available => UpdateService.Notice(_update, now)!,
                UpdateOutcome.UpToDate => $"SecReview is up to date (looked {ScanPresentation.Age(_update.CheckedAt!.Value, now)}).",
                UpdateOutcome.Failed => _update.Problem ?? "SecReview could not look for updates.",
                _ => "SecReview has not looked for updates yet.",
            };
        }
    }

    /// <summary>Whether looking for updates is possible at all, for the button in the About dialog.</summary>
    public bool CanLookForUpdates => _updates is { IsOn: true };

    /// <summary>
    /// Shows what is known about updates and looks again when it is time (or at once, when
    /// <paramref name="now"/> is set). Never throws.
    /// </summary>
    public async Task LookForUpdatesAsync(bool now)
    {
        if (_updates is null)
        {
            return;
        }

        try
        {
            ShowUpdate(_updates.Known());
            UpdateState found = await Task.Run(() => _updates.LookAsync(now)).ConfigureAwait(true);
            ShowUpdate(found);

            // The check "SecReview is up to date" reads what was just found.
            WakeTray();
        }
#pragma warning disable CA1031 // Looking for updates must never be what breaks the window.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("Looking for updates failed", exception);
            _reporter.Report(exception);
        }
    }

    /// <summary>
    /// Installs the newer version: Windows asks for permission, then SecReview's helper
    /// downloads the setup program, checks it and starts it. Setup closes SecReview and opens
    /// it again. Saying no at the prompt changes nothing. Never throws.
    /// </summary>
    public async Task UpdateNowAsync()
    {
        if (_role.Demo || !CanUpdateNow)
        {
            return;
        }

        string notice = UpdateMessage;
        _updateBusy = true;
        Changed(nameof(CanUpdateNow));
        UpdateProblem = string.Empty;
        try
        {
            var launcher = new WindowsElevatedLauncher(Path.Combine(AppContext.BaseDirectory, AdministratorScan.HelperFileName), WindowsElevatedLauncher.UpdateCommand);
            (UpdateInstallOutcome outcome, string? problem) = await UpdateInstall
                .RunAsync(launcher, progress => _onWindowThread(() => UpdateMessage = Describe(progress, _update.Available)))
                .ConfigureAwait(true);

            switch (outcome)
            {
                case UpdateInstallOutcome.Installing:
                    UpdateMessage = $"Installing version {_update.Available}. SecReview closes and opens again when it is done.";
                    return; // the button stays off: setup is running

                case UpdateInstallOutcome.Failed:
                    UpdateProblem = problem ?? "The update could not be installed.";
                    _log.Error("The update was not installed", new InvalidOperationException(UpdateProblem));
                    break;
            }
        }
#pragma warning disable CA1031 // Whatever goes wrong here, the window and its results stay.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The update could not be started", exception);
            _reporter.Report(exception);
            UpdateProblem = "The update could not be started.";
        }

        UpdateMessage = notice;
        _updateBusy = false;
        Changed(nameof(CanUpdateNow));
    }

    private static string Describe(UpdateProgress progress, string? version) => progress.Stage switch
    {
        UpdateStage.Checking => $"Getting version {version}…",
        UpdateStage.Downloading when progress.Total > 0 => $"Downloading version {version} ({100 * progress.Done / progress.Total} %)…",
        UpdateStage.Downloading => $"Downloading version {version}…",
        UpdateStage.Verifying => $"Checking version {version}…",
        UpdateStage.Installing => $"Installing version {version}. SecReview closes and opens again when it is done.",
        _ => $"Version {version} is available.",
    };

    private void ShowUpdate(UpdateState state)
    {
        _update = state;
        if (!_updateBusy)
        {
            UpdateMessage = UpdateService.Notice(state, DateTimeOffset.UtcNow) ?? string.Empty;
        }

        Changed(nameof(UpdateNotes));
        Changed(nameof(HasUpdateNotes));
        Changed(nameof(CanUpdateNow));
        Changed(nameof(UpdateStatus));
    }

    /// <summary>Closes the note about what went wrong with the administrator checks.</summary>
    public void DismissAdministratorProblem() => AdministratorProblem = string.Empty;

    private void SetAdministratorBusy(bool busy)
    {
        _administratorBusy = busy;
        Changed(nameof(CanRun));
        Changed(nameof(CanRunAdministratorChecks));
        ShowHeadline();
    }

    /// <summary>Leaves a check out of every count, with the user's reason.</summary>
    public void Ignore(string checkId, string reason)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        ChangeSettings(settings => settings.WithIgnored(checkId, reason, now));
        Redraw();
    }

    public void StopIgnoring(string checkId)
    {
        ChangeSettings(settings => settings.WithoutIgnored(checkId));
        Redraw();
    }

    /// <summary>Whether SecReview keeps an icon in the notification area and checks again by itself.</summary>
    public bool RunInNotificationArea => _settings.RunInNotificationArea;

    /// <summary>How many hours pass between the icon's checks.</summary>
    public int RecheckHours => _settings.RecheckHours;

    /// <summary>Whether the icon says so when a check starts failing.</summary>
    public bool NotifyNewFailures => _settings.NotifyNewFailures;

    /// <summary>
    /// Switches the notification-area icon on or off. On starts it now; off makes the running
    /// one leave. Nothing is registered with Windows: whether it starts at sign-in is the
    /// installer's entry, and this setting is what the icon looks at when it starts.
    /// </summary>
    public void SetRunInNotificationArea(bool on)
    {
        if (_settings.RunInNotificationArea == on)
        {
            return;
        }

        ChangeSettings(settings => settings with { RunInNotificationArea = on });
        if (on && !_role.Demo && !StartsIconLater)
        {
            StartTray();
        }
    }

    /// <summary>
    /// Whether this window got administrator rights through the Windows prompt. An icon
    /// started from it would keep those rights all day, so it is not started from here: it
    /// comes at the next sign-in.
    /// </summary>
    public bool StartsIconLater => !_role.Demo && WindowsProbes.IsSupported && WindowsProbes.IsElevatedByPrompt();

    public void SetRecheckHours(int hours)
    {
        if (AppSettings.RecheckChoices.Contains(hours) && _settings.RecheckHours != hours)
        {
            ChangeSettings(settings => settings with { RecheckHours = hours });
        }
    }

    public void SetNotifyNewFailures(bool on)
    {
        if (_settings.NotifyNewFailures != on)
        {
            ChangeSettings(settings => settings with { NotifyNewFailures = on });
        }
    }

    /// <summary>
    /// Opens the row of a check, among all checks, for the window to scroll to. False when
    /// there is no such row (no results yet, or a check this version does not have).
    /// </summary>
    public bool Open(string checkId)
    {
        // The icon asks for a check it has just found failing: show its answer, not an older one.
        TakeInFromDisk();
        if (!_results.TryGetValue(checkId, out ScannedCheck? check))
        {
            return false;
        }

        // A new object for the same answer, so the row is made again, open.
        _results[checkId] = check with { Result = check.Result with { } };
        _openNext.Add(checkId);
        _filter = ScanFilter.All;
        Redraw();
        return true;
    }

    /// <summary>Where a check's row is: which group and which row in it; null when it is not on screen.</summary>
    public (int Section, int Row)? PositionOf(string checkId)
    {
        for (int section = 0; section < Sections.Count; section++)
        {
            if (Sections[section] is SectionItem group)
            {
                for (int row = 0; row < group.Checks.Count; row++)
                {
                    if (group.Checks[row] is CheckItem item && item.Id == checkId)
                    {
                        return (section, row);
                    }
                }
            }
        }

        return null;
    }

    /// <summary>The user's switch for error reports. Saved, and applied at once.</summary>
    public void SetErrorReports(bool on)
    {
        if (_settings.SendErrorReports == on)
        {
            return;
        }

        ChangeSettings(settings => settings with { SendErrorReports = on });
        ApplyErrorReports();
    }

    /// <summary>Which checks do not pass, as it would go with feedback; null without results.</summary>
    public string? ResultsForFeedback() => CurrentScan() is { } scan ? ErrorReports.ResultsForFeedback(scan) : null;

    /// <summary>
    /// Sends feedback with exactly the text the user was shown as included (null for nothing).
    /// False when it was not sent. With made-up results nothing is ever sent.
    /// </summary>
    public bool SendFeedback(string text, string? included) => !_role.Demo && _reporter.SendFeedback(text, included);

    /// <summary>Closes the first-run notice for good.</summary>
    public void DismissFirstRun()
    {
        ShowFirstRun = false;
        if (!_settings.FirstRunDone)
        {
            ChangeSettings(settings => settings with { FirstRunDone = true });

            // The notice has said that errors are reported; from now on they may be.
            ApplyErrorReports();
        }
    }

    /// <summary>Everything about one check as text, for the clipboard; null when it has no result.</summary>
    public string? DetailsOf(string checkId) =>
        _results.TryGetValue(checkId, out ScannedCheck? check) ? ScanPresentation.Details(check, _settings.IgnoredOf(checkId)) : null;

    /// <summary>
    /// The current results as a report; null when there are none, or while a scan runs: a
    /// report of half a scan would look like a whole one.
    /// </summary>
    public string? ReportJson() =>
        !IsBusy && _beingChecked.Count == 0 && CurrentScan() is { } scan ? ReportFile.ToJson(ReportBuilder.Build(scan)) : null;

    /// <summary>
    /// Called by the window a few times a second: draws results that arrived since the last
    /// redraw, and keeps "checked 5 minutes ago" true while the window stays open.
    /// </summary>
    public void Tick()
    {
        // What the notification-area icon found while this window was open is shown here too.
        if (Stopwatch.GetElapsedTime(_lastLookAtDisk) >= TimeSpan.FromSeconds(2))
        {
            _lastLookAtDisk = Stopwatch.GetTimestamp();
            if (TakeInFromDisk())
            {
                Redraw();
                return;
            }
        }

        if (_redrawPending && Stopwatch.GetElapsedTime(_lastRedraw) >= RedrawInterval)
        {
            Redraw();
        }
        else if (Stopwatch.GetElapsedTime(_lastAgeShown) >= TimeSpan.FromSeconds(30))
        {
            ShowHeadline();
        }
    }

    /// <summary>Opens every row on screen (automated runs, so that what is inside them can be looked at).</summary>
    public void ExpandAll()
    {
        foreach (CheckItem row in Sections.OfType<SectionItem>().SelectMany(section => section.Checks.OfType<CheckItem>()).ToArray())
        {
            _results[row.Id] = row.Check with { Result = row.Check.Result with { } };
            _openNext.Add(row.Id);
        }

        Redraw();
    }

    private Scanner NewScanner()
    {
        if (!WindowsProbes.IsSupported)
        {
            throw new PlatformNotSupportedException($"SecReview needs {WindowsProbes.MinimumWindowsName} or later.");
        }

        // A check that throws is a bug in SecReview: the row says "could not check", and the
        // error (its type and where, never its message) is reported when reporting is on.
        return new Scanner(WindowsProbes.Create(), TimeProvider.System) { OnUnexpectedError = (checkId, error) => _reporter.Report(error, checkId) };
    }

    private Task<ScanResult> ScanThisPcAsync(Action<ScannedCheck> onResult) =>
        NewScanner().RunAsync(CheckSelection.All, WindowsProbes.IsProcessElevated(), onResult);

    /// <summary>Starts or stops error reporting to match the build, the organisation's policy and the user's switch.</summary>
    private void ApplyErrorReports()
    {
        if (!_role.Demo && WindowsProbes.IsSupported)
        {
            // Settings that could not be read say nothing about the user's choice; and until
            // the first-run notice is closed the user has not been told.
            var choice = new ErrorReportsChoice(_settings.SendErrorReports, SettingsWereRead: !HasSettingsProblem, NoticeSeen: _settings.FirstRunDone);
            _reporter.Apply(choice, WindowsProbes.Create().Registry);
        }

        Changed(nameof(ErrorReportsOn));
        Changed(nameof(ErrorReportsSwitch));
        Changed(nameof(CanChangeErrorReports));
        Changed(nameof(ErrorReportsDescription));
        Changed(nameof(CanSendFeedback));
        Changed(nameof(FirstRunMessage));
    }

    /// <summary>Called on a scan's threads as each check answers.</summary>
    private void Arrived(ScannedCheck check) => _onWindowThread(() =>
    {
        if (!IsBusy)
        {
            return; // the scan is over and its full result is already shown
        }

        _results[check.Definition.Id] = ScanPresentation.Newer(_results.GetValueOrDefault(check.Definition.Id), check, DateTimeOffset.UtcNow);
        if (Stopwatch.GetElapsedTime(_lastRedraw) >= RedrawInterval)
        {
            Redraw();
        }
        else
        {
            _redrawPending = true; // drawn by the next Tick
        }
    });

    private void ShowDemo()
    {
        TimeProvider clock = TimeProvider.System;
        ScanResult scan = DemoScan.Create(clock, _role.DemoState);

        // The notice of a newer version, where there is room to look at it.
        if (_role.DemoState is DemoState.Mixed or DemoState.Dialogs)
        {
            ShowUpdate(new UpdateState
            {
                Outcome = UpdateOutcome.Available,
                Available = "9.9.9",
                CheckedAt = clock.GetUtcNow(),
                Published = clock.GetUtcNow().AddDays(-3),
                Notes = "Made-up notes: two new checks, and a clearer message when a check needs administrator rights.",
            });
        }

        switch (_role.DemoState)
        {
            case DemoState.Failed:
                Headline = "The checks could not run";
                Failure = $"SecReview needs {WindowsProbes.MinimumWindowsName} or later.";
                HasFailed = true;
                return;

            case DemoState.FirstRun:
                ShowFirstRun = true;
                break;

            case DemoState.Ignored or DemoState.Dialogs:
                _settings = _settings with { Ignored = DemoScan.Ignored(clock) };
                break;

            case DemoState.Loading:
                // Yesterday's results stay on screen while the new scan runs.
                scan = scan with { FinishedAt = scan.FinishedAt.AddHours(-26) };
                IsBusy = true;
                break;
        }

        Take(scan);
        Redraw();
    }

    /// <summary>
    /// Replaces what is known with a finished scan. Checks the scan does not have are dropped.
    /// Where the scan can only say "needs administrator rights" and the administrator checks
    /// answered earlier, that answer stays (see <see cref="ScanPresentation.Newer"/>).
    /// </summary>
    private void TakeOver(ScanResult scan)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Dictionary<string, ScannedCheck> merged = scan.Checks.ToDictionary(
            check => check.Definition.Id,
            check => ScanPresentation.Newer(_results.GetValueOrDefault(check.Definition.Id), check, now),
            StringComparer.Ordinal);

        _results.Clear();
        foreach ((string id, ScannedCheck check) in merged)
        {
            _results[id] = check;
        }

        _finishedAt = scan.FinishedAt;
        _elevated = scan.Elevated;
    }

    private void Take(ScanResult scan)
    {
        foreach (ScannedCheck check in scan.Checks)
        {
            _results[check.Definition.Id] = check;
        }

        _finishedAt = scan.FinishedAt;
        _elevated = scan.Elevated;
    }

    /// <summary>What is known right now as one scan, in catalogue order; null without results.</summary>
    private ScanResult? CurrentScan() =>
        _results.Count == 0
            ? null
            : new ScanResult(
                CheckCatalogue.Checks.Where(check => _results.ContainsKey(check.Definition.Id)).Select(check => _results[check.Definition.Id]).ToArray(),
                _finishedAt ?? DateTimeOffset.UtcNow,
                _elevated);

    /// <summary>
    /// Brings the groups and counts in line with what is known. Only what changed is touched: a
    /// row whose result is the same stays the same object, so nothing on screen flickers or
    /// closes while results arrive.
    /// </summary>
    private void Redraw()
    {
        _lastRedraw = Stopwatch.GetTimestamp();
        _redrawPending = false;
        Dictionary<string, CheckItem> shown = Sections.OfType<SectionItem>()
            .SelectMany(section => section.Checks.OfType<CheckItem>())
            .ToDictionary(item => item.Id, StringComparer.Ordinal);

        Changed(nameof(HasResults));
        Changed(nameof(AllLabel));
        Changed(nameof(AttentionLabel));
        Changed(nameof(AdminLabel));
        Changed(nameof(PassedLabel));
        Changed(nameof(IgnoredLabel));

        if (CurrentScan() is not { } scan)
        {
            Sections.Clear();
            EmptyText = string.Empty;
            Notice = string.Empty;
            if (HasFailed)
            {
                Headline = "The checks could not run";
                Detail = string.Empty;
            }

            return;
        }

        IReadOnlySet<string> ignored = _settings.IgnoredIds();
        IReadOnlyList<ScanSection> wanted = ScanPresentation.Sections(scan, ignored, _filter);
        Dictionary<string, SectionItem> sections = Sections.OfType<SectionItem>().ToDictionary(section => section.Title, StringComparer.Ordinal);
        var groups = new List<object>(wanted.Count);
        foreach (ScanSection section in wanted)
        {
            SectionItem group = sections.TryGetValue(section.Title, out SectionItem? existing) ? existing : new SectionItem(section.Title);
            group.Detail = section.Detail;
            ListSync.Apply(group.Checks, section.Checks.Select(object (check) =>
            {
                string id = check.Definition.Id;
                IgnoredCheck? entry = _settings.IgnoredOf(id);
                bool beingChecked = _beingChecked.Contains(id);
                if (shown.TryGetValue(id, out CheckItem? row) && row.IsStill(check, entry, beingChecked))
                {
                    return row;
                }

                bool expanded = _openNext.Remove(id) || ScanPresentation.StartsExpanded(
                    row is null ? null : (row.IsIgnored, row.IsExpanded), entry is not null, ScanPresentation.StandingOf(check));
                return new CheckItem(check, entry, expanded, beingChecked);
            }).ToList());
            groups.Add(group);
        }

        ListSync.Apply(Sections, groups);

        EmptyText = Sections.Count > 0
            ? string.Empty
            : _filter switch
            {
                ScanFilter.NeedsAttention => "Nothing needs attention.",
                ScanFilter.NeedsAdmin => "No check is waiting for administrator rights.",
                ScanFilter.Passed => "No check has passed yet.",
                ScanFilter.Ignored => "No check is ignored. Use Ignore on a failing check to leave it out of the count, with a reason.",
                _ => "No checks were run.",
            };

        int needAdmin = ScanPresentation.CountFor(scan, ignored, ScanFilter.NeedsAdmin);
        string notice = needAdmin switch
        {
            0 => string.Empty,
            1 => "1 check needs administrator rights. It is not counted as failing.",
            _ => $"{needAdmin} checks need administrator rights. They are not counted as failing.",
        };

        // Where this copy cannot run them, the notice says what it takes.
        Notice = notice.Length > 0 && !ShowAdministratorButton ? $"{notice} {_administratorUnavailable}" : notice;
        Changed(nameof(CanRunAdministratorChecks));

        ShowHeadline();
    }

    private void ShowHeadline()
    {
        _lastAgeShown = Stopwatch.GetTimestamp();
        if (HasFailed && _results.Count == 0)
        {
            return;
        }

        // No scan has ever finished: what is on screen is a beginning, not a verdict.
        if (_finishedAt is null)
        {
            if (IsBusy)
            {
                (Headline, Detail) = ScanPresentation.Progress(_results.Count, CheckCatalogue.Checks.Count);
            }

            return;
        }

        if (CurrentScan() is not { } scan)
        {
            return;
        }

        IReadOnlySet<string> ignored = _settings.IgnoredIds();
        Headline = ScanPresentation.Headline(scan, ignored);
        string age = ScanPresentation.Age(scan.FinishedAt, DateTimeOffset.UtcNow);
        Detail = IsBusy
            ? $"{ScanPresentation.Counts(scan, ignored)} · checked {age} · checking again…"
            : _administratorBusy
                ? $"{ScanPresentation.Counts(scan, ignored)} · checked {age} · running the administrator checks…"
                : $"{ScanPresentation.Counts(scan, ignored)} · checked {age}";
    }

    /// <summary>A filter's name with its count. No count until a scan has finished: a count of the first few answers would mislead.</summary>
    private string Label(string name, ScanFilter filter) =>
        _finishedAt is not null && CurrentScan() is { } scan ? $"{name} ({ScanPresentation.CountFor(scan, _settings.IgnoredIds(), filter)})" : name;

    /// <summary>
    /// Changes the settings as they are on disk now, not as this window read them earlier: the
    /// notification-area icon writes the same file (its pause).
    /// </summary>
    private void ChangeSettings(Func<AppSettings, AppSettings> change)
    {
        if (_settingsStore is null)
        {
            _settings = change(_settings); // made-up results: nothing is written
            return;
        }

        AppSettings changed = _settingsStore.Update(change, out string? problem);

        // Settings that could not be read or saved: the change holds in this window, on top of
        // what the window knew, not on top of the defaults.
        _settings = problem is null ? changed : change(_settings);
        SettingsProblem = problem ?? string.Empty;
        WakeTray();
    }

    /// <summary>
    /// Takes in the answers the notification-area icon saved since this window last read or
    /// wrote the results. True when something changed.
    /// </summary>
    private bool TakeInFromDisk()
    {
        if (_resultsStore is null || _resultsStore.Stamp() is not { } stamp || stamp == _resultsStamp)
        {
            return false;
        }

        _resultsStamp = stamp;
        if (_resultsStore.Load(CheckCatalogue.Checks, CheckCatalogue.Texts) is not { } saved)
        {
            return false;
        }

        bool changed = ScanPresentation.TakeNewer(_results, saved, DateTimeOffset.UtcNow);
        if (_finishedAt is null || saved.FinishedAt > _finishedAt)
        {
            _finishedAt = saved.FinishedAt;
            changed = true;
        }

        return changed;
    }

    /// <summary>
    /// Saves what is shown, after taking in what the icon saved meanwhile, so neither
    /// process writes its older answers over the other's newer ones.
    /// </summary>
    private void SaveResults()
    {
        if (_resultsStore is null)
        {
            return;
        }

        TakeInFromDisk();
        if (CurrentScan() is { } shown)
        {
            if (!_resultsStore.Save(shown))
            {
                _log.Error("The results could not be saved", new IOException("Writing results.json failed."));
            }

            _resultsStamp = _resultsStore.Stamp();
            WakeTray();
        }
    }

    /// <summary>Tells the notification-area icon, if there is one, that the settings or the results changed.</summary>
    private void WakeTray()
    {
        if (!_role.Demo && WindowsProbes.IsSupported)
        {
            WakeSignal.Send(InstanceNames.TrayWake(AppData.Directory));
        }
    }

    /// <summary>Starts the notification-area icon. A second one ends by itself.</summary>
    private void StartTray()
    {
        if (Environment.ProcessPath is not { } self)
        {
            return;
        }

        try
        {
            var start = new ProcessStartInfo(self) { UseShellExecute = false };
            start.ArgumentList.Add(AppArguments.TraySwitch);
            using Process? started = Process.Start(start);
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            _log.Error("The notification-area icon could not be started", exception);
        }
    }

    private void Changed(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool Set<T>(ref T field, T value, string name)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        Changed(name);
        return true;
    }
}
