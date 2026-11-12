using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Elevation;
using SecReview.Probing.Windows;
using SecReview.Reporting;
using SecReview.Scanning;
using SecReview.Settings;

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
            _administratorUnavailable = AdministratorScan.WhyUnavailable(
                AppContext.BaseDirectory,
                new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                },
                File.Exists);
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
        if (_previousRunCrashed)
        {
            _reporter.ReportAbnormalEnd();
        }

        ShowFirstRun = !_settings.FirstRunDone;

        try
        {
            if (_resultsStore!.Load(CheckCatalogue.Checks, CheckCatalogue.Texts) is { } last)
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
            if (CurrentScan() is { } shown && !_resultsStore!.Save(shown))
            {
                _log.Error("The results could not be saved", new IOException("Writing results.json failed."));
            }
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
            if (CurrentScan() is { } scan)
            {
                _resultsStore!.Save(scan);
            }
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

                    if (CurrentScan() is { } shown)
                    {
                        _resultsStore!.Save(shown);
                    }

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
        _settings = _settings.WithIgnored(checkId, reason, DateTimeOffset.UtcNow);
        SaveSettings();
        Redraw();
    }

    public void StopIgnoring(string checkId)
    {
        _settings = _settings.WithoutIgnored(checkId);
        SaveSettings();
        Redraw();
    }

    /// <summary>The user's switch for error reports. Saved, and applied at once.</summary>
    public void SetErrorReports(bool on)
    {
        if (_settings.SendErrorReports == on)
        {
            return;
        }

        _settings = _settings with { SendErrorReports = on };
        SaveSettings();
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
            _settings = _settings with { FirstRunDone = true };
            SaveSettings();

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

        switch (_role.DemoState)
        {
            case DemoState.Failed:
                Headline = "The checks could not run";
                Failure = "SecReview needs Windows 10 version 22H2 or later.";
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

    private void SaveSettings()
    {
        if (_settingsStore is null)
        {
            return; // made-up results: nothing is written
        }

        if (!_settingsStore.Save(_settings, out string? problem))
        {
            SettingsProblem = problem ?? "The settings could not be saved.";
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
