using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Scanning;
using SecReview.Settings;
using SecReview.Tray;

namespace SecReview.Tests.Tray;

[TestClass]
public sealed class TraySessionTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);
    private static readonly CheckTexts Texts = CheckTexts.Load();

    /// <summary>Three real checks of the catalogue, so their wording is found.</summary>
    private static readonly ICheck[] Checks = [new FirewallCheck(), new AutomaticLogonCheck(), new AntivirusCheck()];

    private readonly Clock _clock = new(Start);
    private readonly Icon _icon = new();
    private readonly List<string?> _opened = [];
    private readonly List<string> _errors = [];
    private string _folder = string.Empty;
    private Func<Task<ScanResult>> _scan = () => throw new InvalidOperationException("No scan was expected.");
    private int _scans;

    [TestInitialize]
    public void CreateFolder() => _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));

    [TestCleanup]
    public void DeleteFolder()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private SettingsStore Settings => new(_folder);

    private ResultsStore Results => new(_folder);

    private TraySession Session() => new(_icon, new TrayEnvironment
    {
        Settings = new SettingsStore(_folder),
        Results = new ResultsStore(_folder),
        Scan = () =>
        {
            Interlocked.Increment(ref _scans);
            return _scan();
        },
        Clock = _clock,
        OpenWindow = _opened.Add,
        OnError = (where, exception) => _errors.Add($"{where}: {exception.GetType().Name}"),
        Checks = Checks,
        Texts = Texts,
    });

    /// <summary>A scan in which the named checks fail and the others pass, finished at the clock's time.</summary>
    private ScanResult Scan(params ICheck[] failing) => new(
        [
            .. Checks.Select(check => new ScannedCheck(
                check.Definition,
                Texts[check.Definition.Id],
                new CheckResult(
                    check.Definition.Id,
                    failing.Contains(check) ? CheckOutcome.Fail("It is off.") : CheckOutcome.Pass("It is on."),
                    _clock.GetUtcNow(),
                    Elevated: false,
                    TimeSpan.Zero))),
        ],
        _clock.GetUtcNow(),
        Elevated: false);

    private void ScansAnswer(params ICheck[] failing) => _scan = () => Task.FromResult(Scan(failing));

    private static async Task Tick(TraySession session)
    {
        session.Handle(TrayCommand.Tick);
        await session.Idle;
    }

    [TestMethod]
    public async Task AfterSigningIn_TheIconIsGrey_ThenChecksAfterAMinute()
    {
        ScansAnswer();
        TraySession session = Session();

        Assert.IsTrue(session.Start());
        Assert.AreEqual((TrayState.Unknown, "SecReview: not checked yet"), (_icon.State, _icon.Tooltip));

        await Tick(session);
        Assert.AreEqual(0, _scans, "not in the first minute");

        _clock.Advance(TimeSpan.FromSeconds(61));
        await Tick(session);

        Assert.AreEqual(1, _scans);
        Assert.AreEqual(TrayState.Fine, _icon.State);
        Assert.IsNotNull(Results.Load(Checks, Texts), "the window finds the results");
        Assert.AreEqual(0, _icon.Notifications.Count);
        Assert.AreEqual(0, _errors.Count, string.Join("; ", _errors));
    }

    [TestMethod]
    public async Task TheChecksRunAgain_WhenTheIntervalIsOver_NotBefore()
    {
        ScansAnswer();
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        await Tick(session);

        _clock.Advance(TimeSpan.FromHours(3));
        await Tick(session);
        Assert.AreEqual(1, _scans);

        _clock.Advance(TimeSpan.FromHours(1));
        await Tick(session);
        Assert.AreEqual(2, _scans);
    }

    [TestMethod]
    public async Task ACheckThatStartsFailing_IsNotifiedOnce_AndAClickOpensTheWindowOnIt()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));

        ScansAnswer(Checks[1]);
        await Tick(session);
        Assert.AreEqual(0, _icon.Notifications.Count, "the first scan is a baseline");
        Assert.AreEqual(TrayState.NeedsAttention, _icon.State);

        ScansAnswer(Checks[0], Checks[1]);
        _clock.Advance(TimeSpan.FromHours(4));
        await Tick(session);

        Assert.AreEqual(1, _icon.Notifications.Count);
        Assert.AreEqual(Texts[FirewallCheck.Id].TitleFail, _icon.Notifications[0].Title);

        session.Handle(TrayCommand.NotificationClicked);
        session.Handle(TrayCommand.Open);
        CollectionAssert.AreEqual(new string?[] { FirewallCheck.Id, null }, _opened);

        _clock.Advance(TimeSpan.FromHours(4));
        await Tick(session);
        Assert.AreEqual(1, _icon.Notifications.Count, "still failing is not news");
    }

    [TestMethod]
    public async Task NotificationsCanBeSwitchedOff_AndIgnoredChecksAreNotNews()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        ScansAnswer();
        await Tick(session);

        Settings.Update(settings => settings with { NotifyNewFailures = false }, out _);
        ScansAnswer(Checks[0]);
        _clock.Advance(TimeSpan.FromHours(4));
        await Tick(session);
        Assert.AreEqual(0, _icon.Notifications.Count);
        Assert.AreEqual(TrayState.NeedsAttention, _icon.State, "the icon still says so");

        Settings.Update(settings => (settings with { NotifyNewFailures = true }).WithIgnored(Checks[2].Definition.Id, "Known", _clock.GetUtcNow()), out _);
        ScansAnswer(Checks[0], Checks[2]);
        _clock.Advance(TimeSpan.FromHours(4));
        await Tick(session);
        Assert.AreEqual(0, _icon.Notifications.Count);
    }

    [TestMethod]
    public async Task APause_StopsTheChecksAndTheNews_AndIsSeenByTheWindow()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        ScansAnswer();
        await Tick(session);

        session.Handle(TrayCommand.PauseDay);
        Assert.AreEqual(TrayState.Snoozed, _icon.State);
        Assert.IsTrue(_icon.Paused);
        Assert.AreEqual(_clock.GetUtcNow().AddDays(1), Settings.Load(out _).SnoozedUntil);

        ScansAnswer(Checks[0]);
        _clock.Advance(TimeSpan.FromHours(8));
        await Tick(session);
        Assert.AreEqual(1, _scans, "paused");

        session.Handle(TrayCommand.CheckNow);
        await session.Idle;
        Assert.AreEqual(2, _scans, "asked for by hand");
        Assert.AreEqual(0, _icon.Notifications.Count, "no news while paused");

        session.Handle(TrayCommand.Resume);
        Assert.IsNull(Settings.Load(out _).SnoozedUntil);
        Assert.AreEqual(TrayState.NeedsAttention, _icon.State);
        Assert.IsFalse(_icon.Paused);
    }

    [TestMethod]
    public async Task WhatTheWindowDid_IsSeenAtTheNextTick()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        ScansAnswer(Checks[0]);
        await Tick(session);
        Assert.AreEqual(TrayState.NeedsAttention, _icon.State);

        // The window scans an hour later and finds the firewall on again.
        _clock.Advance(TimeSpan.FromHours(1));
        Assert.IsTrue(Results.Save(Scan()));
        File.SetLastWriteTimeUtc(Path.Combine(_folder, ResultsStore.FileName), _clock.GetUtcNow().UtcDateTime);
        await Tick(session);
        Assert.AreEqual(TrayState.Fine, _icon.State);

        // Its scan counts for the interval: the next one is four hours after it.
        _clock.Advance(TimeSpan.FromHours(3.5));
        await Tick(session);
        Assert.AreEqual(1, _scans);
        _clock.Advance(TimeSpan.FromHours(1));
        await Tick(session);
        Assert.AreEqual(2, _scans);

        // Ignoring the check in the window turns the icon green without a scan.
        ScansAnswer(Checks[0]);
        session.Handle(TrayCommand.CheckNow);
        await session.Idle;
        Assert.AreEqual(TrayState.NeedsAttention, _icon.State);
        Settings.Update(settings => settings.WithIgnored(FirewallCheck.Id, "Known", _clock.GetUtcNow()), out _);
        await Tick(session);
        Assert.AreEqual(TrayState.Fine, _icon.State);
    }

    [TestMethod]
    public async Task ACheckTheWindowAlreadyShowedFailing_IsNotNewsLater()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        ScansAnswer();
        await Tick(session);

        _clock.Advance(TimeSpan.FromHours(1));
        Assert.IsTrue(Results.Save(Scan(Checks[0])));
        ScansAnswer(Checks[0]);
        _clock.Advance(TimeSpan.FromHours(4));
        await Tick(session);

        Assert.AreEqual(2, _scans);
        Assert.AreEqual(0, _icon.Notifications.Count);
    }

    [TestMethod]
    public async Task SwitchedOffInSettings_TheIconNeverStarts_OrLeavesAtTheNextTick()
    {
        Settings.Update(settings => settings with { RunInNotificationArea = false }, out _);
        Assert.IsFalse(Session().Start());
        Assert.AreEqual(0, _icon.Updates);

        Settings.Update(settings => settings with { RunInNotificationArea = true }, out _);
        TraySession session = Session();
        Assert.IsTrue(session.Start());
        Settings.Update(settings => settings with { RunInNotificationArea = false }, out _);
        await Tick(session);

        Assert.IsTrue(_icon.HasQuit);
        Assert.AreEqual(0, _scans);

        session.Handle(TrayCommand.Quit);
        Assert.IsTrue(_icon.HasQuit);
    }

    [TestMethod]
    public async Task AScanThatCannotRun_IsSaidAndTriedAgainLater_NotEveryTick()
    {
        _scan = () => throw new InvalidOperationException("made up");
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));

        await Tick(session);
        Assert.AreEqual(1, _scans);
        CollectionAssert.AreEqual(new[] { "The scan could not run: InvalidOperationException" }, _errors);
        Assert.IsFalse(_icon.Busy);
        Assert.AreEqual(TrayState.Unknown, _icon.State, "nothing is known, so nothing is green");

        _clock.Advance(TimeSpan.FromMinutes(5));
        await Tick(session);
        Assert.AreEqual(1, _scans);

        ScansAnswer();
        _clock.Advance(TimeSpan.FromMinutes(11));
        await Tick(session);
        Assert.AreEqual(2, _scans);
        Assert.AreEqual(TrayState.Fine, _icon.State);
    }

    [TestMethod]
    public async Task WhenTheChecksKeepFailingToRun_GreenDoesNotStandForDays()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        ScansAnswer();
        await Tick(session);
        Assert.AreEqual(TrayState.Fine, _icon.State);

        _scan = () => throw new InvalidOperationException("made up");
        _clock.Advance(TimeSpan.FromHours(20));
        await Tick(session);
        Assert.AreEqual(TrayState.Fine, _icon.State, "yesterday's answer still stands for a while");

        _clock.Advance(TimeSpan.FromHours(5));
        await Tick(session);
        Assert.AreEqual(TrayState.Unknown, _icon.State, "a day later nobody knows");
        StringAssert.Contains(_icon.Tooltip, "checked 1 day ago");
    }

    [TestMethod]
    public async Task WhileAScanRuns_TheIconSaysSo_AndASecondOneDoesNotStart()
    {
        var gate = new TaskCompletionSource<ScanResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        _scan = () => gate.Task;
        TraySession session = Session();
        session.Start();

        session.Handle(TrayCommand.CheckNow);
        session.Handle(TrayCommand.CheckNow);
        session.Handle(TrayCommand.Tick);
        Assert.IsTrue(_icon.Busy);
        Assert.AreEqual("SecReview: checking this PC…", _icon.Tooltip);

        gate.SetResult(Scan());
        await session.Idle;

        Assert.AreEqual(1, _scans);
        Assert.IsFalse(_icon.Busy);
    }

    [TestMethod]
    public async Task TheIcon_IsOnlyRedrawnWhenSomethingChanged()
    {
        ScansAnswer();
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        await Tick(session);
        int after = _icon.Updates;

        await Tick(session);
        await Tick(session);

        Assert.AreEqual(after, _icon.Updates);
    }

    [TestMethod]
    public async Task SettingsThatCannotBeReadJustNow_ChangeNothing()
    {
        TraySession session = Session();
        session.Start();
        _clock.Advance(TimeSpan.FromMinutes(2));
        ScansAnswer();
        await Tick(session);
        session.Handle(TrayCommand.PauseHour);

        string file = Path.Combine(_folder, SettingsStore.FileName);
        using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            await Tick(session);
        }

        Assert.AreEqual(TrayState.Snoozed, _icon.State, "the pause stands");
        Assert.IsFalse(_icon.HasQuit);
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>An icon that remembers what it was told. Posted actions run at once.</summary>
    private sealed class Icon : ITrayIcon
    {
        private readonly Lock _gate = new();

        public TrayState State { get; private set; }

        public string Tooltip { get; private set; } = string.Empty;

        public bool Paused { get; private set; }

        public bool Busy { get; private set; }

        public int Updates { get; private set; }

        public bool HasQuit { get; private set; }

        public List<(string Title, string Text)> Notifications { get; } = [];

        public void Update(TrayState state, bool darkTaskbar, string tooltip, bool paused, bool busy)
        {
            (State, Tooltip, Paused, Busy) = (state, tooltip, paused, busy);
            Updates++;
        }

        public void Notify(string title, string text) => Notifications.Add((title, text));

        public void Post(Action action)
        {
            lock (_gate)
            {
                action();
            }
        }

        public void Quit() => HasQuit = true;
    }
}
