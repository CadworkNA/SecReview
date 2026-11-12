using SecReview.Probing;

namespace SecReview.Updates;

/// <summary>
/// Looks for updates when it is time, for the window and the notification-area icon alike:
/// what one of them found is kept in the data folder and serves the other, so the server is
/// asked once a day. A build without an update address, or a PC whose organisation said no,
/// never asks.
/// </summary>
public sealed class UpdateService
{
    private readonly UpdateSource _source;
    private readonly UpdateStateStore _store;
    private readonly Func<IUpdateTransport> _transport;
    private readonly TimeProvider _clock;
    private readonly string _installed;
    private readonly Func<UpdatePolicy> _policy;
    private readonly double _spread;
    private int _looking;
    private long? _lastLook;

    /// <summary>
    /// However the kept answer reads (or cannot be written), one process asks the server at
    /// most this often by itself.
    /// </summary>
    public static readonly TimeSpan MinimumGap = TimeSpan.FromMinutes(30);

    /// <param name="source">Where this build looks.</param>
    /// <param name="store">Where what was found is kept.</param>
    /// <param name="transport">Makes the fetcher, only when a look is really made.</param>
    /// <param name="clock">The time.</param>
    /// <param name="installed">The running version.</param>
    /// <param name="policy">Reads what the organisation decided.</param>
    /// <param name="spread">A fraction of an hour that differs per PC, so all PCs do not ask at once.</param>
    public UpdateService(
        UpdateSource source, UpdateStateStore store, Func<IUpdateTransport> transport, TimeProvider clock, string installed, Func<UpdatePolicy> policy, double spread)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentException.ThrowIfNullOrWhiteSpace(installed);
        ArgumentNullException.ThrowIfNull(policy);
        _source = source;
        _store = store;
        _transport = transport;
        _clock = clock;
        _installed = installed;
        _policy = policy;
        _spread = spread;
    }

    /// <summary>The service of this build, for a data folder and a way to read the policy.</summary>
    public static UpdateService ForThisBuild(string dataFolder, IRegistryProbe registry) => new(
        UpdateSource.Compiled,
        new UpdateStateStore(dataFolder),
        () => new HttpUpdateTransport(UpdateSource.Compiled),
        TimeProvider.System,
        ProductInfo.Version,
        () => UpdatePolicy.Read(registry),
        Random.Shared.NextDouble());

    /// <summary>Whether this build, on this PC, looks for updates at all.</summary>
    public bool IsOn => _source.IsConfigured && !_policy().NoUpdateCheck;

    /// <summary>Whether an update may be installed from SecReview (the organisation may allow only the notice).</summary>
    public bool MayInstall => IsOn && !_policy().NoSelfUpdate;

    /// <summary>What is known right now, without asking anybody.</summary>
    public UpdateState Known() => IsOn ? _store.Load().For(_installed, _clock.GetUtcNow()) : new UpdateState();

    /// <summary>
    /// Looks if it is time (or at once, when <paramref name="now"/> is set) and returns what
    /// is known afterwards. Never throws. One look at a time: a second call while one runs
    /// returns what is known.
    /// </summary>
    public async Task<UpdateState> LookAsync(bool now = false, CancellationToken cancellation = default)
    {
        if (!IsOn)
        {
            return new UpdateState();
        }

        UpdateState known = Known();
        if (!now && !UpdateRules.IsCheckDue(known, _clock.GetUtcNow(), _spread))
        {
            return known;
        }

        if (!now && _lastLook is { } last && _clock.GetElapsedTime(last) < MinimumGap)
        {
            return known;
        }

        if (Interlocked.Exchange(ref _looking, 1) != 0)
        {
            return known;
        }

        try
        {
            _lastLook = _clock.GetTimestamp();
            IUpdateTransport transport = _transport();
            try
            {
                UpdateState found = await new UpdateChecker(_source, transport, _clock, _installed).CheckAsync(cancellation).ConfigureAwait(false);
                _store.Save(found);
                return found;
            }
            finally
            {
                (transport as IDisposable)?.Dispose();
            }
        }
        catch (OperationCanceledException)
        {
            return known;
        }
        finally
        {
            Volatile.Write(ref _looking, 0);
        }
    }

    /// <summary>The notice for a newer version: "Version 1.4.0 is available, released 3 days ago."; null when there is none.</summary>
    public static string? Notice(UpdateState state, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Outcome != UpdateOutcome.Available || state.Available is null)
        {
            return null;
        }

        return state.Published is { } published
            ? $"Version {state.Available} is available, released {Scanning.ScanPresentation.Age(published, now)}."
            : $"Version {state.Available} is available.";
    }
}
