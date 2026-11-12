using System.Globalization;
using SecReview.Probing;

namespace SecReview.Checks;

/// <summary>Which checks a run covers.</summary>
public enum CheckSelection
{
    /// <summary>Every check.</summary>
    All,

    /// <summary>
    /// Only machine-scope checks that need administrator rights, or gain detail from them: what
    /// the elevated helper runs. User-scope checks are never part of it.
    /// </summary>
    AdministratorOnly,
}

/// <summary>
/// Runs checks so that one misbehaving check cannot spoil a run: each has a time limit, an
/// exception becomes "could not check", and the others carry on.
/// </summary>
public sealed class CheckRunner
{
    /// <summary>A check that has not answered by then is reported as not finished.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);

    private const int MaximumConcurrency = 4;

    private readonly SystemProbes _probes;
    private readonly TimeProvider _clock;
    private readonly CheckSelection _selection;
    private readonly bool _isElevated;
    private readonly TimeSpan _timeout;
    private readonly PrivacyFilter _privacy;

    /// <param name="probes">How the checks read the machine.</param>
    /// <param name="clock">The clock (a fake in tests).</param>
    /// <param name="selection">Which checks this run covers.</param>
    /// <param name="isElevated">Whether this process has administrator rights.</param>
    /// <param name="timeout">The time limit per check; <see cref="DefaultTimeout"/> if null.</param>
    /// <param name="privacy">Removes user and computer names from results; this process's names if null.</param>
    public CheckRunner(
        SystemProbes probes,
        TimeProvider clock,
        CheckSelection selection,
        bool isElevated,
        TimeSpan? timeout = null,
        PrivacyFilter? privacy = null)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(clock);
        if (timeout is { } limit && limit <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "The time limit must be positive.");
        }

        _probes = probes;
        _clock = clock;
        _selection = selection;
        _isElevated = isElevated;
        _timeout = timeout ?? DefaultTimeout;
        _privacy = privacy ?? PrivacyFilter.ForThisProcess();
    }

    /// <summary>Whether <paramref name="check"/> belongs in a run of the given selection.</summary>
    public static bool IsIncluded(CheckDefinition check, CheckSelection selection)
    {
        ArgumentNullException.ThrowIfNull(check);
        return selection == CheckSelection.All ||
            (check.Scope == CheckScope.Machine && check.NeedsAdmin != AdminNeed.No);
    }

    /// <summary>Runs the selected checks and returns one result each, in the order given.</summary>
    public Task<IReadOnlyList<CheckResult>> RunAsync(IReadOnlyList<ICheck> checks, CancellationToken cancellation = default) =>
        RunAsync(checks, onResult: null, cancellation);

    /// <summary>Runs the selected checks and returns one result each, in the order given.</summary>
    /// <param name="checks">The checks.</param>
    /// <param name="onResult">
    /// Called with each result as soon as it is there, from whichever thread finished it and in
    /// whatever order the checks finish. It must not throw.
    /// </param>
    /// <param name="cancellation">Abandons the run.</param>
    public async Task<IReadOnlyList<CheckResult>> RunAsync(
        IReadOnlyList<ICheck> checks, Action<CheckResult>? onResult, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(checks);

        ICheck[] included = [.. checks.Where(check => IsIncluded(check.Definition, _selection))];
        var results = new CheckResult[included.Length];

        using var gate = new SemaphoreSlim(MaximumConcurrency);
        var runs = new Task[included.Length];
        for (int index = 0; index < included.Length; index++)
        {
            int slot = index;
            runs[slot] = RunGatedAsync(slot);
        }

        await Task.WhenAll(runs).ConfigureAwait(false);
        return results;

        async Task RunGatedAsync(int slot)
        {
            await gate.WaitAsync(cancellation).ConfigureAwait(false);
            try
            {
                results[slot] = await RunOneAsync(included[slot], cancellation).ConfigureAwait(false);
                onResult?.Invoke(results[slot]);
            }
            finally
            {
                gate.Release();
            }
        }
    }

    /// <summary>Runs a single check (for "Check again"). It must belong to this run's selection.</summary>
    public async Task<CheckResult> RunOneAsync(ICheck check, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(check);
        if (!IsIncluded(check.Definition, _selection))
        {
            // In particular: a user-scope check must never run in the elevated helper, where
            // it would read another account's settings.
            throw new InvalidOperationException(
                $"Check '{check.Definition.Id}' is not part of a run that covers {_selection}.");
        }

        long started = _clock.GetTimestamp();

        CheckOutcome outcome;
        if (_isElevated && check.Definition.Scope == CheckScope.User)
        {
            // An elevated process may be running under another administrator's account, whose
            // settings and files are not the signed-in user's. Reading them would report on the
            // wrong person, so the check is not run at all.
            outcome = CheckOutcome.Error(
                "Not checked: this reads your own settings, which an administrator session cannot " +
                "see reliably. Run SecReview without administrator rights.");
        }
        else if (!_isElevated && check.Definition.NeedsAdmin == AdminNeed.Yes)
        {
            outcome = CheckOutcome.NeedsAdmin("This check needs administrator rights.");
        }
        else
        {
            outcome = await RunWithLimitAsync(check, cancellation).ConfigureAwait(false);
        }

        return new CheckResult(
            check.Definition.Id,
            _privacy.Scrub(outcome),
            _clock.GetUtcNow(),
            _isElevated,
            _clock.GetElapsedTime(started));
    }

    private async Task<CheckOutcome> RunWithLimitAsync(ICheck check, CancellationToken cancellation)
    {
        // The check gets its own token: it is signalled when the time limit passes, so a check
        // that looks at it can stop, but a check stuck inside Windows is simply left behind.
        using var abandoned = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var context = new CheckContext(_probes, _clock, _isElevated, abandoned.Token);

        Task<CheckOutcome> run = Task.Run(() => Guard(check, context), CancellationToken.None);
        try
        {
            return await run.WaitAsync(_timeout, _clock, cancellation).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            await abandoned.CancelAsync().ConfigureAwait(false);

            // Left running in the background; its eventual result is ignored (Guard never throws).
            return CheckOutcome.Error(string.Create(
                CultureInfo.InvariantCulture,
                $"The check did not finish within {_timeout.TotalSeconds:0} seconds."));
        }
    }

    /// <summary>Runs the check and turns anything unexpected into "could not check".</summary>
    private static CheckOutcome Guard(ICheck check, CheckContext context)
    {
        try
        {
            CheckOutcome? outcome = check.Run(context);
            if (outcome is null || string.IsNullOrWhiteSpace(outcome.Summary))
            {
                return CheckOutcome.Error("The check returned no result.");
            }

            return outcome;
        }
#pragma warning disable CA1031 // Any exception from a check must become a result, not end the run.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return CheckOutcome.Error($"The check failed unexpectedly: {exception.GetType().Name}: {exception.Message}");
        }
    }
}
