using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.Scanning;

/// <summary>One check as shown to the user: what it is, how it is worded, and how it ended.</summary>
/// <param name="Definition">The check.</param>
/// <param name="Text">Its wording.</param>
/// <param name="Result">
/// The latest answer. When <see cref="Administrator"/> is set, this is the latest answer read
/// without administrator rights.
/// </param>
public sealed record ScannedCheck(CheckDefinition Definition, CheckText Text, CheckResult Result)
{
    /// <summary>
    /// An earlier answer read with administrator rights, kept beside <see cref="Result"/> (read
    /// without them) so that neither replaces the other; null when there is none. Each is shown
    /// with its own date, and each is replaced only by a newer answer of its own kind.
    /// </summary>
    public CheckResult? Administrator { get; init; }

    /// <summary>
    /// The answer that decides where the check stands, its title and its summary. The
    /// administrator answer decides when it says something worse, or when the other answer
    /// read nothing more than "needs administrator rights" for a check only an administrator
    /// can answer in full. Otherwise the answer read without the rights, the newer one, does.
    /// </summary>
    public CheckResult Shown => Administrator is { } administrator && AdministratorDecides(administrator) ? administrator : Result;

    /// <summary>The title that matches the outcome (see <see cref="CheckText.TitleFor"/>).</summary>
    public string Title => Text.TitleFor(Shown.Outcome.Status);

    private bool AdministratorDecides(CheckResult administrator)
    {
        CheckStatus ordinary = Result.Outcome.Status;
        if (ordinary == CheckStatus.NeedsAdmin && (Definition.NeedsAdmin == AdminNeed.Yes || Definition.KeepsAdministratorAnswer))
        {
            return true;
        }

        return Weight(administrator.Outcome.Status) > Weight(ordinary);
    }

    /// <summary>How much an answer says is wrong: a failure, then "could not check", then "needs administrator".</summary>
    private static int Weight(CheckStatus status) => status switch
    {
        CheckStatus.Fail => 4,
        CheckStatus.Error => 3,
        CheckStatus.NeedsAdmin => 2,
        CheckStatus.Pass => 1,
        _ => 0,
    };
}

/// <summary>A finished scan.</summary>
/// <param name="Checks">Every check that ran, in catalogue order.</param>
/// <param name="FinishedAt">When the scan finished.</param>
/// <param name="Elevated">Whether it ran with administrator rights.</param>
public sealed record ScanResult(IReadOnlyList<ScannedCheck> Checks, DateTimeOffset FinishedAt, bool Elevated)
{
    public int Count(CheckStatus status) => Checks.Count(c => c.Shown.Outcome.Status == status);
}

/// <summary>Runs the catalogue of checks and pairs each result with its wording.</summary>
public sealed class Scanner
{
    private readonly IReadOnlyList<ICheck> _checks;
    private readonly CheckTexts _texts;
    private readonly SystemProbes _probes;
    private readonly TimeProvider _clock;

    /// <summary>
    /// Called with a check's identifier and the error when a check throws (a bug in SecReview).
    /// The result still says "could not check"; this is for reporting the bug. It must not throw.
    /// </summary>
    public Action<string, Exception>? OnUnexpectedError { get; init; }

    public Scanner(SystemProbes probes, TimeProvider clock)
        : this(probes, clock, CheckCatalogue.Checks, CheckCatalogue.Texts)
    {
    }

    public Scanner(SystemProbes probes, TimeProvider clock, IReadOnlyList<ICheck> checks, CheckTexts texts)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(texts);

        _probes = probes;
        _clock = clock;
        _checks = checks;
        _texts = texts;
    }

    /// <summary>The checks this scanner runs.</summary>
    public IReadOnlyList<ICheck> Checks => _checks;

    /// <param name="selection">Which checks to run.</param>
    /// <param name="isElevated">Whether this process has administrator rights.</param>
    /// <param name="cancellation">Abandons the scan.</param>
    public Task<ScanResult> RunAsync(CheckSelection selection, bool isElevated, CancellationToken cancellation = default) =>
        RunAsync(selection, isElevated, onResult: null, cancellation);

    /// <param name="selection">Which checks to run.</param>
    /// <param name="isElevated">Whether this process has administrator rights.</param>
    /// <param name="onResult">
    /// Called with each check as soon as it has answered, from another thread and in whatever
    /// order the checks finish, so a window can fill in while the slow checks still run.
    /// </param>
    /// <param name="cancellation">Abandons the scan.</param>
    public async Task<ScanResult> RunAsync(
        CheckSelection selection, bool isElevated, Action<ScannedCheck>? onResult, CancellationToken cancellation = default)
    {
        // Readings that several checks share are taken once per scan.
        var runner = new CheckRunner(ScanCache.ForOneScan(_probes), _clock, selection, isElevated, onUnexpected: OnUnexpectedError);
        Dictionary<string, CheckDefinition> definitions = _checks.ToDictionary(c => c.Definition.Id, c => c.Definition);
        ScannedCheck Scanned(CheckResult result) => new(definitions[result.CheckId], _texts[result.CheckId], result);

        IReadOnlyList<CheckResult> results = await runner
            .RunAsync(_checks, onResult is null ? null : result => onResult(Scanned(result)), cancellation)
            .ConfigureAwait(false);

        return new ScanResult([.. results.Select(Scanned)], _clock.GetUtcNow(), isElevated);
    }

    /// <summary>Runs one check again, with fresh readings ("Check again" on a row).</summary>
    /// <exception cref="ArgumentException">No check has that identifier.</exception>
    public async Task<ScannedCheck> RunOneAsync(string checkId, bool isElevated, CancellationToken cancellation = default)
    {
        ICheck check = _checks.FirstOrDefault(c => c.Definition.Id == checkId)
            ?? throw new ArgumentException($"There is no check '{checkId}'.", nameof(checkId));

        var runner = new CheckRunner(ScanCache.ForOneScan(_probes), _clock, CheckSelection.All, isElevated, onUnexpected: OnUnexpectedError);
        CheckResult result = await runner.RunOneAsync(check, cancellation).ConfigureAwait(false);
        return new ScannedCheck(check.Definition, _texts[checkId], result);
    }
}
