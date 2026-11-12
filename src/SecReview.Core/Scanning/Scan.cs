using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;

namespace SecReview.Scanning;

/// <summary>One check as shown to the user: what it is, how it is worded, and how it ended.</summary>
public sealed record ScannedCheck(CheckDefinition Definition, CheckText Text, CheckResult Result)
{
    /// <summary>The title that matches the outcome (see <see cref="CheckText.TitleFor"/>).</summary>
    public string Title => Text.TitleFor(Result.Outcome.Status);
}

/// <summary>A finished scan.</summary>
/// <param name="Checks">Every check that ran, in catalogue order.</param>
/// <param name="FinishedAt">When the scan finished.</param>
/// <param name="Elevated">Whether it ran with administrator rights.</param>
public sealed record ScanResult(IReadOnlyList<ScannedCheck> Checks, DateTimeOffset FinishedAt, bool Elevated)
{
    public int Count(CheckStatus status) => Checks.Count(c => c.Result.Outcome.Status == status);
}

/// <summary>Runs the catalogue of checks and pairs each result with its wording.</summary>
public sealed class Scanner
{
    private readonly IReadOnlyList<ICheck> _checks;
    private readonly CheckTexts _texts;
    private readonly SystemProbes _probes;
    private readonly TimeProvider _clock;

    public Scanner(SystemProbes probes, TimeProvider clock)
        : this(probes, clock, BuiltInChecks.All, CheckTexts.Load())
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
    public async Task<ScanResult> RunAsync(
        CheckSelection selection, bool isElevated, CancellationToken cancellation = default)
    {
        // Readings that several checks share are taken once per scan.
        var runner = new CheckRunner(ScanCache.ForOneScan(_probes), _clock, selection, isElevated);
        IReadOnlyList<CheckResult> results = await runner.RunAsync(_checks, cancellation).ConfigureAwait(false);

        Dictionary<string, CheckDefinition> definitions = _checks.ToDictionary(c => c.Definition.Id, c => c.Definition);
        return new ScanResult(
            [.. results.Select(r => new ScannedCheck(definitions[r.CheckId], _texts[r.CheckId], r))],
            _clock.GetUtcNow(),
            isElevated);
    }
}
