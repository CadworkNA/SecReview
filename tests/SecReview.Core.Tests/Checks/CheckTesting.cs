using SecReview.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

/// <summary>Runs a check against fake probes, the way the runner would.</summary>
internal static class CheckTesting
{
    /// <summary>The moment every check that looks at the time is tested at.</summary>
    public static readonly DateTimeOffset Now = new(2026, 11, 11, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The check's answer for this fake PC. The check is then run against damaged copies of the
    /// same PC too (see <see cref="DamagedCopies"/>), so every test that runs a check also
    /// proves that the check survives damage to what that test made it read.
    /// </summary>
    public static CheckOutcome Run(this ICheck check, FakeProbes probes, bool elevated = false, DateTimeOffset? now = null)
    {
        var clock = new FixedClock(now ?? Now);
        CheckOutcome outcome = check.Run(new CheckContext(probes.Build(), clock, elevated, CancellationToken.None));
        DamagedCopies.Verify(check, probes, clock, elevated);
        return outcome;
    }

    /// <summary>The findings as "item: found (expected) [status]" lines, for compact assertions.</summary>
    public static string[] Rows(this CheckOutcome outcome) =>
        [.. outcome.Findings.Select(f => f.Status == FindingStatus.Note
            ? $"{f.Item}: {f.Found} [note]"
            : $"{f.Item}: {f.Found} (expected {f.Expected}) [{(f.Status == FindingStatus.Ok ? "ok" : "problem")}]")];

    /// <summary>A clock that always shows the same moment.</summary>
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
