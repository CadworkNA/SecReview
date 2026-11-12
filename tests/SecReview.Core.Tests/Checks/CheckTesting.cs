using SecReview.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

/// <summary>Runs a check against fake probes, the way the runner would.</summary>
internal static class CheckTesting
{
    public static CheckOutcome Run(this ICheck check, FakeProbes probes, bool elevated = false) =>
        check.Run(new CheckContext(probes.Build(), TimeProvider.System, elevated, CancellationToken.None));

    /// <summary>The findings as "item: found (expected) [status]" lines, for compact assertions.</summary>
    public static string[] Rows(this CheckOutcome outcome) =>
        [.. outcome.Findings.Select(f => f.Status == FindingStatus.Note
            ? $"{f.Item}: {f.Found} [note]"
            : $"{f.Item}: {f.Found} (expected {f.Expected}) [{(f.Status == FindingStatus.Ok ? "ok" : "problem")}]")];
}
