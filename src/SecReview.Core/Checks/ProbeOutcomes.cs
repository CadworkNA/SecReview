using SecReview.Probing;

namespace SecReview.Checks;

/// <summary>Turns a failed reading into the honest outcome for the check that needed it.</summary>
public static class ProbeOutcomes
{
    /// <summary>
    /// The outcome when a reading the check depends on gave no value: administrator rights
    /// needed, or could not check. Never a pass or a fail, and never "does not apply": that a
    /// way of reading something is missing on this Windows does not mean the check is
    /// irrelevant. A check that knows it does not apply says so itself.
    /// </summary>
    /// <param name="status">How the reading ended.</param>
    /// <param name="detail">The reading's own explanation, if it gave one.</param>
    /// <param name="what">What was being read, for the message: "the firewall state".</param>
    public static CheckOutcome FromFailure(ProbeStatus status, string? detail, string what) => status switch
    {
        ProbeStatus.Ok => throw new ArgumentException("A successful reading is not a failure.", nameof(status)),
        ProbeStatus.AccessDenied =>
            CheckOutcome.NeedsAdmin($"Reading {what} needs administrator rights."),
        ProbeStatus.NotSupported =>
            CheckOutcome.Error(detail ?? $"This edition of Windows offers no way to read {what}."),
        ProbeStatus.NotFound =>
            CheckOutcome.Error($"Could not find {what}."),
        _ => CheckOutcome.Error(detail ?? $"Could not read {what}."),
    };

    public static CheckOutcome FromFailure<T>(ProbeResult<T> result, string what) =>
        FromFailure(result.Status, result.Detail, what);
}
