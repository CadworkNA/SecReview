namespace SecReview.Probing;

/// <summary>How a read of machine state ended.</summary>
public enum ProbeStatus
{
    /// <summary>
    /// The read failed; <see cref="ProbeResult{T}.Detail"/> says why. This is the zero value on
    /// purpose: a result nobody filled in reads as a failure, never as a success.
    /// </summary>
    Failed = 0,

    /// <summary>The value was read.</summary>
    Ok,

    /// <summary>The thing asked about does not exist (a registry value, a file, a service).</summary>
    NotFound,

    /// <summary>Reading it needs rights this process does not have.</summary>
    AccessDenied,

    /// <summary>This edition or version of Windows does not have it.</summary>
    NotSupported,
}

/// <summary>
/// The outcome of reading machine state: a value, or the reason there is none. Checks turn
/// anything other than <see cref="ProbeStatus.Ok"/> into "could not check" or "needs
/// administrator"; a failed read is never treated as a passing value.
/// </summary>
public readonly record struct ProbeResult<T>
{
    private ProbeResult(ProbeStatus status, T? value, string? detail)
    {
        Status = status;
        Value = value;
        Detail = detail;
    }

    public ProbeStatus Status { get; }

    /// <summary>The value read; meaningful only when <see cref="IsOk"/>.</summary>
    public T? Value { get; }

    /// <summary>Why there is no value, in words fit to show the user.</summary>
    public string? Detail { get; }

    public bool IsOk => Status == ProbeStatus.Ok;

#pragma warning disable CA1000 // A factory on the generic type reads best at call sites.
    public static ProbeResult<T> Ok(T value) => new(ProbeStatus.Ok, value, null);
#pragma warning restore CA1000

#pragma warning disable CA2225 // The named alternative is ProbeFailure itself.
    public static implicit operator ProbeResult<T>(ProbeFailure failure) =>
        new(failure.Status, default, failure.Detail);
#pragma warning restore CA2225

    /// <summary>The same failure, typed for another value.</summary>
    public ProbeFailure ToFailure() => IsOk
        ? throw new InvalidOperationException("A successful result is not a failure.")
        : new ProbeFailure(Status, Detail);
}

/// <summary>A failed read, convertible to any <see cref="ProbeResult{T}"/>.</summary>
public readonly record struct ProbeFailure
{
    internal ProbeFailure(ProbeStatus status, string? detail)
    {
        if (status == ProbeStatus.Ok)
        {
            throw new ArgumentException("Ok is not a failure.", nameof(status));
        }

        Status = status;
        Detail = detail;
    }

    public ProbeStatus Status { get; }

    public string? Detail { get; }

    public static ProbeFailure NotFound(string? detail = null) => new(ProbeStatus.NotFound, detail);

    public static ProbeFailure AccessDenied(string? detail = null) => new(ProbeStatus.AccessDenied, detail);

    public static ProbeFailure NotSupported(string detail) => new(ProbeStatus.NotSupported, detail);

    public static ProbeFailure Failed(string detail) => new(ProbeStatus.Failed, detail);
}
