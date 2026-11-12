using System.Text.Json;
using SecReview.Diagnostics;

namespace SecReview.Updates;

/// <summary>How the last look for updates ended.</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter<UpdateOutcome>))]
public enum UpdateOutcome
{
    /// <summary>Nobody has looked yet. The zero value on purpose: "not known" is never "up to date".</summary>
    Unknown = 0,

    /// <summary>This is the newest version.</summary>
    UpToDate,

    /// <summary>A newer version is there.</summary>
    Available,

    /// <summary>Looking failed; <see cref="UpdateState.Problem"/> says why.</summary>
    Failed,
}

/// <summary>
/// What SecReview knows about updates, kept in its data folder (<c>update.json</c>) so the
/// window, the notification-area icon and the check agree and the server is asked once a day,
/// not by each of them.
/// </summary>
public sealed record UpdateState
{
    /// <summary>The file's name in the data folder.</summary>
    public const string FileName = "update.json";

    public const int CurrentVersion = 1;

    public int Version { get; init; } = CurrentVersion;

    /// <summary>When SecReview last looked; null when it never has.</summary>
    public DateTimeOffset? CheckedAt { get; init; }

    public UpdateOutcome Outcome { get; init; }

    /// <summary>The version of SecReview that looked. What an older version found says nothing about this one.</summary>
    public string? CheckedBy { get; init; }

    /// <summary>The newest version, when <see cref="Outcome"/> is <see cref="UpdateOutcome.Available"/>.</summary>
    public string? Available { get; init; }

    /// <summary>When that version was published.</summary>
    public DateTimeOffset? Published { get; init; }

    /// <summary>What is new in it.</summary>
    public string? Notes { get; init; }

    /// <summary>Why looking failed, in words fit to show.</summary>
    public string? Problem { get; init; }

    /// <summary>The state as far as it can be believed by this version at this time: anything else is "not known".</summary>
    public UpdateState For(string installed, DateTimeOffset now)
    {
        // Found by another version, or dated after now: it says nothing reliable.
        if (CheckedBy != installed || CheckedAt is not { } checkedAt || checkedAt > now.AddMinutes(5))
        {
            return new UpdateState();
        }

        // "Available" must still be newer than what runs now, and well-formed.
        if (Outcome == UpdateOutcome.Available && (Available is null || !UpdateRules.IsNewer(Available, installed)))
        {
            return new UpdateState();
        }

        return this;
    }
}

/// <summary>Reads and writes <see cref="UpdateState"/>. Never throws: a file that cannot be used reads as "not known".</summary>
public sealed class UpdateStateStore
{
    private const int MaximumBytes = 64 * 1024;

    private readonly string _path;

    public UpdateStateStore(string folder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        _path = Path.Combine(folder, UpdateState.FileName);
    }

    public UpdateState Load()
    {
        try
        {
            var file = new FileInfo(_path);
            if (!file.Exists || file.Length > MaximumBytes)
            {
                return new UpdateState();
            }

            return FromBytes(AtomicFile.Read(_path));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new UpdateState();
        }
    }

    /// <summary>The state from the file's bytes; "not known" when they are not a state of this version.</summary>
    public static UpdateState FromBytes(ReadOnlySpan<byte> bytes)
    {
        try
        {
            UpdateState? read = bytes.Length <= MaximumBytes ? JsonSerializer.Deserialize(bytes, UpdateJson.Default.UpdateState) : null;
            if (read is not { Version: UpdateState.CurrentVersion })
            {
                return new UpdateState();
            }

            // Text from the file is shown in the window: kept to a sensible length.
            return read with
            {
                Available = Fit(read.Available, 64),
                Notes = Fit(read.Notes, UpdateManifest.MaximumNotesLength),
                Problem = Fit(read.Problem, 300),
                CheckedBy = Fit(read.CheckedBy, 64),
            };
        }
        catch (JsonException)
        {
            return new UpdateState();
        }
    }

    public bool Save(UpdateState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        try
        {
            AtomicFile.Write(_path, JsonSerializer.SerializeToUtf8Bytes(state, UpdateJson.Default.UpdateState));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string? Fit(string? text, int maximum) => text is null || text.Length <= maximum ? text : text[..maximum];
}
