using System.Text.Json;
using System.Text.Json.Serialization;
using SecReview.Diagnostics;

namespace SecReview.Settings;

/// <summary>A check the user chose to leave out of the count, with the reason they gave.</summary>
/// <param name="CheckId">The check's identifier.</param>
/// <param name="Reason">Why it is ignored, in the user's words.</param>
/// <param name="Since">When it was ignored.</param>
public sealed record IgnoredCheck(string CheckId, string Reason, DateTimeOffset Since);

/// <summary>What SecReview remembers between runs. Results are not part of it.</summary>
public sealed record AppSettings
{
    /// <summary>The shape of the settings file. A file of another version is not used.</summary>
    public const int CurrentVersion = 1;

    /// <summary>The longest reason kept for an ignored check.</summary>
    public const int MaximumReasonLength = 200;

    /// <summary>More ignored checks than there could ever be checks means the file is not ours.</summary>
    public const int MaximumIgnored = 1000;

    public int Version { get; init; } = CurrentVersion;

    /// <summary>Whether the first-run notice has been shown and closed.</summary>
    public bool FirstRunDone { get; init; }

    /// <summary>Whether errors of SecReview itself may be reported. Results never are.</summary>
    public bool SendErrorReports { get; init; } = true;

    /// <summary>The ignored checks, oldest first.</summary>
    public IReadOnlyList<IgnoredCheck> Ignored { get; init; } = [];

    /// <summary>The entry for an ignored check; null when it is not ignored.</summary>
    public IgnoredCheck? IgnoredOf(string checkId) =>
        Ignored.FirstOrDefault(entry => entry.CheckId.Equals(checkId, StringComparison.Ordinal));

    /// <summary>The identifiers of the ignored checks.</summary>
    public IReadOnlySet<string> IgnoredIds() => Ignored.Select(entry => entry.CheckId).ToHashSet(StringComparer.Ordinal);

    /// <summary>These settings with a check ignored (replacing an earlier reason). The reason is trimmed and cut to its limit.</summary>
    public AppSettings WithIgnored(string checkId, string reason, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(checkId);
        ArgumentNullException.ThrowIfNull(reason);

        string kept = Clean(reason);
        return this with
        {
            Ignored = [.. Ignored.Where(entry => !entry.CheckId.Equals(checkId, StringComparison.Ordinal)), new IgnoredCheck(checkId, kept, now)],
        };
    }

    /// <summary>These settings with a check no longer ignored.</summary>
    public AppSettings WithoutIgnored(string checkId) =>
        this with { Ignored = [.. Ignored.Where(entry => !entry.CheckId.Equals(checkId, StringComparison.Ordinal))] };

    /// <summary>A reason as it is kept: one line, trimmed, within the limit.</summary>
    public static string Clean(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);
        string oneLine = string.Join(' ', reason.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        string printable = new([.. oneLine.Where(c => !char.IsControl(c))]);
        return printable.Length <= MaximumReasonLength ? printable : printable[..MaximumReasonLength].TrimEnd();
    }
}

/// <summary>
/// Reads and writes the settings file. Reading never fails: a file that is missing, damaged or
/// of another version gives the defaults, and a damaged one is kept aside under another name so
/// nothing the user typed is thrown away unseen. Writing replaces the file in one step.
/// </summary>
public sealed class SettingsStore
{
    /// <summary>The file's name in the data folder.</summary>
    public const string FileName = "settings.json";

    /// <summary>A settings file larger than this is not ours.</summary>
    private const int MaximumBytes = 1024 * 1024;

    private readonly string _path;

    /// <summary>
    /// Set when a settings file is there but could not be read or moved aside. Saving would
    /// then replace settings nobody has seen, so it is refused until a read succeeds.
    /// </summary>
    private bool _mustNotOverwrite;

    public SettingsStore(string folder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        _path = Path.Combine(folder, FileName);
    }

    /// <summary>The settings, or the defaults. <paramref name="problem"/> says why a file that is there was not used.</summary>
    public AppSettings Load(out string? problem)
    {
        problem = null;
        _mustNotOverwrite = false;
        try
        {
            var file = new FileInfo(_path);
            if (!file.Exists)
            {
                return new AppSettings();
            }

            if (file.Length > MaximumBytes)
            {
                problem = "The settings file is too large to be SecReview's.";
                return SetAside();
            }

            AppSettings? read = JsonSerializer.Deserialize(File.ReadAllBytes(_path), SettingsJson.Default.AppSettings);
            if (read is null || read.Version != AppSettings.CurrentVersion)
            {
                problem = "The settings file is from another version of SecReview.";
                return SetAside();
            }

            return Checked(read);
        }
        catch (JsonException)
        {
            problem = "The settings file could not be understood.";
            return SetAside();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The file may be perfectly good and only held by another program for a moment.
            _mustNotOverwrite = true;
            problem = $"The settings file could not be read ({exception.GetType().Name}). Changes are not saved until it can be.";
            return new AppSettings();
        }
    }

    /// <summary>Saves the settings. False, with the reason, when they could not be written.</summary>
    public bool Save(AppSettings settings, out string? problem)
    {
        ArgumentNullException.ThrowIfNull(settings);
        problem = null;
        if (_mustNotOverwrite)
        {
            // Try once more: what kept the file from being read may be gone.
            Load(out _);
            if (_mustNotOverwrite)
            {
                problem = "The settings were not saved: the settings file on disk cannot be read, and saving would replace it.";
                return false;
            }
        }

        try
        {
            AtomicFile.Write(_path, JsonSerializer.SerializeToUtf8Bytes(Checked(settings), SettingsJson.Default.AppSettings));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            problem = $"The settings could not be saved ({exception.GetType().Name}).";
            return false;
        }
    }

    /// <summary>What was read, kept only where it makes sense: no entry without a check, none twice, reasons within their limit.</summary>
    private static AppSettings Checked(AppSettings settings)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var ignored = new List<IgnoredCheck>();
        foreach (IgnoredCheck? entry in settings.Ignored ?? [])
        {
            if (entry is { CheckId: { Length: > 0 and <= 100 } id } && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_') &&
                seen.Add(id) && ignored.Count < AppSettings.MaximumIgnored)
            {
                ignored.Add(entry with { Reason = AppSettings.Clean(entry.Reason ?? string.Empty) });
            }
        }

        return settings with { Version = AppSettings.CurrentVersion, Ignored = ignored };
    }

    /// <summary>Moves a file that cannot be used out of the way and returns the defaults.</summary>
    private AppSettings SetAside()
    {
        try
        {
            // A name of its own each time, so one damaged file never replaces another.
            File.Move(_path, $"{_path}.unreadable-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _mustNotOverwrite = true;
        }

        return new AppSettings();
    }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    ReadCommentHandling = JsonCommentHandling.Disallow)]
[JsonSerializable(typeof(AppSettings))]
internal sealed partial class SettingsJson : JsonSerializerContext;
