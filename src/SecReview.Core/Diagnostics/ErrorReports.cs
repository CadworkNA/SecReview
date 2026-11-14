using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.Diagnostics;

/// <summary>Whether errors of SecReview itself are reported, and if not, why not.</summary>
public enum ErrorReportsState
{
    /// <summary>
    /// This build has nowhere to send reports: a development build, or one somebody else
    /// compiled. The zero value on purpose: nothing is sent unless everything says so.
    /// </summary>
    NoAddress = 0,

    /// <summary>The organisation has switched reports off for this PC.</summary>
    OffByPolicy,

    /// <summary>The user has switched reports off.</summary>
    OffBySetting,

    /// <summary>
    /// The user's choice is not known: the settings could not be read, or the notice that
    /// tells them about reports has not been closed yet. Nothing is sent until it is known.
    /// </summary>
    NotYetKnown,

    On,
}

/// <summary>What the user has said about error reports, as far as it is known.</summary>
/// <param name="SwitchOn">The switch in Settings.</param>
/// <param name="SettingsWereRead">False when the settings file could not be read or used: the switch shown is then only the default.</param>
/// <param name="NoticeSeen">Whether the first-run notice, which says that errors are reported, has been closed.</param>
public readonly record struct ErrorReportsChoice(bool SwitchOn, bool SettingsWereRead, bool NoticeSeen);

/// <summary>
/// The rules for reporting errors of SecReview itself, apart from the library that sends them,
/// so that they can be tested. A report holds an error's type and where in SecReview it
/// happened, and the versions of SecReview, Windows and .NET. Never a message (it can quote
/// anything), never a check's result or finding (which checks fail on which PC is a map of its
/// weaknesses), never the computer's or the user's name or a path, never an identifier.
/// </summary>
public static class ErrorReports
{
    /// <summary>Where an organisation's settings for SecReview live (under HKEY_LOCAL_MACHINE).</summary>
    public const string PolicyKey = @"SOFTWARE\Policies\SecReview";

    /// <summary>The policy value that switches error reports off when it is not zero.</summary>
    public const string PolicyValue = "NoErrorReports";

    /// <summary>The assembly metadata key the build writes the address for reports under.</summary>
    public const string AddressMetadataKey = "ErrorReportAddress";

    /// <summary>The one message SecReview sends that is not an error: a fixed text.</summary>
    public const string AbnormalEndMessage = "The previous run of SecReview ended without closing down.";

    /// <summary>The longest feedback text sent.</summary>
    public const int MaximumFeedbackLength = 2000;

    /// <summary>
    /// Whether reports are sent. The policy is read first and wins; when it cannot be read,
    /// nothing is sent: an organisation that said no must not be overruled by a failed read.
    /// Then the user: nothing is sent while their choice is not known.
    /// </summary>
    /// <param name="address">Where reports go; null or empty for a build without one.</param>
    /// <param name="choice">What the user has said.</param>
    /// <param name="registry">How the policy is read.</param>
    public static ErrorReportsState State(string? address, ErrorReportsChoice choice, IRegistryProbe registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        if (string.IsNullOrWhiteSpace(address))
        {
            return ErrorReportsState.NoAddress;
        }

        ProbeResult<RegistryValue> policy = registry.GetValue(RegistryRoot.LocalMachine, PolicyKey, PolicyValue);
        if (policy.IsOk ? policy.Value is not { Type: RegistryValueType.Number, Number: 0 } : policy.Status != ProbeStatus.NotFound)
        {
            return ErrorReportsState.OffByPolicy;
        }

        if (!choice.SettingsWereRead || !choice.NoticeSeen)
        {
            return ErrorReportsState.NotYetKnown;
        }

        return choice.SwitchOn ? ErrorReportsState.On : ErrorReportsState.OffBySetting;
    }

    /// <summary>The state in a sentence, for the settings dialog.</summary>
    public static string Describe(ErrorReportsState state) => state switch
    {
        ErrorReportsState.On => "On. Only errors of SecReview itself are sent, never results.",
        ErrorReportsState.OffBySetting => "Off.",
        ErrorReportsState.OffByPolicy => "Switched off by your organisation.",
        ErrorReportsState.NotYetKnown => "Nothing is sent until the welcome notice has been closed and the settings can be read.",
        _ => "This build of SecReview has nowhere to send reports, so nothing is sent.",
    };

    /// <summary>A text the user typed, as it may be sent: names removed, within a limit.</summary>
    public static string Text(string? text, PrivacyFilter privacy, int maximumLength)
    {
        ArgumentNullException.ThrowIfNull(privacy);
        string scrubbed = privacy.Scrub((text ?? string.Empty).Trim());
        return scrubbed.Length <= maximumLength ? scrubbed : scrubbed[..maximumLength];
    }

    /// <summary>
    /// Whether a tag value is a check's identifier ("firewall.enabled"): letters, digits, dots,
    /// dashes and underscores. Anything else is not sent as one.
    /// </summary>
    public static bool IsCheckId([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? value) =>
        value is { Length: > 0 and <= 100 } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_');

    /// <summary>
    /// What tells one bug from another for "already reported": the error's type and the first
    /// place in SecReview's own code on its way up. The check it came from is left out, so one
    /// bug that hits twenty checks is one report; so is the message, which differs from PC to PC.
    /// </summary>
    public static string Fingerprint(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        string[] frames = (exception.StackTrace ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string where = frames.FirstOrDefault(frame => frame.Contains("SecReview.", StringComparison.Ordinal)) ?? frames.FirstOrDefault() ?? string.Empty;
        return $"{exception.GetType().FullName}|{where}";
    }

    /// <summary>
    /// The results as they may go with feedback when the user asks for it: for each check that
    /// did not pass, its identifier and how it ended. No summaries and no findings.
    /// </summary>
    public static string ResultsForFeedback(Scanning.ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);
        string[] lines =
        [
            .. scan.Checks
                .Where(check => check.Shown.Outcome.Status is not (CheckStatus.Pass or CheckStatus.NotApplicable))
                .Select(check => $"{check.Definition.Id}: {check.Shown.Outcome.Status}"),
        ];
        int passed = scan.Count(CheckStatus.Pass);
        return lines.Length == 0
            ? $"{passed} checks pass; none fail."
            : $"{passed} checks pass. Not passing:{Environment.NewLine}{string.Join(Environment.NewLine, lines)}";
    }
}

/// <summary>
/// Keeps SecReview from reporting the same bug over and over: each bug once a day, and only a
/// handful of different ones a day, however often SecReview is started. What was reported
/// today is remembered in a small file in the data folder (the day and a hash per bug).
/// </summary>
public sealed class ErrorReportBudget
{
    /// <summary>How many different bugs are reported in one day at most.</summary>
    public const int DefaultMaximum = 10;

    /// <summary>The file's name in the data folder.</summary>
    public const string FileName = "reported.txt";

    private readonly string? _path;
    private readonly TimeProvider _clock;
    private readonly int _maximum;
    private readonly Lock _gate = new();
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private string _day = string.Empty;
    private bool _loaded;

    /// <param name="folder">Where to remember what was reported; null to remember for this run only.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="maximum">How many different bugs a day.</param>
    public ErrorReportBudget(string? folder, TimeProvider clock, int maximum = DefaultMaximum)
    {
        ArgumentNullException.ThrowIfNull(clock);
        _path = folder is null ? null : Path.Combine(folder, FileName);
        _clock = clock;
        _maximum = maximum;
    }

    /// <summary>Whether a bug with this fingerprint may be reported now. True at most once a day per fingerprint.</summary>
    public bool Allow(string fingerprint)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        string hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint)))[..16];
        string today = _clock.GetUtcNow().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        lock (_gate)
        {
            if (!_loaded || _day != today)
            {
                Load(today);
            }

            if (_seen.Count >= _maximum || !_seen.Add(hash))
            {
                return false;
            }

            Save();
            return true;
        }
    }

    private void Load(string today)
    {
        _loaded = true;
        _day = today;
        _seen.Clear();
        if (_path is null)
        {
            return;
        }

        try
        {
            // First line: the day. Then one hash per line. Anything else means "nothing yet today".
            string[] lines = File.Exists(_path) && new FileInfo(_path).Length < 64 * 1024 ? File.ReadAllLines(_path) : [];
            if (lines.Length > 0 && lines[0] == today)
            {
                foreach (string line in lines.Skip(1).Where(line => line.Length == 16 && line.All(char.IsAsciiHexDigitLower)).Take(1000))
                {
                    _seen.Add(line);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Not remembered across runs this time; the limit for this run still holds.
        }
    }

    private void Save()
    {
        if (_path is null)
        {
            return;
        }

        try
        {
            AtomicFile.Write(_path, Encoding.UTF8.GetBytes(string.Join('\n', new[] { _day }.Concat(_seen)) + "\n"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // As above.
        }
    }
}

/// <summary>
/// Tells whether SecReview's previous run ended without closing down: a file is left in the
/// data folder while a window is open and removed when it closes. A file whose process is gone
/// is a run that crashed or was ended from outside.
/// </summary>
public sealed class RunMarker
{
    private readonly string _folder;
    private readonly int _processId;
    private readonly Func<int, bool> _isRunning;

    /// <param name="folder">SecReview's data folder.</param>
    /// <param name="processId">This process.</param>
    /// <param name="isRunning">Whether a process of that number is a running SecReview.</param>
    public RunMarker(string folder, int processId, Func<int, bool> isRunning)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        ArgumentNullException.ThrowIfNull(isRunning);
        _folder = folder;
        _processId = processId;
        _isRunning = isRunning;
    }

    /// <summary>The marker for this process, in SecReview's data folder.</summary>
    public static RunMarker ForThisProcess()
    {
        string name = Path.GetFileNameWithoutExtension(Environment.ProcessPath) ?? ProductInfo.Name;
        return new RunMarker(AppData.Directory, Environment.ProcessId, id =>
        {
            try
            {
                using var other = Process.GetProcessById(id);
                return other.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase);
            }
#pragma warning disable CA1031 // Whatever keeps Windows from saying: a process that cannot be looked at is not known to be ours.
            catch (Exception)
#pragma warning restore CA1031
            {
                return false;
            }
        });
    }

    private string Path_ => Path.Combine(_folder, $"running-{_processId}.marker");

    /// <summary>
    /// Marks this run as started. Returns whether an earlier run ended without closing down;
    /// what that run left behind is cleared, so it is said once. Never throws.
    /// </summary>
    public bool Begin()
    {
        bool abnormal = false;
        try
        {
            Directory.CreateDirectory(_folder);
            foreach (string marker in Directory.GetFiles(_folder, "running-*.marker"))
            {
                string number = Path.GetFileNameWithoutExtension(marker)["running-".Length..];
                if (!int.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out int id))
                {
                    File.Delete(marker); // not one of ours
                }
                else if (id == _processId || !_isRunning(id))
                {
                    // Its process is gone (or its number has come round to this one): that run never closed down.
                    abnormal = true;
                    File.Delete(marker);
                }
            }

            File.WriteAllText(Path_, string.Empty);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Without a marker the next run simply has nothing to say.
        }

        return abnormal;
    }

    /// <summary>Marks this run as closed down. Never throws.</summary>
    public void End()
    {
        try
        {
            File.Delete(Path_);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The next run will take it for a run that did not close down; that is the lesser evil.
        }
    }
}
